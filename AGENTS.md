# AGENTS.md — Meshtastic MQTT Relay

## Project Overview

Build a **minimal, secure, Meshtastic-aware MQTT relay** in Python, packaged as a Docker container. It runs as a sidecar alongside an existing Mosquitto broker. The relay subscribes to the local broker, decodes Meshtastic protobuf packets, filters them by type, and republishes allowed packets to one or more upstream MQTT servers with optional topic remapping.

The relay serves a local Meshtastic community. It must be able to:

1. **Relay packets to one or more upstream MQTT servers** — acting as a unidirectional or bidirectional bridge with topic remapping.
2. **Filter relayed packets by portnum** — decode the Meshtastic `ServiceEnvelope` protobuf and drop specific packet types (e.g. `TEXT_MESSAGE_APP`) before forwarding, while allowing others (telemetry, position, nodeinfo, map reports) through.

> **Note:** Downlink blocking on specific channels (e.g. `msh/BR/2/e/LongFast/#`) is handled by Mosquitto's ACL file, not by this relay. See the `mosquitto/` section below for the ACL configuration.

---

## Architecture

```
Meshtastic Nodes
        │
        ▼
┌──────────────────┐         ┌─────────────────────────┐
│   Mosquitto      │         │  meshtastic-relay        │
│   (MQTT broker)  │◄───────►│  (Python + paho-mqtt)    │
│                  │  local   │                          │
│  • Auth (passwd) │  MQTT    │  1. Subscribe local      │
│  • ACL (downlink │         │  2. Decode ServiceEnvelope│
│    blocking)     │         │  3. Filter by portnum     │
│  • Persistence   │         │  4. Remap topic           │
│  • WebSockets    │         │  5. Publish upstream ─────┼──► Upstream MQTT
└──────────────────┘         └─────────────────────────┘     (e.g. meshbrasil)
```

Two containers, each with a single responsibility:

- **Mosquitto** — the production MQTT broker. Handles device connections, authentication, ACLs, persistence, and WebSockets. Already deployed and working.
- **meshtastic-relay** — a lightweight Python service. Connects to Mosquitto as a regular MQTT client, inspects packets, and selectively forwards them upstream.

---

## Tech Stack

| Component         | Library / Tool                                                   |
| ----------------- | ---------------------------------------------------------------- |
| MQTT Client       | `paho-mqtt` (both local subscription and upstream publishing)    |
| Protobuf Decoding | `meshtastic` Python package (provides compiled protobuf classes) |
| Configuration     | YAML file (`config.yaml`)                                        |
| Container         | Docker (Python 3.12-slim base image)                             |
| Async Runtime     | Threading via paho-mqtt's `loop_start()` (one thread per target) |

---

## Configuration Format

All behavior is driven by a single `config.yaml` file mounted into the container.

```yaml
# ─── Local Broker Connection ─────────────────────────────────────
local:
  host: "mosquitto"          # Docker service name or IP
  port: 1883
  username: "meshdev"
  password: "large4cats"
  client_id: "meshtastic-relay"
  # Topics to subscribe to on the local broker.
  # This determines what packets the relay sees.
  subscribe:
    - "msh/BR/meshsorocaba/#"

# ─── Encryption Keys (for inspecting encrypted packets) ──────────
# Without these, encrypted packets are forwarded unfiltered.
# Keys are base64-encoded.
encryption:
  # The well-known default Meshtastic key (used by LongFast etc.)
  default_key: "1PG7OiApB1nwvP+rz05pAQ=="
  # Optional per-channel overrides
  channel_keys: {}
    # MyPrivateChannel: "<base64 key>"

# ─── Encrypted Packet Policy ────────────────────────────────────
# What to do when a packet is encrypted and cannot be decrypted
# (no matching PSK). Options: "forward" or "drop"
encrypted_fallback: "forward"

# ─── Relay Targets ──────────────────────────────────────────────
# One or more upstream MQTT servers to forward packets to.
relay:
  targets:
    - name: "meshbrasil"
      enabled: true
      host: "platform.meshbrasil.com"
      port: 1883
      username: "meshdev"
      password: "large4cats"
      client_id: "meshsorocaba-bridge"
      qos: 1

      # Direction: "out" (local→remote), "in" (remote→local), "both"
      direction: "out"

      # Topic remapping: strip local_prefix, prepend remote_prefix.
      # Example:
      #   local:  msh/BR/meshsorocaba/2/e/LongFast/!aabb
      #   remote: meshdev/2/e/LongFast/!aabb
      topic_map:
        local_prefix: "msh/BR/meshsorocaba/"
        remote_prefix: "meshdev/"

      # ── Packet Filter ──────────────────────────────────────
      # Filter packets by Meshtastic portnum before relaying.
      # Mode: "allowlist" or "blocklist"
      #
      # Common portnums (from meshtastic.portnums_pb2):
      #   TEXT_MESSAGE_APP        = 1
      #   POSITION_APP            = 3
      #   NODEINFO_APP            = 4
      #   ROUTING_APP             = 5
      #   ADMIN_APP               = 6
      #   TELEMETRY_APP           = 67
      #   TRACEROUTE_APP          = 70
      #   NEIGHBORINFO_APP        = 71
      #   MAP_REPORT_APP          = 73
      filter:
        mode: "blocklist"
        portnums:
          - TEXT_MESSAGE_APP

      # ── Topic Bypass ───────────────────────────────────────
      # Topic patterns that skip portnum filtering entirely and
      # are always forwarded. Map reports and stats don't contain
      # ServiceEnvelope protobufs and carry no private content.
      bypass_topics:
        - "msh/+/+/map/#"
        - "msh/+/+/stat/#"
```

---

## Meshtastic Protobuf Details

This is critical context for implementing the Packet Inspector.

### Wire Format

Meshtastic devices publish raw protobuf bytes to topics matching:

```
msh/<REGION>/2/e/<CHANNEL_NAME>/<GATEWAY_ID>
```

The payload is a `ServiceEnvelope` protobuf (defined in `meshtastic/protobuf/mqtt.proto`):

```protobuf
message ServiceEnvelope {
  MeshPacket packet = 1;
  string channel_id = 2;
  string gateway_id = 3;
}
```

The `MeshPacket` contains either:
- `encrypted` (bytes) — the encrypted payload (when encryption is enabled)
- `decoded` (Data) — the decrypted payload (when encryption is disabled)

The `Data` message contains:
```protobuf
message Data {
  PortNum portnum = 1;    // ← THIS is what we filter on
  bytes payload = 2;
  // ...
}
```

### Accessing the Portnum

```python
from meshtastic.protobuf import mqtt_pb2, mesh_pb2, portnums_pb2

envelope = mqtt_pb2.ServiceEnvelope()
envelope.ParseFromString(raw_payload)

packet = envelope.packet

if packet.HasField("decoded"):
    portnum = packet.decoded.portnum
    # e.g. portnums_pb2.TEXT_MESSAGE_APP == 1
elif packet.encrypted:
    # Packet is encrypted — must decrypt to inspect portnum.
    # See crypto.py section below.
    pass
```

### Encrypted Packets

When `encryption_enabled` is true on the Meshtastic device (the default), `MeshPacket.encrypted` is populated and `MeshPacket.decoded` is empty. **You cannot read the portnum without decrypting first.**

Decryption uses AES-128-CTR. The nonce is constructed from `packet.id` and `packet.from`. The default channel key is `1PG7OiApB1nwvP+rz05pAQ==` (base64). Refer to `MeshInterface.py` in the Meshtastic Python library for the exact nonce construction:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def decrypt_packet(packet, key_bytes):
    """
    Decrypt a MeshPacket's encrypted payload.

    Nonce: 8 bytes of packet.id (little-endian) + 8 bytes of
           packet.from (little-endian), zero-padded to 16 bytes.
    """
    nonce = packet.id.to_bytes(8, "little") + packet.from_.to_bytes(8, "little")

    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(packet.encrypted) + decryptor.finalize()

    data = mesh_pb2.Data()
    data.ParseFromString(decrypted)
    return data  # data.portnum is now accessible
```

**If the PSK is not available or decryption fails, apply `encrypted_fallback` policy** (`"forward"` or `"drop"`, default `"forward"`). Log a warning once (not per-packet) that filtering is degraded.

### Map Reports and Stat Topics

These use different topic paths and are NOT `ServiceEnvelope` protobufs:

```
msh/<REGION>/2/map/<GATEWAY_ID>     → MapReport protobuf (always unencrypted)
msh/<REGION>/2/stat/<GATEWAY_ID>    → Status messages
```

These should always be forwarded (they contain no private message content). The config's `bypass_topics` list handles this — any topic matching a bypass pattern skips the filter entirely.

### Legacy and JSON Topics

- **Legacy `/c/` topics**: firmware before 2.3.0 uses `/c/` instead of `/e/`. Handle both.
- **JSON topics** (`msh/.../2/json/...`): contain unencrypted JSON with a `"type"` field for the portnum. Filter these too using the JSON type field instead of protobuf decoding.

---

## Implementation Plan

### Phase 1: Basic Relay (no filtering)

1. Write a Python entry point (`main.py`) that:
   - Reads `config.yaml`.
   - Creates a paho-mqtt client connected to the **local** Mosquitto broker.
   - Creates one paho-mqtt client per **relay target**.
   - Subscribes to `local.subscribe` topics on the local broker.
   - On every received message, remaps the topic and publishes to the upstream target.
2. Handle reconnection for both local and upstream clients using paho-mqtt's automatic reconnect.
3. Verify: publish a test message on the local broker under `msh/BR/meshsorocaba/test` and confirm it arrives at the upstream broker as `meshdev/test`.

### Phase 2: Portnum Filtering

1. Add the Packet Inspector module (`inspector.py`):
   - Receives raw payload bytes and the topic string.
   - If the topic matches a `bypass_topics` pattern, return `FORWARD`.
   - Attempt to parse as `ServiceEnvelope`.
   - If `packet.decoded` is present, read the portnum and apply the filter.
   - If `packet.encrypted` is present, attempt decryption with the configured key. If successful, read the portnum and apply the filter. If decryption fails, apply `encrypted_fallback` policy.
   - If protobuf parsing fails entirely, return `FORWARD` (don't silently drop data we can't parse).
2. Integrate the inspector into the relay's `on_message` callback: only publish upstream if the inspector returns `FORWARD`.
3. Verify: send a `TEXT_MESSAGE_APP` packet — confirm it is NOT relayed. Send a `POSITION_APP` packet — confirm it IS relayed.

### Phase 3: Bidirectional Support

1. For targets with `direction: "both"` or `"in"`:
   - Subscribe to the upstream broker with the reverse topic mapping.
   - On messages received from upstream, remap the topic (remote_prefix → local_prefix) and republish to the local Mosquitto broker.
   - Apply the same portnum filter in the inbound direction.
2. This is not needed for the current Mesh Brasil use case (`direction: "out"`) but should be supported in the config.

### Phase 4: Docker Packaging

1. Write a `Dockerfile` based on `python:3.12-slim`.
2. Install only: `paho-mqtt`, `meshtastic`, `pyyaml`, `cryptography`.
3. Run as a non-root user.
4. No ports exposed (the relay is a client, not a server).
5. Mount `config.yaml` as a volume.

---

## Project Structure

```
meshtastic-relay/
├── AGENTS.md                  ← This file
├── Dockerfile
├── docker-compose.yaml        ← Includes both Mosquitto and the relay
├── requirements.txt
├── config.yaml                ← Default config (override via volume mount)
├── mosquitto/
│   ├── mosquitto.conf         ← Mosquitto config (auth, ACLs, listeners)
│   ├── acl                    ← ACL file (LongFast downlink block etc.)
│   └── passwd                 ← Generated password file
├── src/
│   ├── __init__.py
│   ├── main.py                ← Entry point: loads config, starts relay
│   ├── config.py              ← YAML config loader and validator
│   ├── inspector.py           ← Packet Inspector: protobuf decode + portnum filter
│   ├── relay.py               ← Relay Engine: local sub → filter → upstream pub
│   ├── topics.py              ← Topic remapping and bypass matching helpers
│   └── crypto.py              ← Meshtastic AES-CTR decryption
└── tests/
    ├── test_inspector.py      ← Unit tests for protobuf parsing and filtering
    ├── test_topics.py         ← Unit tests for topic remapping and bypass matching
    ├── test_relay.py          ← Integration tests for relay pipeline
    └── fixtures/
        ├── text_message.bin   ← Sample ServiceEnvelope with TEXT_MESSAGE_APP
        ├── position.bin       ← Sample ServiceEnvelope with POSITION_APP
        └── encrypted.bin      ← Sample encrypted ServiceEnvelope
```

---

## Dockerfile

```dockerfile
FROM python:3.12-slim

RUN groupadd -r meshrelay && useradd -r -g meshrelay meshrelay

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config.yaml .

RUN chown -R meshrelay:meshrelay /app
USER meshrelay

# No ports exposed — the relay is a client, not a server.

ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--config", "/app/config.yaml"]
```

---

## docker-compose.yaml

This is the full stack: Mosquitto + relay running together.

```yaml
services:
  mosquitto:
    image: eclipse-mosquitto:2
    container_name: mosquitto
    restart: unless-stopped
    ports:
      - "1883:1883"
      - "9001:9001"
    volumes:
      - ./mosquitto/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro
      - ./mosquitto/acl:/mosquitto/config/acl:ro
      - ./mosquitto/passwd:/mosquitto/config/passwd:ro
      - mosquitto-data:/mosquitto/data
      - mosquitto-log:/mosquitto/log

  meshtastic-relay:
    build: .
    container_name: meshtastic-relay
    restart: unless-stopped
    depends_on:
      - mosquitto
    volumes:
      - ./config.yaml:/app/config.yaml:ro
    environment:
      - LOG_LEVEL=INFO

volumes:
  mosquitto-data:
  mosquitto-log:
```

> **Note:** With this compose file, the relay connects to Mosquitto using
> `host: "mosquitto"` (the Docker service name) in `config.yaml`.

---

## Mosquitto Configuration

The Mosquitto broker config should be updated so that file paths match the
Docker image's expected layout (`/mosquitto/config/` instead of `/etc/mosquitto/`).
Also, **remove the bridge section** from `mosquitto.conf` — the relay now handles
upstream forwarding.

Key points for `mosquitto.conf`:

```
persistence true
persistence_location /mosquitto/data/

log_dest file /mosquitto/log/mosquitto.log
log_dest stdout

listener 1883 0.0.0.0
listener 9001 0.0.0.0
protocol websockets

allow_anonymous false
password_file /mosquitto/config/passwd
acl_file /mosquitto/config/acl
```

The `acl` file still handles downlink blocking:

```
user meshdev
topic deny msh/BR/2/e/LongFast/#
topic readwrite #
```

---

## Security Requirements

- **No anonymous access** on Mosquitto. Every client must authenticate.
- **Relay runs as non-root** inside its container.
- **Minimal base image** (`python:3.12-slim`).
- **No secrets in the image.** Credentials live in `config.yaml`, mounted at runtime.
- **Input validation.** All incoming MQTT payloads are untrusted. Protobuf parsing must be wrapped in try/except — a malformed payload must never crash the relay.
- **Graceful degradation.** If an upstream target is unreachable, the relay logs the error and keeps running. It does not crash or block other targets.

---

## Testing Strategy

### Unit Tests

- `test_inspector.py`: Feed raw protobuf bytes (encrypted and decrypted) into the inspector. Assert correct portnum extraction and filter decisions for both allowlist and blocklist modes. Test malformed payloads return `FORWARD` (fail-open). Test encrypted packets with wrong key apply fallback policy.
- `test_topics.py`: Test topic remapping (prefix strip + prepend). Test bypass pattern matching with MQTT wildcards. Test edge cases (empty prefix, topic equals prefix exactly, partial segment matches).
- `test_config.py`: Test YAML loading, required field validation, and sensible defaults.

### Integration Tests

- Start Mosquitto and the relay via `docker compose up`.
- Publish a mock `ServiceEnvelope` with `TEXT_MESSAGE_APP` portnum to the local broker.
- Verify it is NOT forwarded to a mock upstream broker.
- Publish a `POSITION_APP` packet. Verify it IS forwarded with the correct remapped topic.

### Test Fixtures

Generate binary fixture files using the `meshtastic` Python library:

```python
from meshtastic.protobuf import mqtt_pb2, mesh_pb2, portnums_pb2

envelope = mqtt_pb2.ServiceEnvelope()
envelope.channel_id = "LongFast"
envelope.gateway_id = "!aabbccdd"
envelope.packet.id = 12345
envelope.packet.to = 0xFFFFFFFF
envelope.packet.decoded.portnum = portnums_pb2.TEXT_MESSAGE_APP
envelope.packet.decoded.payload = b"Hello mesh!"

with open("fixtures/text_message.bin", "wb") as f:
    f.write(envelope.SerializeToString())
```

---

## Logging

Use Python's `logging` module. Log levels:

- **INFO**: relay start/stop, upstream connect/disconnect, config loaded, summary stats (packets forwarded/dropped per minute)
- **WARNING**: authentication failures, decryption failures (once per channel, not per-packet), upstream connection lost
- **DEBUG**: every relayed packet (topic, portnum, size, target), every dropped packet (topic, portnum, reason)
- **ERROR**: config validation failures, unhandled exceptions

Format: `%(asctime)s [%(levelname)s] %(name)s: %(message)s`

---

## Edge Cases to Handle

1. **Encrypted packets with no PSK configured**: apply `encrypted_fallback` policy. Log a warning once per channel that filtering is degraded.
2. **Legacy `/c/` topics**: older firmware (pre-2.3.0) publishes to `/c/` instead of `/e/`. Handle both in topic matching and bypass rules.
3. **JSON topics** (`msh/.../2/json/...`): contain unencrypted JSON with a `"type"` field. Parse as JSON, extract the type, and apply the same portnum filter.
4. **Map report topics** (`msh/.../2/map/...`): always forward via bypass rules.
5. **Stat topics** (`msh/.../2/stat/...`): always forward via bypass rules.
6. **Upstream broker disconnection**: paho-mqtt handles automatic reconnection. Messages published while disconnected are queued up to `max_queued_messages_set` (configure to a sensible limit like 1000).
7. **Malformed protobuf**: log at DEBUG, forward as-is (don't silently drop data we can't parse).
8. **Topic remapping edge cases**: prefix replacement must happen on topic-level boundaries (split by `/`). `msh/BR/meshsorocaba/` must NOT accidentally match `msh/BR/meshsorocaba_other/`.
9. **Local Mosquitto restart**: the relay should reconnect automatically via paho-mqtt's reconnect logic. Use `reconnect_delay_set(min_delay=1, max_delay=30)`.
10. **Multiple relay targets**: each target has its own upstream client, its own filter config, and its own topic mapping. A packet dropped for one target may still be forwarded to another.

---

## References

- Meshtastic Protobuf definitions: https://github.com/meshtastic/protobufs
- Meshtastic MQTT integration docs: https://meshtastic.org/docs/software/integrations/mqtt/
- Meshtastic Python library: https://github.com/meshtastic/python
- paho-mqtt documentation: https://eclipse.dev/paho/files/paho.mqtt.python/html/
- Meshtastic encryption details: AES-128-CTR, see `MeshInterface.py` in the Python library
- Meshtastic portnums: https://buf.build/meshtastic/protobufs/docs/main:meshtastic#meshtastic.PortNum
