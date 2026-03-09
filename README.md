# meshduct: a Meshtastic MQTT relay

A minimal, secure, Meshtastic-aware MQTT relay. It subscribes to the local broker, decodes Meshtastic protobuf packets, filters them by type, and republishes allowed packets to one or more upstream MQTT servers with optional topic remapping.

## Features

- **Relay packets to upstream MQTT servers** — Unidirectional or bidirectional bridge with topic remapping
- **Filter by portnum** — Decode Meshtastic `ServiceEnvelope` protobuf and drop specific packet types (e.g., `TEXT_MESSAGE_APP`)
- **Encryption support** — Decrypt encrypted packets using AES-128-CTR for filtering
- **Graceful degradation** — Continues operating even if upstream targets are unreachable
- **Docker-ready** — Packaged as a minimal container

## Quick Start

### 1. Configure

Edit `config.yaml` to match your environment:

```yaml
local:
  host: "mosquitto"
  port: 1883
  username: "meshdev"
  password: "yourpassword"
  subscribe:
    - "msh/BR/yourlocalmesh/#"

relay:
  targets:
    - name: "meshtastic.org"
      enabled: true
      host: "mqtt.meshtastic.org"
      port: 1883
      username: "meshdev"
      password: "yourpassword"
      topic_map:
        local_prefix: "msh/BR/yourlocalmesh/"
        remote_prefix: "msh/BR/"
      filter:
        mode: "blocklist"
        portnums:
          - TEXT_MESSAGE_APP
      bypass_topics:
        - "msh/+/+/map/#"
        - "msh/+/+/stat/#"
```
## Configuration Reference

### Local Broker Connection

| Field | Description | Default |
|-------|-------------|---------|
| `host` | Mosquitto hostname or IP | `localhost` |
| `port` | Mosquitto port | `1883` |
| `username` | MQTT username | - |
| `password` | MQTT password | - |
| `client_id` | MQTT client ID | `meshduct` |
| `subscribe` | Topics to subscribe | `["msh/#"]` |

### Encryption Keys

| Field | Description |
|-------|-------------|
| `default_key` | Base64-encoded default AES key |
| `channel_keys` | Per-channel key overrides |

### Relay Targets

| Field | Description | Default |
|-------|-------------|---------|
| `name` | Target name | `default` |
| `enabled` | Enable/disable target | `true` |
| `host` | Upstream broker hostname | `localhost` |
| `port` | Upstream broker port | `1883` |
| `username` | Upstream username | - |
| `password` | Upstream password | - |
| `client_id` | Upstream client ID | - |
| `qos` | QoS level for publishing | `1` |
| `direction` | `out`, `in`, or `both` | `out` |
| `topic_map.local_prefix` | Prefix to strip from local topics | - |
| `topic_map.remote_prefix` | Prefix to prepend for remote topics | - |
| `filter.mode` | `allowlist` or `blocklist` | `blocklist` |
| `filter.portnums` | Portnums to allow/block | `[]` |
| `bypass_topics` | Topics that skip filtering | `[]` |

### Common Portnums

| Name | Value | Description |
|------|-------|-------------|
| `TEXT_MESSAGE_APP` | 1 | Text messages |
| `POSITION_APP` | 3 | Position updates |
| `NODEINFO_APP` | 4 | Node info |
| `ROUTING_APP` | 5 | Routing messages |
| `ADMIN_APP` | 6 | Admin messages |
| `TELEMETRY_APP` | 67 | Telemetry data |
| `TRACEROUTE_APP` | 70 | Traceroute |
| `NEIGHBORINFO_APP` | 71 | Neighbor info |
| `MAP_REPORT_APP` | 73 | Map reports |

## Running Tests

```bash
# Install dependencies
pip install -r requirements.txt
pip install pytest

# Generate test fixtures
python -c "from tests.fixtures import generate_all_fixtures; generate_all_fixtures()"

# Run tests
pytest tests/ -v
```

## Logging

The relay uses standard Python logging. Set the `LOG_LEVEL` environment variable:

```bash
docker compose run -e LOG_LEVEL=DEBUG meshduct
```

Log levels:
- **INFO**: Start/stop, connections, summary stats
- **WARNING**: Auth failures, decryption issues, disconnections
- **DEBUG**: Per-packet details (forwarded/dropped)
- **ERROR**: Config failures, unhandled exceptions

## License

MIT
