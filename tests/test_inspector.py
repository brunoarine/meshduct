"""Tests for the packet inspector."""

import json
import os
import pytest
from meshtastic.protobuf import mqtt_pb2, mesh_pb2, portnums_pb2

from src.config import EncryptionConfig, FilterConfig
from src.crypto import decrypt_packet, decode_key, reset_warning_tracker
from src.inspector import (
    PacketInspector,
    FilterDecision,
    InspectionResult,
    get_portnum_name,
)


# Path to fixtures
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name: str) -> bytes:
    """Load a fixture file."""
    path = os.path.join(FIXTURES_DIR, name)
    if not os.path.exists(path):
        pytest.skip(f"Fixture not found: {path}")
    with open(path, "rb") as f:
        return f.read()


class TestGetPortnumName:
    """Tests for portnum name lookup."""
    
    def test_known_portnum(self):
        """Test known portnum values."""
        assert get_portnum_name(1) == "TEXT_MESSAGE_APP"
        assert get_portnum_name(3) == "POSITION_APP"
        assert get_portnum_name(4) == "NODEINFO_APP"
        assert get_portnum_name(67) == "TELEMETRY_APP"
    
    def test_unknown_portnum(self):
        """Test unknown portnum values."""
        assert get_portnum_name(9999) == "UNKNOWN_9999"


class TestPacketInspector:
    """Tests for the PacketInspector class."""
    
    def test_blocklist_mode_drop_text_message(self):
        """Test that TEXT_MESSAGE_APP is dropped in blocklist mode."""
        config = FilterConfig(
            mode="blocklist",
            portnums=["TEXT_MESSAGE_APP"],
        )
        inspector = PacketInspector(config)
        
        payload = load_fixture("text_message.bin")
        result = inspector.inspect("msh/BR/2/e/LongFast/!aabb", payload)
        
        assert result.decision == FilterDecision.DROP
        assert result.portnum == 1
        assert result.portnum_name == "TEXT_MESSAGE_APP"
    
    def test_blocklist_mode_forward_position(self):
        """Test that POSITION_APP is forwarded in blocklist mode."""
        config = FilterConfig(
            mode="blocklist",
            portnums=["TEXT_MESSAGE_APP"],
        )
        inspector = PacketInspector(config)
        
        payload = load_fixture("position.bin")
        result = inspector.inspect("msh/BR/2/e/LongFast/!aabb", payload)
        
        assert result.decision == FilterDecision.FORWARD
        assert result.portnum == 3
        assert result.portnum_name == "POSITION_APP"
    
    def test_allowlist_mode_forward_text_message(self):
        """Test that TEXT_MESSAGE_APP is forwarded in allowlist mode."""
        config = FilterConfig(
            mode="allowlist",
            portnums=["TEXT_MESSAGE_APP"],
        )
        inspector = PacketInspector(config)
        
        payload = load_fixture("text_message.bin")
        result = inspector.inspect("msh/BR/2/e/LongFast/!aabb", payload)
        
        assert result.decision == FilterDecision.FORWARD
        assert result.portnum == 1
    
    def test_allowlist_mode_drop_position(self):
        """Test that POSITION_APP is dropped in allowlist mode."""
        config = FilterConfig(
            mode="allowlist",
            portnums=["TEXT_MESSAGE_APP"],
        )
        inspector = PacketInspector(config)
        
        payload = load_fixture("position.bin")
        result = inspector.inspect("msh/BR/2/e/LongFast/!aabb", payload)
        
        assert result.decision == FilterDecision.DROP
        assert result.portnum == 3
    
    def test_bypass_topic_always_forward(self):
        """Test that bypass topics are always forwarded."""
        config = FilterConfig(
            mode="blocklist",
            portnums=["TEXT_MESSAGE_APP"],
        )
        inspector = PacketInspector(
            config,
            bypass_topics=["msh/+/+/map/#", "msh/+/+/stat/#"],
        )
        
        # Map topic should bypass filter
        result = inspector.inspect("msh/BR/2/map/!aabb", b"some data")
        assert result.decision == FilterDecision.FORWARD
        assert result.reason == "bypass_topic"
        
        # Stat topic should bypass filter
        result = inspector.inspect("msh/BR/2/stat/!aabb", b"some data")
        assert result.decision == FilterDecision.FORWARD
        assert result.reason == "bypass_topic"
    
    def test_malformed_protobuf_forward(self):
        """Test that malformed protobufs are forwarded (fail-open)."""
        config = FilterConfig(
            mode="blocklist",
            portnums=["TEXT_MESSAGE_APP"],
        )
        inspector = PacketInspector(config)
        
        # Invalid protobuf bytes
        result = inspector.inspect("msh/BR/2/e/LongFast/!aabb", b"\xff\xff\xff\xff")
        
        assert result.decision == FilterDecision.FORWARD
        assert result.reason == "protobuf_parse_error"
    
    def test_json_topic_parsing(self):
        """Test JSON topic parsing."""
        config = FilterConfig(
            mode="blocklist",
            portnums=["TEXT_MESSAGE_APP"],
        )
        inspector = PacketInspector(config)
        
        # JSON with TEXT_MESSAGE_APP type
        json_payload = json.dumps({"type": "TEXT_MESSAGE_APP", "payload": "hello"}).encode()
        result = inspector.inspect("msh/BR/2/json/LongFast/!aabb", json_payload)
        
        assert result.decision == FilterDecision.DROP
        
        # JSON with POSITION_APP type
        json_payload = json.dumps({"type": "POSITION_APP"}).encode()
        result = inspector.inspect("msh/BR/2/json/LongFast/!aabb", json_payload)
        
        assert result.decision == FilterDecision.FORWARD
    
    def test_json_topic_invalid_json(self):
        """Test JSON topic with invalid JSON."""
        config = FilterConfig(
            mode="blocklist",
            portnums=["TEXT_MESSAGE_APP"],
        )
        inspector = PacketInspector(config)
        
        result = inspector.inspect("msh/BR/2/json/LongFast/!aabb", b"not valid json")
        
        assert result.decision == FilterDecision.FORWARD
        assert result.reason == "json_parse_error"
    
    def test_multiple_portnums_in_blocklist(self):
        """Test multiple portnums in blocklist."""
        config = FilterConfig(
            mode="blocklist",
            portnums=["TEXT_MESSAGE_APP", "POSITION_APP"],
        )
        inspector = PacketInspector(config)
        
        # TEXT_MESSAGE should be dropped
        payload = load_fixture("text_message.bin")
        result = inspector.inspect("msh/BR/2/e/LongFast/!aabb", payload)
        assert result.decision == FilterDecision.DROP
        
        # POSITION should be dropped
        payload = load_fixture("position.bin")
        result = inspector.inspect("msh/BR/2/e/LongFast/!aabb", payload)
        assert result.decision == FilterDecision.DROP
        
        # TELEMETRY should be forwarded
        payload = load_fixture("telemetry.bin")
        result = inspector.inspect("msh/BR/2/e/LongFast/!aabb", payload)
        assert result.decision == FilterDecision.FORWARD


class TestCrypto:
    """Tests for cryptographic functions."""
    
    def test_decode_valid_key(self):
        """Test decoding a valid base64 key."""
        # Default Meshtastic key
        key = decode_key("1PG7OiApB1nwvP+rz05pAQ==")
        assert key is not None
        assert len(key) == 16
    
    def test_decode_invalid_key_length(self):
        """Test decoding a key with wrong length."""
        key = decode_key("YWJjZA==")  # "abcd" - only 4 bytes
        assert key is None
    
    def test_decode_invalid_base64(self):
        """Test decoding invalid base64."""
        key = decode_key("not valid base64!!!")
        assert key is None


class TestEncryptedPackets:
    """Tests for encrypted packet handling."""
    
    def test_encrypted_fallback_forward(self):
        """Test encrypted_fallback='forward' policy."""
        reset_warning_tracker()
        
        config = FilterConfig(
            mode="blocklist",
            portnums=["TEXT_MESSAGE_APP"],
        )
        enc_config = EncryptionConfig(default_key=None)  # No key
        
        inspector = PacketInspector(
            config,
            encryption_config=enc_config,
            encrypted_fallback="forward",
        )
        
        # Create an encrypted packet
        envelope = mqtt_pb2.ServiceEnvelope()
        envelope.channel_id = "LongFast"
        envelope.gateway_id = "!aabbccdd"
        envelope.packet.id = 12345
        setattr(envelope.packet, 'from', 0x11223344)  # 'from' is a Python keyword
        envelope.packet.encrypted = b"encrypted payload here"
        
        payload = envelope.SerializeToString()
        result = inspector.inspect("msh/BR/2/e/LongFast/!aabb", payload)
        
        assert result.decision == FilterDecision.FORWARD
        assert result.was_encrypted
        assert not result.decryption_success
    
    def test_encrypted_fallback_drop(self):
        """Test encrypted_fallback='drop' policy."""
        reset_warning_tracker()
        
        config = FilterConfig(
            mode="blocklist",
            portnums=["TEXT_MESSAGE_APP"],
        )
        enc_config = EncryptionConfig(default_key=None)  # No key
        
        inspector = PacketInspector(
            config,
            encryption_config=enc_config,
            encrypted_fallback="drop",
        )
        
        # Create an encrypted packet
        envelope = mqtt_pb2.ServiceEnvelope()
        envelope.channel_id = "LongFast"
        envelope.gateway_id = "!aabbccdd"
        envelope.packet.id = 12345
        setattr(envelope.packet, 'from', 0x11223344)  # 'from' is a Python keyword
        envelope.packet.encrypted = b"encrypted payload here"
        
        payload = envelope.SerializeToString()
        result = inspector.inspect("msh/BR/2/e/LongFast/!aabb", payload)
        
        assert result.decision == FilterDecision.DROP
        assert result.was_encrypted
        assert not result.decryption_success


class TestSpecialTopics:
    """Tests for special topic handling."""
    
    def test_map_topic_forward(self):
        """Test that map topics are always forwarded."""
        config = FilterConfig(
            mode="blocklist",
            portnums=["TEXT_MESSAGE_APP"],
        )
        inspector = PacketInspector(config)
        
        result = inspector.inspect("msh/BR/2/map/!aabb", b"map data")
        assert result.decision == FilterDecision.FORWARD
        assert result.reason == "special_topic"
    
    def test_stat_topic_forward(self):
        """Test that stat topics are always forwarded."""
        config = FilterConfig(
            mode="blocklist",
            portnums=["TEXT_MESSAGE_APP"],
        )
        inspector = PacketInspector(config)
        
        result = inspector.inspect("msh/BR/2/stat/!aabb", b"status")
        assert result.decision == FilterDecision.FORWARD
        assert result.reason == "special_topic"
