"""
Packet Inspector: protobuf decode + portnum filter.

The inspector receives raw payload bytes and topic string, then determines
whether the packet should be forwarded or dropped based on the configured
filter rules.
"""

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from meshtastic.protobuf import mesh_pb2, mqtt_pb2, portnums_pb2

from . import crypto
from .config import EncryptionConfig, FilterConfig, RelayTargetConfig
from .topics import (
    extract_channel_id,
    is_json_topic,
    is_map_topic,
    is_stat_topic,
    matches_bypass_topic,
)

logger = logging.getLogger(__name__)


class FilterDecision(Enum):
    """Decision made by the packet filter."""
    FORWARD = "forward"
    DROP = "drop"


@dataclass
class InspectionResult:
    """Result of inspecting a packet."""
    decision: FilterDecision
    portnum: Optional[int] = None
    portnum_name: Optional[str] = None
    reason: Optional[str] = None
    was_encrypted: bool = False
    decryption_success: bool = False


def get_portnum_name(portnum: int) -> str:
    """
    Get the human-readable name for a portnum value.
    
    Args:
        portnum: The portnum integer value.
    
    Returns:
        The portnum name (e.g., "TEXT_MESSAGE_APP") or "UNKNOWN_<value>".
    """
    for name, value in vars(portnums_pb2).items():
        if isinstance(value, int) and name.isupper() and not name.startswith("_"):
            if value == portnum:
                return name
    return f"UNKNOWN_{portnum}"


class PacketInspector:
    """
    Inspects Meshtastic packets and applies filter rules.
    
    The inspector handles:
    - Decoding ServiceEnvelope protobufs
    - Decrypting encrypted packets
    - Parsing JSON topics
    - Applying allowlist/blocklist filters
    - Bypassing special topics (map, stat)
    """
    
    def __init__(
        self,
        filter_config: FilterConfig,
        encryption_config: Optional[EncryptionConfig] = None,
        encrypted_fallback: str = "forward",
        bypass_topics: Optional[list[str]] = None,
    ):
        """
        Initialize the packet inspector.
        
        Args:
            filter_config: Filter configuration (mode, portnums).
            encryption_config: Encryption keys configuration.
            encrypted_fallback: Policy for undecryptable packets ("forward" or "drop").
            bypass_topics: List of topic patterns to always forward.
        """
        self.filter_config = filter_config
        self.encryption_config = encryption_config or EncryptionConfig()
        self.encrypted_fallback = encrypted_fallback
        self.bypass_topics = bypass_topics or []
        
        # Pre-compute portnum values
        self._portnum_values = filter_config.get_portnum_values()
        
        # Pre-decode keys
        self._default_key: Optional[bytes] = None
        self._channel_keys: dict[str, bytes] = {}
        self._decode_keys()
    
    def _decode_keys(self) -> None:
        """Decode and cache encryption keys."""
        if self.encryption_config.default_key:
            self._default_key = crypto.decode_key(self.encryption_config.default_key)
        
        for channel_name, key_b64 in self.encryption_config.channel_keys.items():
            key_bytes = crypto.decode_key(key_b64)
            if key_bytes:
                self._channel_keys[channel_name] = key_bytes
    
    def inspect(self, topic: str, payload: bytes) -> InspectionResult:
        """
        Inspect a packet and decide whether to forward it.
        
        Args:
            topic: The MQTT topic the packet was received on.
            payload: The raw packet payload bytes.
        
        Returns:
            An InspectionResult with the decision and metadata.
        """
        # Check bypass topics first
        if matches_bypass_topic(topic, self.bypass_topics):
            return InspectionResult(
                decision=FilterDecision.FORWARD,
                reason="bypass_topic",
            )
        
        # Check for map/stat topics (these don't have ServiceEnvelope)
        if is_map_topic(topic) or is_stat_topic(topic):
            return InspectionResult(
                decision=FilterDecision.FORWARD,
                reason="special_topic",
            )
        
        # Check for JSON topic
        if is_json_topic(topic):
            return self._inspect_json(payload)
        
        # Try to parse as ServiceEnvelope
        return self._inspect_protobuf(topic, payload)
    
    def _inspect_json(self, payload: bytes) -> InspectionResult:
        """
        Inspect a JSON-encoded packet.
        
        JSON topics contain unencrypted JSON with a "type" field for the portnum.
        
        Args:
            payload: The JSON payload bytes.
        
        Returns:
            An InspectionResult.
        """
        try:
            data = json.loads(payload.decode("utf-8"))
            portnum = data.get("type")
            
            if portnum is None:
                # No type field - forward anyway
                return InspectionResult(
                    decision=FilterDecision.FORWARD,
                    reason="json_no_type_field",
                )
            
            # Convert to int if needed
            if isinstance(portnum, str):
                # Try to find the portnum by name
                if hasattr(portnums_pb2, portnum):
                    portnum = getattr(portnums_pb2, portnum)
                else:
                    try:
                        portnum = int(portnum)
                    except ValueError:
                        return InspectionResult(
                            decision=FilterDecision.FORWARD,
                            reason="json_unknown_type",
                        )
            
            return self._apply_filter(portnum)
            
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.debug(f"Failed to parse JSON payload: {e}")
            # Malformed JSON - forward anyway (fail-open)
            return InspectionResult(
                decision=FilterDecision.FORWARD,
                reason="json_parse_error",
            )
    
    def _inspect_protobuf(self, topic: str, payload: bytes) -> InspectionResult:
        """
        Inspect a ServiceEnvelope protobuf packet.
        
        Args:
            topic: The MQTT topic.
            payload: The raw protobuf payload.
        
        Returns:
            An InspectionResult.
        """
        try:
            envelope = mqtt_pb2.ServiceEnvelope()
            envelope.ParseFromString(payload)
            packet = envelope.packet
            
            # Check if packet has decoded payload
            if packet.HasField("decoded"):
                portnum = packet.decoded.portnum
                return self._apply_filter(portnum)
            
            # Check if packet is encrypted
            if packet.encrypted:
                return self._inspect_encrypted(topic, packet)
            
            # No decoded or encrypted payload - forward anyway
            return InspectionResult(
                decision=FilterDecision.FORWARD,
                reason="no_payload",
            )
            
        except Exception as e:
            logger.debug(f"Failed to parse protobuf: {e}")
            # Malformed protobuf - forward anyway (fail-open)
            return InspectionResult(
                decision=FilterDecision.FORWARD,
                reason="protobuf_parse_error",
            )
    
    def _inspect_encrypted(self, topic: str, packet) -> InspectionResult:
        """
        Inspect an encrypted packet.
        
        Attempts to decrypt the packet using configured keys, then applies
        the filter. If decryption fails, applies the encrypted_fallback policy.
        
        Args:
            topic: The MQTT topic.
            packet: The MeshPacket with encrypted payload.
        
        Returns:
            An InspectionResult.
        """
        channel_id = extract_channel_id(topic) or "unknown"
        
        # Get the appropriate key
        key_bytes = self._get_key_for_channel(channel_id)
        
        if key_bytes is None:
            # No key available
            crypto.log_decryption_warning_once(
                channel_id, 
                f"no encryption key configured for channel '{channel_id}'"
            )
            return self._apply_encrypted_fallback(channel_id)
        
        # Attempt decryption
        data = crypto.decrypt_packet(packet, key_bytes)
        
        if data is None:
            crypto.log_decryption_warning_once(
                channel_id,
                "decryption failed (wrong key?)"
            )
            return self._apply_encrypted_fallback(channel_id)
        
        # Decryption successful
        portnum = data.portnum
        result = self._apply_filter(portnum)
        result.was_encrypted = True
        result.decryption_success = True
        return result
    
    def _get_key_for_channel(self, channel_id: str) -> Optional[bytes]:
        """
        Get the encryption key for a channel.
        
        First checks channel-specific keys, then falls back to the default key.
        
        Args:
            channel_id: The channel identifier.
        
        Returns:
            The encryption key bytes, or None if not found.
        """
        # Check channel-specific key first
        if channel_id in self._channel_keys:
            return self._channel_keys[channel_id]
        
        # Fall back to default key
        return self._default_key
    
    def _apply_encrypted_fallback(self, channel_id: str) -> InspectionResult:
        """
        Apply the encrypted_fallback policy.
        
        Args:
            channel_id: The channel identifier for logging.
        
        Returns:
            An InspectionResult based on the fallback policy.
        """
        if self.encrypted_fallback == "drop":
            return InspectionResult(
                decision=FilterDecision.DROP,
                reason="encrypted_fallback_drop",
                was_encrypted=True,
                decryption_success=False,
            )
        else:
            return InspectionResult(
                decision=FilterDecision.FORWARD,
                reason="encrypted_fallback_forward",
                was_encrypted=True,
                decryption_success=False,
            )
    
    def _apply_filter(self, portnum: int) -> InspectionResult:
        """
        Apply the filter rules to a portnum.
        
        Args:
            portnum: The portnum value.
        
        Returns:
            An InspectionResult.
        """
        portnum_name = get_portnum_name(portnum)
        in_list = portnum in self._portnum_values
        
        if self.filter_config.mode == "allowlist":
            # Allowlist: forward only if portnum IS in the list
            if in_list:
                return InspectionResult(
                    decision=FilterDecision.FORWARD,
                    portnum=portnum,
                    portnum_name=portnum_name,
                    reason="allowlist_match",
                )
            else:
                return InspectionResult(
                    decision=FilterDecision.DROP,
                    portnum=portnum,
                    portnum_name=portnum_name,
                    reason="allowlist_no_match",
                )
        else:
            # Blocklist: forward only if portnum is NOT in the list
            if in_list:
                return InspectionResult(
                    decision=FilterDecision.DROP,
                    portnum=portnum,
                    portnum_name=portnum_name,
                    reason="blocklist_match",
                )
            else:
                return InspectionResult(
                    decision=FilterDecision.FORWARD,
                    portnum=portnum,
                    portnum_name=portnum_name,
                    reason="blocklist_no_match",
                )


def create_inspector_for_target(target: RelayTargetConfig, encryption_config: EncryptionConfig, encrypted_fallback: str) -> PacketInspector:
    """
    Create a PacketInspector for a relay target.
    
    Args:
        target: The relay target configuration.
        encryption_config: Encryption keys configuration.
        encrypted_fallback: Policy for undecryptable packets.
    
    Returns:
        A configured PacketInspector.
    """
    return PacketInspector(
        filter_config=target.filter,
        encryption_config=encryption_config,
        encrypted_fallback=encrypted_fallback,
        bypass_topics=target.bypass_topics,
    )
