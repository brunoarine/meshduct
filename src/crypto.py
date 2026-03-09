"""
Meshtastic AES-CTR decryption for encrypted packets.
"""

import base64
import logging
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from meshtastic.protobuf import mesh_pb2

logger = logging.getLogger(__name__)

# Track channels where we've logged decryption warnings
_decryption_warning_logged: set[str] = set()


def decrypt_packet(packet, key_bytes: bytes) -> Optional[mesh_pb2.Data]:
    """
    Decrypt a MeshPacket's encrypted payload.
    
    Meshtastic uses AES-128-CTR mode. The nonce is constructed from:
    - 8 bytes of packet.id (little-endian)
    - 8 bytes of packet.from (little-endian)
    
    Args:
        packet: A MeshPacket protobuf with encrypted payload.
        key_bytes: The 16-byte AES key.
    
    Returns:
        Decrypted Data protobuf, or None if decryption failed.
    """
    try:
        # Construct the nonce
        # Note: 'from' is a Python keyword, use getattr
        packet_id = packet.id if packet.id else 0
        packet_from = getattr(packet, 'from', 0) if getattr(packet, 'from', None) else 0
        
        nonce = packet_id.to_bytes(8, "little") + packet_from.to_bytes(8, "little")
        
        # Decrypt using AES-128-CTR
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(packet.encrypted) + decryptor.finalize()
        
        # Parse as Data protobuf
        data = mesh_pb2.Data()
        data.ParseFromString(decrypted)
        return data
        
    except Exception as e:
        logger.debug(f"Decryption failed: {e}")
        return None


def decode_key(key_b64: str) -> Optional[bytes]:
    """
    Decode a base64-encoded encryption key.
    
    Args:
        key_b64: Base64-encoded key string.
    
    Returns:
        Raw key bytes, or None if decoding failed.
    """
    try:
        key_bytes = base64.b64decode(key_b64)
        if len(key_bytes) != 16:
            logger.warning(f"Invalid key length: {len(key_bytes)} bytes (expected 16)")
            return None
        return key_bytes
    except Exception as e:
        logger.warning(f"Failed to decode key: {e}")
        return None


def log_decryption_warning_once(channel_id: str, reason: str) -> None:
    """
    Log a decryption warning once per channel (not per packet).
    
    Args:
        channel_id: The channel identifier.
        reason: The reason for the warning.
    """
    if channel_id not in _decryption_warning_logged:
        _decryption_warning_logged.add(channel_id)
        logger.warning(
            f"Cannot decrypt packets on channel '{channel_id}': {reason}. "
            f"Filtering may be degraded for this channel."
        )


def reset_warning_tracker() -> None:
    """Reset the decryption warning tracker (useful for testing)."""
    global _decryption_warning_logged
    _decryption_warning_logged = set()
