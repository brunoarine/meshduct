"""
Topic remapping and bypass matching helpers.
"""

import fnmatch
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def remap_topic(topic: str, local_prefix: str, remote_prefix: str, reverse: bool = False) -> str:
    """
    Remap a topic by stripping a prefix and prepending another.
    
    Prefix replacement happens on topic-level boundaries (split by '/').
    For example, "msh/BR/meshsorocaba/" will NOT match "msh/BR/meshsorocaba_other/".
    
    Args:
        topic: The original topic string.
        local_prefix: The prefix to strip from local topics.
        remote_prefix: The prefix to prepend for remote topics.
        reverse: If True, remap from remote to local (remote_prefix → local_prefix).
    
    Returns:
        The remapped topic string.
    """
    if reverse:
        source_prefix = remote_prefix
        dest_prefix = local_prefix
    else:
        source_prefix = local_prefix
        dest_prefix = remote_prefix
    
    # Normalize prefixes - ensure they end with '/' for proper segment matching
    if source_prefix and not source_prefix.endswith("/"):
        source_prefix_normalized = source_prefix + "/"
    else:
        source_prefix_normalized = source_prefix
    
    if dest_prefix and not dest_prefix.endswith("/"):
        dest_prefix_normalized = dest_prefix + "/"
    else:
        dest_prefix_normalized = dest_prefix
    
    # Check if topic starts with the source prefix (on segment boundary)
    if source_prefix_normalized:
        # Topic must start with the prefix exactly (including trailing /)
        if topic.startswith(source_prefix_normalized):
            remainder = topic[len(source_prefix_normalized):]
            return dest_prefix_normalized + remainder
    
    # No prefix match - return topic as-is with dest_prefix prepended
    if dest_prefix:
        return dest_prefix.rstrip("/") + "/" + topic
    return topic


def matches_bypass_topic(topic: str, patterns: list[str]) -> bool:
    """
    Check if a topic matches any bypass pattern.
    
    Uses MQTT-style wildcard matching:
    - '+' matches a single topic level
    - '#' matches zero or more topic levels
    
    Args:
        topic: The topic string to check.
        patterns: List of patterns to match against.
    
    Returns:
        True if the topic matches any pattern.
    """
    for pattern in patterns:
        if mqtt_topic_match(topic, pattern):
            return True
    return False


def mqtt_topic_match(topic: str, pattern: str) -> bool:
    """
    Match a topic against an MQTT-style pattern.
    
    Supports MQTT wildcards:
    - '+' matches exactly one topic level
    - '#' matches zero or more topic levels (must be last character)
    
    Args:
        topic: The topic string (e.g., "msh/BR/2/e/LongFast/!aabb")
        pattern: The pattern to match (e.g., "msh/+/+/map/#")
    
    Returns:
        True if the topic matches the pattern.
    """
    # Normalize - remove leading/trailing slashes
    topic = topic.strip("/")
    pattern = pattern.strip("/")
    
    topic_parts = topic.split("/")
    pattern_parts = pattern.split("/")
    
    return _match_parts(topic_parts, pattern_parts, 0, 0)


def _match_parts(topic_parts: list[str], pattern_parts: list[str], ti: int, pi: int) -> bool:
    """
    Recursively match topic parts against pattern parts.
    
    Args:
        topic_parts: Split topic string.
        pattern_parts: Split pattern string.
        ti: Current topic index.
        pi: Current pattern index.
    
    Returns:
        True if the parts match.
    """
    # Both exhausted - match
    if ti >= len(topic_parts) and pi >= len(pattern_parts):
        return True
    
    # Pattern exhausted but topic remains - no match
    if pi >= len(pattern_parts):
        return False
    
    # Topic exhausted but pattern remains - check if remaining pattern is all '#'
    if ti >= len(topic_parts):
        # Only '#' can match empty
        return all(p == "#" for p in pattern_parts[pi:])
    
    current_pattern = pattern_parts[pi]
    
    # '#' matches everything remaining (must be last)
    if current_pattern == "#":
        return True
    
    # '+' matches exactly one level
    if current_pattern == "+":
        return _match_parts(topic_parts, pattern_parts, ti + 1, pi + 1)
    
    # Exact match required
    if current_pattern == topic_parts[ti]:
        return _match_parts(topic_parts, pattern_parts, ti + 1, pi + 1)
    
    return False


def extract_channel_id(topic: str) -> Optional[str]:
    """
    Extract the channel ID from a Meshtastic MQTT topic.
    
    Topics are in the format:
    - msh/<REGION>/2/e/<CHANNEL>/<GATEWAY_ID>
    - msh/<REGION>/2/c/<CHANNEL>/<GATEWAY_ID> (legacy)
    - msh/<REGION>/2/json/<CHANNEL>/<GATEWAY_ID>
    
    Args:
        topic: The MQTT topic string.
    
    Returns:
        The channel ID if found, None otherwise.
    """
    parts = topic.split("/")
    
    # Need at least 6 parts for msh/REGION/2/e/CHANNEL/GATEWAY
    if len(parts) < 6:
        return None
    
    # Check for valid structure
    if parts[0] != "msh":
        return None
    
    # parts[2] should be "2" (protocol version)
    # parts[3] should be "e", "c", or "json"
    # parts[4] is the channel name
    
    if parts[3] in ("e", "c", "json"):
        return parts[4]
    
    return None


def is_json_topic(topic: str) -> bool:
    """
    Check if a topic is a JSON topic (contains '/json/').
    
    Args:
        topic: The MQTT topic string.
    
    Returns:
        True if this is a JSON topic.
    """
    return "/json/" in topic


def is_map_topic(topic: str) -> bool:
    """
    Check if a topic is a map report topic.
    
    Map topics are in the format: msh/<REGION>/2/map/<GATEWAY_ID>
    
    Args:
        topic: The MQTT topic string.
    
    Returns:
        True if this is a map topic.
    """
    parts = topic.split("/")
    if len(parts) >= 5:
        return parts[0] == "msh" and parts[3] == "map"
    return False


def is_stat_topic(topic: str) -> bool:
    """
    Check if a topic is a stat topic.
    
    Stat topics are in the format: msh/<REGION>/2/stat/<GATEWAY_ID>
    
    Args:
        topic: The MQTT topic string.
    
    Returns:
        True if this is a stat topic.
    """
    parts = topic.split("/")
    if len(parts) >= 5:
        return parts[0] == "msh" and parts[3] == "stat"
    return False
