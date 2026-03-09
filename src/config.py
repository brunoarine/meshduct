"""
Configuration loader and validator for the Meshtastic MQTT Relay.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml
from meshtastic.protobuf import portnums_pb2

logger = logging.getLogger(__name__)


@dataclass
class LocalConfig:
    """Local broker connection configuration."""
    host: str = "localhost"
    port: int = 1883
    username: Optional[str] = None
    password: Optional[str] = None
    client_id: str = "meshtastic-relay"
    subscribe: list[str] = field(default_factory=lambda: ["msh/#"])


@dataclass
class EncryptionConfig:
    """Encryption keys configuration."""
    default_key: Optional[str] = None
    channel_keys: dict[str, str] = field(default_factory=dict)


@dataclass
class FilterConfig:
    """Packet filter configuration."""
    mode: str = "blocklist"  # "allowlist" or "blocklist"
    portnums: list[str] = field(default_factory=list)

    def get_portnum_values(self) -> set[int]:
        """Convert portnum names to their integer values."""
        values = set()
        for name in self.portnums:
            # Handle both string names and integer values
            if isinstance(name, int):
                values.add(name)
            elif hasattr(portnums_pb2, name):
                values.add(getattr(portnums_pb2, name))
            else:
                try:
                    values.add(int(name))
                except ValueError:
                    logger.warning(f"Unknown portnum: {name}")
        return values


@dataclass
class TopicMapConfig:
    """Topic remapping configuration."""
    local_prefix: str = ""
    remote_prefix: str = ""


@dataclass
class RelayTargetConfig:
    """Relay target configuration."""
    name: str = "default"
    enabled: bool = True
    host: str = "localhost"
    port: int = 1883
    username: Optional[str] = None
    password: Optional[str] = None
    client_id: str = "meshtastic-relay-upstream"
    qos: int = 1
    direction: str = "out"  # "out", "in", or "both"
    topic_map: TopicMapConfig = field(default_factory=TopicMapConfig)
    filter: FilterConfig = field(default_factory=FilterConfig)
    bypass_topics: list[str] = field(default_factory=list)


@dataclass
class Config:
    """Main configuration container."""
    local: LocalConfig = field(default_factory=LocalConfig)
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    encrypted_fallback: str = "forward"  # "forward" or "drop"
    stats_interval: int = 60  # Seconds between stats log output
    relay: dict[str, Any] = field(default_factory=lambda: {"targets": []})
    targets: list[RelayTargetConfig] = field(default_factory=list)


def _parse_local(data: dict) -> LocalConfig:
    """Parse local broker configuration."""
    local_data = data.get("local", {})
    return LocalConfig(
        host=local_data.get("host", "localhost"),
        port=local_data.get("port", 1883),
        username=local_data.get("username"),
        password=local_data.get("password"),
        client_id=local_data.get("client_id", "meshtastic-relay"),
        subscribe=local_data.get("subscribe", ["msh/#"]),
    )


def _parse_encryption(data: dict) -> EncryptionConfig:
    """Parse encryption configuration."""
    enc_data = data.get("encryption", {})
    return EncryptionConfig(
        default_key=enc_data.get("default_key"),
        channel_keys=enc_data.get("channel_keys", {}),
    )


def _parse_filter(data: dict) -> FilterConfig:
    """Parse filter configuration."""
    filter_data = data.get("filter", {})
    return FilterConfig(
        mode=filter_data.get("mode", "blocklist"),
        portnums=filter_data.get("portnums", []),
    )


def _parse_topic_map(data: dict) -> TopicMapConfig:
    """Parse topic map configuration."""
    map_data = data.get("topic_map", {})
    return TopicMapConfig(
        local_prefix=map_data.get("local_prefix", ""),
        remote_prefix=map_data.get("remote_prefix", ""),
    )


def _parse_target(target_data: dict) -> RelayTargetConfig:
    """Parse a single relay target configuration."""
    return RelayTargetConfig(
        name=target_data.get("name", "default"),
        enabled=target_data.get("enabled", True),
        host=target_data.get("host", "localhost"),
        port=target_data.get("port", 1883),
        username=target_data.get("username"),
        password=target_data.get("password"),
        client_id=target_data.get("client_id", "meshtastic-relay-upstream"),
        qos=target_data.get("qos", 1),
        direction=target_data.get("direction", "out"),
        topic_map=_parse_topic_map(target_data),
        filter=_parse_filter(target_data),
        bypass_topics=target_data.get("bypass_topics", []),
    )


def load_config(config_path: str | Path) -> Config:
    """Load and validate configuration from a YAML file."""
    config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, "r") as f:
        data = yaml.safe_load(f) or {}
    
    config = Config(
        local=_parse_local(data),
        encryption=_parse_encryption(data),
        encrypted_fallback=data.get("encrypted_fallback", "forward"),
        stats_interval=data.get("stats_interval", 60),
        relay=data.get("relay", {"targets": []}),
    )
    
    # Parse relay targets
    relay_data = data.get("relay", {})
    targets_data = relay_data.get("targets", [])
    config.targets = [_parse_target(t) for t in targets_data]
    
    # Validate
    _validate_config(config)
    
    logger.info(f"Configuration loaded from {config_path}")
    logger.info(f"Local broker: {config.local.host}:{config.local.port}")
    logger.info(f"Enabled targets: {[t.name for t in config.targets if t.enabled]}")
    
    return config


def _validate_config(config: Config) -> None:
    """Validate configuration values."""
    # Validate stats_interval
    if config.stats_interval < 1:
        raise ValueError(
            f"stats_interval must be at least 1 second, got: {config.stats_interval}"
        )

    # Validate encrypted_fallback
    if config.encrypted_fallback not in ("forward", "drop"):
        raise ValueError(
            f"encrypted_fallback must be 'forward' or 'drop', got: {config.encrypted_fallback}"
        )
    
    # Validate targets
    for target in config.targets:
        if target.direction not in ("out", "in", "both"):
            raise ValueError(
                f"Target {target.name}: direction must be 'out', 'in', or 'both', got: {target.direction}"
            )
        
        if target.filter.mode not in ("allowlist", "blocklist"):
            raise ValueError(
                f"Target {target.name}: filter.mode must be 'allowlist' or 'blocklist', got: {target.filter.mode}"
            )
        
        if target.qos not in (0, 1, 2):
            raise ValueError(
                f"Target {target.name}: qos must be 0, 1, or 2, got: {target.qos}"
            )
    
    # Warn about missing credentials
    if not config.local.username:
        logger.warning("No username configured for local broker")
    
    for target in config.targets:
        if target.enabled and not target.username:
            logger.warning(f"Target {target.name}: no username configured")
