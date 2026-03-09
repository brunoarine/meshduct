"""Tests for configuration loading."""

import os
import pytest
import tempfile
import yaml

from src.config import (
    Config,
    FilterConfig,
    LocalConfig,
    EncryptionConfig,
    RelayTargetConfig,
    TopicMapConfig,
    load_config,
)


class TestConfigLoading:
    """Tests for configuration file loading."""
    
    def test_load_valid_config(self):
        """Test loading a valid configuration file."""
        config_content = """
local:
  host: "localhost"
  port: 1883
  username: "testuser"
  password: "testpass"
  client_id: "test-relay"
  subscribe:
    - "msh/test/#"

encryption:
  default_key: "1PG7OiApB1nwvP+rz05pAQ=="
  channel_keys:
    MyChannel: "dGhpcyBpcyBhIHRlc3Qga2V5IQ=="

encrypted_fallback: "drop"

relay:
  targets:
    - name: "test-target"
      enabled: true
      host: "mqtt.example.com"
      port: 1883
      username: "upstream"
      password: "uppass"
      client_id: "test-upstream"
      qos: 1
      direction: "out"
      topic_map:
        local_prefix: "msh/test/"
        remote_prefix: "remote/"
      filter:
        mode: "blocklist"
        portnums:
          - TEXT_MESSAGE_APP
      bypass_topics:
        - "msh/+/+/map/#"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            f.flush()
            config_path = f.name
        
        try:
            config = load_config(config_path)
            
            # Check local config
            assert config.local.host == "localhost"
            assert config.local.port == 1883
            assert config.local.username == "testuser"
            assert config.local.password == "testpass"
            assert config.local.client_id == "test-relay"
            assert config.local.subscribe == ["msh/test/#"]
            
            # Check encryption config
            assert config.encryption.default_key == "1PG7OiApB1nwvP+rz05pAQ=="
            assert "MyChannel" in config.encryption.channel_keys
            
            # Check encrypted_fallback
            assert config.encrypted_fallback == "drop"
            
            # Check targets
            assert len(config.targets) == 1
            target = config.targets[0]
            assert target.name == "test-target"
            assert target.enabled == True
            assert target.host == "mqtt.example.com"
            assert target.direction == "out"
            assert target.topic_map.local_prefix == "msh/test/"
            assert target.topic_map.remote_prefix == "remote/"
            assert target.filter.mode == "blocklist"
            assert "TEXT_MESSAGE_APP" in target.filter.portnums
        finally:
            os.unlink(config_path)
    
    def test_load_missing_file(self):
        """Test loading a non-existent configuration file."""
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")
    
    def test_validate_invalid_encrypted_fallback(self):
        """Test validation of invalid encrypted_fallback value."""
        config_content = """
encrypted_fallback: "invalid"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            f.flush()
            config_path = f.name
        
        try:
            with pytest.raises(ValueError) as exc_info:
                load_config(config_path)
            assert "encrypted_fallback" in str(exc_info.value)
        finally:
            os.unlink(config_path)
    
    def test_validate_invalid_direction(self):
        """Test validation of invalid direction value."""
        config_content = """
relay:
  targets:
    - name: "test"
      direction: "invalid"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            f.flush()
            config_path = f.name
        
        try:
            with pytest.raises(ValueError) as exc_info:
                load_config(config_path)
            assert "direction" in str(exc_info.value)
        finally:
            os.unlink(config_path)
    
    def test_validate_invalid_qos(self):
        """Test validation of invalid QoS value."""
        config_content = """
relay:
  targets:
    - name: "test"
      direction: "out"
      qos: 5
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            f.flush()
            config_path = f.name
        
        try:
            with pytest.raises(ValueError) as exc_info:
                load_config(config_path)
            assert "qos" in str(exc_info.value)
        finally:
            os.unlink(config_path)
    
    def test_defaults(self):
        """Test default values for optional fields."""
        config_content = """
local:
  host: "localhost"

relay:
  targets: []
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            f.flush()
            config_path = f.name
        
        try:
            config = load_config(config_path)
            
            # Check defaults
            assert config.local.port == 1883
            assert config.local.client_id == "meshtastic-relay"
            assert config.local.subscribe == ["msh/#"]
            assert config.encrypted_fallback == "forward"
            assert config.targets == []
        finally:
            os.unlink(config_path)


class TestFilterConfig:
    """Tests for FilterConfig."""
    
    def test_get_portnum_values(self):
        """Test conversion of portnum names to values."""
        config = FilterConfig(
            mode="blocklist",
            portnums=["TEXT_MESSAGE_APP", "POSITION_APP", 67],
        )
        
        values = config.get_portnum_values()
        
        assert 1 in values  # TEXT_MESSAGE_APP
        assert 3 in values  # POSITION_APP
        assert 67 in values  # TELEMETRY_APP (direct int)
    
    def test_get_portnum_values_unknown(self):
        """Test handling of unknown portnum names."""
        config = FilterConfig(
            mode="blocklist",
            portnums=["UNKNOWN_PORTNUM"],
        )
        
        # Should not raise, just log warning
        values = config.get_portnum_values()
        assert len(values) == 0
