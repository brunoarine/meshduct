"""Tests for the relay engine."""

import pytest
import threading
import time
from unittest.mock import MagicMock, patch, call

from src.config import Config, LocalConfig, RelayTargetConfig, FilterConfig, TopicMapConfig
from src.relay import RelayEngine, RelayStats, TargetClient
from src.inspector import FilterDecision, PacketInspector


class TestRelayStats:
    """Tests for RelayStats."""
    
    def test_initial_values(self):
        """Test initial stat values are zero."""
        stats = RelayStats()
        assert stats.packets_received == 0
        assert stats.packets_forwarded == 0
        assert stats.packets_dropped == 0
        assert stats.packets_error == 0
    
    def test_snapshot(self):
        """Test stats snapshot."""
        stats = RelayStats()
        stats.packets_received = 100
        stats.packets_forwarded = 80
        stats.packets_dropped = 15
        stats.packets_error = 5
        
        snapshot = stats.snapshot()
        
        assert snapshot["received"] == 100
        assert snapshot["forwarded"] == 80
        assert snapshot["dropped"] == 15
        assert snapshot["error"] == 5


class TestRelayEngine:
    """Tests for the RelayEngine class."""
    
    @pytest.fixture
    def mock_config(self):
        """Create a mock configuration."""
        config = Config()
        config.local = LocalConfig(
            host="localhost",
            port=1883,
            username="testuser",
            password="testpass",
            client_id="test-relay",
            subscribe=["msh/test/#"],
        )
        config.targets = [
            RelayTargetConfig(
                name="test-target",
                enabled=True,
                host="upstream.example.com",
                port=1883,
                username="upstream",
                password="uppass",
                client_id="test-upstream",
                qos=1,
                direction="out",
                topic_map=TopicMapConfig(
                    local_prefix="msh/test/",
                    remote_prefix="remote/",
                ),
                filter=FilterConfig(
                    mode="blocklist",
                    portnums=["TEXT_MESSAGE_APP"],
                ),
                bypass_topics=["msh/+/+/map/#"],
            )
        ]
        return config
    
    def test_relay_engine_init(self, mock_config):
        """Test RelayEngine initialization."""
        engine = RelayEngine(mock_config)
        
        assert engine.config == mock_config
        assert "test-target" in engine.target_clients
        assert not engine.running
    
    def test_relay_engine_disabled_target(self, mock_config):
        """Test that disabled targets are not set up."""
        mock_config.targets[0].enabled = False
        
        engine = RelayEngine(mock_config)
        
        assert "test-target" not in engine.target_clients


class TestTopicRemapping:
    """Tests for topic remapping in relay context."""
    
    def test_outbound_remap(self):
        """Test outbound topic remapping."""
        from src.topics import remap_topic
        
        result = remap_topic(
            "msh/test/2/e/LongFast/!aabb",
            "msh/test/",
            "remote/",
        )
        assert result == "remote/2/e/LongFast/!aabb"
    
    def test_inbound_remap(self):
        """Test inbound topic remapping."""
        from src.topics import remap_topic
        
        result = remap_topic(
            "remote/2/e/LongFast/!aabb",
            "msh/test/",
            "remote/",
            reverse=True,
        )
        assert result == "msh/test/2/e/LongFast/!aabb"
