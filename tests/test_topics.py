"""Tests for topic remapping and bypass matching."""

import pytest
from src.topics import (
    mqtt_topic_match,
    remap_topic,
    matches_bypass_topic,
    extract_channel_id,
    is_json_topic,
    is_map_topic,
    is_stat_topic,
)


class TestRemapTopic:
    """Tests for topic remapping."""
    
    def test_basic_remap(self):
        """Test basic prefix replacement."""
        result = remap_topic(
            "msh/BR/meshsorocaba/2/e/LongFast/!aabb",
            "msh/BR/meshsorocaba/",
            "meshdev/",
        )
        assert result == "meshdev/2/e/LongFast/!aabb"
    
    def test_remap_without_trailing_slash(self):
        """Test prefix without trailing slash."""
        result = remap_topic(
            "msh/BR/meshsorocaba/2/e/LongFast/!aabb",
            "msh/BR/meshsorocaba",
            "meshdev",
        )
        assert result == "meshdev/2/e/LongFast/!aabb"
    
    def test_remap_no_match(self):
        """Test topic that doesn't match the prefix."""
        result = remap_topic(
            "msh/BR/other/2/e/LongFast/!aabb",
            "msh/BR/meshsorocaba/",
            "meshdev/",
        )
        # Should prepend the destination prefix
        assert result == "meshdev/msh/BR/other/2/e/LongFast/!aabb"
    
    def test_remap_empty_prefixes(self):
        """Test with empty prefixes."""
        result = remap_topic(
            "msh/BR/test",
            "",
            "",
        )
        assert result == "msh/BR/test"
    
    def test_remap_segment_boundary(self):
        """Test that prefix matches on segment boundaries only."""
        # Should NOT match because 'meshsorocaba_other' is different from 'meshsorocaba'
        result = remap_topic(
            "msh/BR/meshsorocaba_other/2/e/LongFast/!aabb",
            "msh/BR/meshsorocaba/",
            "meshdev/",
        )
        # Should NOT strip the prefix - it's a different segment
        assert "meshsorocaba_other" in result
    
    def test_remap_reverse(self):
        """Test reverse remapping (remote to local)."""
        result = remap_topic(
            "meshdev/2/e/LongFast/!aabb",
            "msh/BR/meshsorocaba/",
            "meshdev/",
            reverse=True,
        )
        assert result == "msh/BR/meshsorocaba/2/e/LongFast/!aabb"
    
    def test_remap_exact_match(self):
        """Test topic that exactly equals the prefix without trailing slash."""
        result = remap_topic(
            "msh/BR/meshsorocaba",
            "msh/BR/meshsorocaba/",
            "meshdev/",
        )
        # Topic doesn't have trailing slash, prefix does - prepends dest_prefix
        # since there's no match
        assert result == "meshdev/msh/BR/meshsorocaba"


class TestMqttTopicMatch:
    """Tests for MQTT-style topic pattern matching."""
    
    def test_exact_match(self):
        """Test exact topic match."""
        assert mqtt_topic_match("msh/BR/2/e/LongFast", "msh/BR/2/e/LongFast")
        assert not mqtt_topic_match("msh/BR/2/e/LongFast", "msh/BR/2/e/Other")
    
    def test_single_wildcard(self):
        """Test single-level wildcard (+)."""
        assert mqtt_topic_match("msh/BR/2/e/LongFast", "msh/+/2/e/LongFast")
        assert mqtt_topic_match("msh/BR/2/e/LongFast", "msh/BR/+/e/LongFast")
        assert mqtt_topic_match("msh/BR/2/e/LongFast", "msh/BR/2/+/LongFast")
        assert mqtt_topic_match("msh/BR/2/e/LongFast", "msh/BR/2/e/+")
        assert not mqtt_topic_match("msh/BR/2/e/LongFast/extra", "msh/BR/2/e/+")
    
    def test_multi_wildcard(self):
        """Test multi-level wildcard (#)."""
        assert mqtt_topic_match("msh/BR/2/e/LongFast", "msh/#")
        assert mqtt_topic_match("msh/BR/2/e/LongFast", "msh/BR/#")
        assert mqtt_topic_match("msh/BR/2/e/LongFast/!aabb", "msh/BR/2/e/#")
        assert mqtt_topic_match("msh/BR", "msh/#")
        assert mqtt_topic_match("msh/BR/2/e/LongFast", "#")
    
    def test_combined_wildcards(self):
        """Test combined wildcards."""
        assert mqtt_topic_match("msh/BR/2/e/LongFast/!aabb", "msh/+/+/e/#")
        assert mqtt_topic_match("msh/BR/2/map/!aabb", "msh/+/+/map/#")
        assert mqtt_topic_match("msh/BR/2/stat/!aabb", "msh/+/+/stat/#")
    
    def test_no_match(self):
        """Test non-matching patterns."""
        assert not mqtt_topic_match("msh/BR/2/e/LongFast", "other/#")
        assert not mqtt_topic_match("msh/BR/2/e/LongFast", "msh/BR/2/c/#")
        assert not mqtt_topic_match("msh/BR/2/e/LongFast", "msh/BR/2/e/Other")


class TestMatchesBypassTopic:
    """Tests for bypass topic matching."""
    
    def test_map_bypass(self):
        """Test map topic bypass."""
        patterns = ["msh/+/+/map/#"]
        assert matches_bypass_topic("msh/BR/2/map/!aabb", patterns)
        assert matches_bypass_topic("msh/US/2/map/!ccdd", patterns)
        assert not matches_bypass_topic("msh/BR/2/e/LongFast", patterns)
    
    def test_stat_bypass(self):
        """Test stat topic bypass."""
        patterns = ["msh/+/+/stat/#"]
        assert matches_bypass_topic("msh/BR/2/stat/!aabb", patterns)
        assert not matches_bypass_topic("msh/BR/2/e/LongFast", patterns)
    
    def test_multiple_patterns(self):
        """Test multiple bypass patterns."""
        patterns = ["msh/+/+/map/#", "msh/+/+/stat/#"]
        assert matches_bypass_topic("msh/BR/2/map/!aabb", patterns)
        assert matches_bypass_topic("msh/BR/2/stat/!aabb", patterns)
        assert not matches_bypass_topic("msh/BR/2/e/LongFast", patterns)


class TestExtractChannelId:
    """Tests for channel ID extraction."""
    
    def test_extract_from_encrypted_topic(self):
        """Test extraction from /e/ topic."""
        assert extract_channel_id("msh/BR/2/e/LongFast/!aabb") == "LongFast"
        assert extract_channel_id("msh/BR/2/e/MyPrivate/!aabb") == "MyPrivate"
    
    def test_extract_from_legacy_topic(self):
        """Test extraction from legacy /c/ topic."""
        assert extract_channel_id("msh/BR/2/c/LongFast/!aabb") == "LongFast"
    
    def test_extract_from_json_topic(self):
        """Test extraction from JSON topic."""
        assert extract_channel_id("msh/BR/2/json/LongFast/!aabb") == "LongFast"
    
    def test_extract_from_map_topic(self):
        """Test extraction from map topic (no channel)."""
        assert extract_channel_id("msh/BR/2/map/!aabb") is None
    
    def test_extract_from_invalid_topic(self):
        """Test extraction from invalid topics."""
        assert extract_channel_id("invalid/topic") is None
        assert extract_channel_id("") is None


class TestTopicTypeChecks:
    """Tests for topic type checking functions."""
    
    def test_is_json_topic(self):
        """Test JSON topic detection."""
        assert is_json_topic("msh/BR/2/json/LongFast/!aabb")
        assert not is_json_topic("msh/BR/2/e/LongFast/!aabb")
        assert not is_json_topic("msh/BR/2/c/LongFast/!aabb")
    
    def test_is_map_topic(self):
        """Test map topic detection."""
        assert is_map_topic("msh/BR/2/map/!aabb")
        assert is_map_topic("msh/US/2/map/!ccdd")
        assert not is_map_topic("msh/BR/2/e/LongFast/!aabb")
    
    def test_is_stat_topic(self):
        """Test stat topic detection."""
        assert is_stat_topic("msh/BR/2/stat/!aabb")
        assert is_stat_topic("msh/US/2/stat/!ccdd")
        assert not is_stat_topic("msh/BR/2/e/LongFast/!aabb")
