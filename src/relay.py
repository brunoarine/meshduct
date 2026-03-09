"""
Relay Engine: local sub → filter → upstream pub

The relay engine manages MQTT connections to both the local broker and
upstream targets, handles message routing and filtering.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import paho.mqtt.client as mqtt

from .config import Config, RelayTargetConfig
from .inspector import FilterDecision, InspectionResult, create_inspector_for_target
from .topics import remap_topic

logger = logging.getLogger(__name__)


@dataclass
class RelayStats:
    """Statistics for the relay."""
    packets_received: int = 0
    packets_forwarded: int = 0
    packets_dropped: int = 0
    packets_error: int = 0
    
    def snapshot(self) -> dict[str, int]:
        """Return a snapshot of the stats."""
        return {
            "received": self.packets_received,
            "forwarded": self.packets_forwarded,
            "dropped": self.packets_dropped,
            "error": self.packets_error,
        }


@dataclass
class TargetClient:
    """Wrapper for an upstream MQTT client and its configuration."""
    name: str
    config: RelayTargetConfig
    client: mqtt.Client
    inspector: Any  # PacketInspector
    connected: bool = False
    stats: RelayStats = field(default_factory=RelayStats)


class RelayEngine:
    """
    Main relay engine that manages all MQTT connections and message routing.
    
    The engine:
    - Connects to the local Mosquitto broker
    - Subscribes to configured topics
    - For each message, applies topic remapping and filtering
    - Forwards allowed packets to upstream targets
    - Handles bidirectional relay when configured
    """
    
    def __init__(self, config: Config):
        """
        Initialize the relay engine.
        
        Args:
            config: The main configuration.
        """
        self.config = config
        self.local_client: Optional[mqtt.Client] = None
        self.target_clients: dict[str, TargetClient] = {}
        self.running = False
        self._stop_event = threading.Event()
        
        # Stats for local broker
        self.local_stats = RelayStats()
        
        # Create inspectors and clients for each target
        self._setup_targets()
    
    def _setup_targets(self) -> None:
        """Set up upstream target clients."""
        for target_config in self.config.targets:
            if not target_config.enabled:
                logger.info(f"Target '{target_config.name}' is disabled, skipping")
                continue
            
            # Create inspector for this target
            inspector = create_inspector_for_target(
                target_config,
                self.config.encryption,
                self.config.encrypted_fallback,
            )
            
            # Create MQTT client
            client = mqtt.Client(
                client_id=target_config.client_id,
                protocol=mqtt.MQTTv311,
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            )
            
            # Set credentials
            if target_config.username:
                client.username_pw_set(
                    target_config.username,
                    target_config.password or "",
                )
            
            # Configure reconnection
            client.reconnect_delay_set(min_delay=1, max_delay=30)
            client.max_queued_messages_set(1000)
            
            # Set callbacks
            client.on_connect = self._on_target_connect(target_config.name)
            client.on_disconnect = self._on_target_disconnect(target_config.name)
            
            # For bidirectional relay, handle incoming messages
            if target_config.direction in ("in", "both"):
                client.on_message = self._on_upstream_message(target_config.name)
            
            self.target_clients[target_config.name] = TargetClient(
                name=target_config.name,
                config=target_config,
                client=client,
                inspector=inspector,
            )
    
    def _create_local_client(self) -> mqtt.Client:
        """Create and configure the local MQTT client."""
        client = mqtt.Client(
            client_id=self.config.local.client_id,
            protocol=mqtt.MQTTv311,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        )
        
        # Set credentials
        if self.config.local.username:
            client.username_pw_set(
                self.config.local.username,
                self.config.local.password or "",
            )
        
        # Configure reconnection
        client.reconnect_delay_set(min_delay=1, max_delay=30)
        
        # Set callbacks
        client.on_connect = self._on_local_connect
        client.on_disconnect = self._on_local_disconnect
        client.on_message = self._on_local_message
        
        return client
    
    def _on_local_connect(self, client, userdata, flags, rc, properties=None) -> None:
        """Callback when connected to local broker."""
        if rc == 0:
            logger.info(f"Connected to local broker: {self.config.local.host}:{self.config.local.port}")
            
            # Subscribe to configured topics
            for topic in self.config.local.subscribe:
                logger.info(f"Subscribing to: {topic}")
                client.subscribe(topic, qos=1)
        else:
            logger.error(f"Failed to connect to local broker, rc={rc}")
    
    def _on_local_disconnect(self, client, userdata, disconnect_flags, rc, properties=None) -> None:
        """Callback when disconnected from local broker."""
        if rc == 0:
            logger.info("Disconnected from local broker")
        else:
            logger.warning(f"Unexpected disconnect from local broker, rc={rc}")
    
    def _on_target_connect(self, target_name: str) -> Callable:
        """Create a callback for target connection."""
        def callback(client, userdata, flags, rc, properties=None) -> None:
            target = self.target_clients.get(target_name)
            if target:
                if rc == 0:
                    logger.info(f"Connected to upstream target: {target_name}")
                    target.connected = True
                    
                    # For bidirectional relay, subscribe to upstream topics
                    if target.config.direction in ("in", "both"):
                        # Subscribe to the remapped topic pattern
                        for local_topic in self.config.local.subscribe:
                            # Remap local subscription to remote topic
                            remote_topic = remap_topic(
                                local_topic,
                                target.config.topic_map.local_prefix,
                                target.config.topic_map.remote_prefix,
                                reverse=True,
                            )
                            logger.info(f"[{target_name}] Subscribing to upstream: {remote_topic}")
                            client.subscribe(remote_topic, qos=target.config.qos)
                else:
                    logger.error(f"Failed to connect to target {target_name}, rc={rc}")
                    target.connected = False
        return callback
    
    def _on_target_disconnect(self, target_name: str) -> Callable:
        """Create a callback for target disconnection."""
        def callback(client, userdata, disconnect_flags, rc, properties=None) -> None:
            target = self.target_clients.get(target_name)
            if target:
                target.connected = False
                if rc == 0:
                    logger.info(f"Disconnected from upstream target: {target_name}")
                else:
                    logger.warning(f"Unexpected disconnect from target {target_name}, rc={rc}")
        return callback
    
    def _on_local_message(self, client, userdata, message) -> None:
        """Callback when a message is received from the local broker."""
        topic = message.topic
        payload = message.payload
        
        self.local_stats.packets_received += 1
        
        logger.debug(f"Received message on {topic} ({len(payload)} bytes)")
        
        # Process for each target
        for target_name, target in self.target_clients.items():
            if target.config.direction == "in":
                # Only receives from upstream, skip local messages
                continue
            
            self._process_message_for_target(topic, payload, target, direction="out")
    
    def _on_upstream_message(self, target_name: str) -> Callable:
        """Create a callback for messages from upstream broker."""
        def callback(client, userdata, message) -> None:
            target = self.target_clients.get(target_name)
            if not target:
                return
            
            if target.config.direction not in ("in", "both"):
                return
            
            topic = message.topic
            payload = message.payload
            
            logger.debug(f"[{target_name}] Received upstream message on {topic}")
            
            self._process_message_for_target(topic, payload, target, direction="in")
        return callback
    
    def _process_message_for_target(
        self,
        topic: str,
        payload: bytes,
        target: TargetClient,
        direction: str,
    ) -> None:
        """
        Process a message for a specific target.
        
        Args:
            topic: The original topic.
            payload: The message payload.
            target: The target client wrapper.
            direction: "out" (local→remote) or "in" (remote→local).
        """
        # Inspect the packet
        result: InspectionResult = target.inspector.inspect(topic, payload)
        
        if result.decision == FilterDecision.DROP:
            target.stats.packets_dropped += 1
            logger.debug(
                f"[{target.name}] Dropping packet: topic={topic}, "
                f"portnum={result.portnum_name or 'N/A'}, reason={result.reason}"
            )
            return
        
        # Determine the destination
        if direction == "out":
            # Forward to upstream
            dest_client = target.client
            dest_topic = remap_topic(
                topic,
                target.config.topic_map.local_prefix,
                target.config.topic_map.remote_prefix,
            )
            dest_name = target.name
        else:
            # Forward to local
            dest_client = self.local_client
            dest_topic = remap_topic(
                topic,
                target.config.topic_map.local_prefix,
                target.config.topic_map.remote_prefix,
                reverse=True,
            )
            dest_name = "local"
        
        # Forward the message
        try:
            dest_client.publish(
                dest_topic,
                payload,
                qos=target.config.qos,
                retain=False,
            )
            target.stats.packets_forwarded += 1
            
            logger.debug(
                f"[{target.name}] Forwarded: {topic} → {dest_topic} "
                f"(portnum={result.portnum_name or 'N/A'}, reason={result.reason})"
            )
        except Exception as e:
            target.stats.packets_error += 1
            logger.error(f"[{target.name}] Failed to publish to {dest_topic}: {e}")
    
    def start(self) -> None:
        """Start the relay engine."""
        if self.running:
            logger.warning("Relay engine is already running")
            return
        
        logger.info("Starting relay engine...")
        self.running = True
        self._stop_event.clear()
        
        # Create and connect local client
        self.local_client = self._create_local_client()
        try:
            self.local_client.connect(
                self.config.local.host,
                self.config.local.port,
                keepalive=60,
            )
            self.local_client.loop_start()
        except Exception as e:
            logger.error(f"Failed to connect to local broker: {e}")
            self.running = False
            return
        
        # Connect to upstream targets
        for target_name, target in self.target_clients.items():
            try:
                target.client.connect(
                    target.config.host,
                    target.config.port,
                    keepalive=60,
                )
                target.client.loop_start()
            except Exception as e:
                logger.error(f"Failed to connect to target {target_name}: {e}")
                # Continue with other targets
        
        # Start stats logger thread
        stats_thread = threading.Thread(target=self._stats_logger, daemon=True)
        stats_thread.start()
        
        logger.info("Relay engine started")
    
    def stop(self) -> None:
        """Stop the relay engine."""
        if not self.running:
            return
        
        logger.info("Stopping relay engine...")
        self.running = False
        self._stop_event.set()
        
        # Disconnect local client
        if self.local_client:
            self.local_client.loop_stop()
            self.local_client.disconnect()
        
        # Disconnect target clients
        for target_name, target in self.target_clients.items():
            try:
                target.client.loop_stop()
                target.client.disconnect()
            except Exception as e:
                logger.debug(f"Error disconnecting from {target_name}: {e}")
        
        logger.info("Relay engine stopped")
    
    def _stats_logger(self) -> None:
        """Periodically log statistics."""
        while self.running:
            self._stop_event.wait(self.config.stats_interval)
            if not self.running:
                break
            
            stats = self.local_stats.snapshot()
            logger.info(
                f"Stats (local): received={stats['received']}, "
                f"forwarded={stats['forwarded']}, "
                f"dropped={stats['dropped']}, "
                f"error={stats['error']}"
            )
            
            for target_name, target in self.target_clients.items():
                stats = target.stats.snapshot()
                logger.info(
                    f"Stats ({target_name}): "
                    f"forwarded={stats['forwarded']}, "
                    f"dropped={stats['dropped']}, "
                    f"error={stats['error']}"
                )
    
    def run_forever(self) -> None:
        """Start the relay and run until interrupted."""
        self.start()
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        finally:
            self.stop()
