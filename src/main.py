"""
Entry point for the Meshtastic MQTT Relay.

Loads configuration, sets up logging, and starts the relay engine.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from .config import load_config
from .relay import RelayEngine


def setup_logging(level: str = "INFO") -> None:
    """
    Configure Python logging.
    
    Args:
        level: Log level name (DEBUG, INFO, WARNING, ERROR).
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )
    
    # Reduce verbosity of paho-mqtt
    logging.getLogger("paho.mqtt.client").setLevel(logging.WARNING)


def main() -> int:
    """
    Main entry point.
    
    Returns:
        Exit code (0 for success, non-zero for error).
    """
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="Meshtastic MQTT Relay - Filter and relay Meshtastic packets"
    )
    parser.add_argument(
        "--config", "-c",
        default="/app/config.yaml",
        help="Path to configuration file (default: /app/config.yaml)",
    )
    parser.add_argument(
        "--log-level", "-l",
        default=os.environ.get("LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO, or LOG_LEVEL env var)",
    )
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)
    
    logger.info("Meshtastic MQTT Relay starting...")
    
    # Load configuration
    try:
        config = load_config(args.config)
    except FileNotFoundError as e:
        logger.error(f"Configuration file not found: {e}")
        return 1
    except ValueError as e:
        logger.error(f"Configuration validation failed: {e}")
        return 1
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return 1
    
    # Check if there are any enabled targets
    enabled_targets = [t for t in config.targets if t.enabled]
    if not enabled_targets:
        logger.warning("No enabled relay targets configured")
        return 0
    
    # Create and run the relay engine
    engine = RelayEngine(config)
    
    try:
        engine.run_forever()
    except Exception as e:
        logger.exception(f"Relay engine crashed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
