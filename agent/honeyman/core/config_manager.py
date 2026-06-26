#!/usr/bin/env python3
"""Configuration Manager"""

import yaml
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manages agent configuration from YAML file"""

    def __init__(self, config_path: str):
        """
        Load configuration from file

        Args:
            config_path: Path to YAML config file
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            logger.warning(f"Config file not found: {self.config_path}")
            return self._get_default_config()

        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                logger.info(f"Loaded configuration from {self.config_path}")
                return config or {}
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Defaults: HTTPS+API-key transport, no MQTT."""
        return {
            'sensor_id': 'unknown',
            'sensor_name': 'Unknown Sensor',
            'rules_dir': '/etc/honeyman/rules',
            'heartbeat_interval': 60,
            'transport': {
                'protocol': 'https',
                'fallback': 'none',
                'https': {
                    'base_url': 'https://api.honeymanproject.com',
                    'api_prefix': '/api/v2',
                    'api_key_file': '/etc/honeyman/api_key',
                    'timeout': 30,
                    'verify_ssl': True,
                },
            },
            'detectors': {
                'usb': True,
                'wifi': False,
                'bluetooth': False,
                'network': True,
                'airdrop': False,
            },
            'location': {
                'enabled': True,
                'gps_enabled': False,
            },
            'logging': {
                'level': 'INFO',
                'file': '/var/log/honeyman/agent.log',
            },
        }

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default

            if value is None:
                return default

        return value

    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def save(self):
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            logger.info(f"Saved configuration to {self.config_path}")
        except Exception as e:
            logger.error(f"Error saving config: {e}")
