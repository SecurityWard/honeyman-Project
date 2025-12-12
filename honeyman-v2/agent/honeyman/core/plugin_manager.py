#!/usr/bin/env python3
"""Plugin Manager - Dynamic detector loading"""

import logging
import importlib
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class PluginManager:
    """Manages detector plugin lifecycle"""

    def __init__(self, rule_engine, transport, config, location_service):
        """
        Initialize plugin manager

        Args:
            rule_engine: Rule engine instance
            transport: Transport handler
            config: Configuration manager
            location_service: Location service
        """
        self.rule_engine = rule_engine
        self.transport = transport
        self.config = config
        self.location_service = location_service

        self.detector_classes = {}

    def load_detector(self, detector_name: str) -> Optional[Any]:
        """
        Load detector plugin by name

        Args:
            detector_name: Name of detector ('usb', 'wifi', 'bluetooth', etc.)

        Returns:
            Detector instance or None if failed
        """
        try:
            # Map detector names to module paths
            detector_modules = {
                'usb': 'honeyman.detectors.usb_detector',
                'wifi': 'honeyman.detectors.wifi_detector',
                'bluetooth': 'honeyman.detectors.ble_detector',
                'ble': 'honeyman.detectors.ble_detector',
                'airdrop': 'honeyman.detectors.airdrop_detector',
                'network': 'honeyman.detectors.network_detector',
            }

            module_path = detector_modules.get(detector_name)
            if not module_path:
                logger.error(f"Unknown detector: {detector_name}")
                return None

            # Dynamically import detector module
            module = importlib.import_module(module_path)

            # Get detector class
            class_name = ''.join(word.capitalize() for word in detector_name.split('_')) + 'Detector'
            detector_class = getattr(module, class_name)

            # Instantiate detector
            detector = detector_class(
                rule_engine=self.rule_engine,
                transport=self.transport,
                config=self.config,
                location_service=self.location_service
            )

            logger.info(f"Loaded detector: {detector_name}")
            return detector

        except ImportError as e:
            logger.error(f"Failed to import detector {detector_name}: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to load detector {detector_name}: {e}")
            return None
