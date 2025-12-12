#!/usr/bin/env python3
"""
Base Detector Abstract Class

All detection modules must extend this class and implement
the required abstract methods.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """
    Abstract base class for all threat detectors

    Provides:
    - Lifecycle management (initialize, start, stop)
    - Rule evaluation integration
    - Threat creation and reporting
    - Location enrichment
    - Transport abstraction
    """

    def __init__(self, rule_engine, transport, config, location_service):
        """
        Initialize detector

        Args:
            rule_engine: Rule engine instance for evaluating events
            transport: Transport layer for sending threats
            config: Configuration manager
            location_service: Service for getting current location
        """
        self.rule_engine = rule_engine
        self.transport = transport
        self.config = config
        self.location_service = location_service

        self.running = False
        self.detector_name = self.__class__.__name__
        self.event_count = 0
        self.threat_count = 0

        logger.info(f"Initialized {self.detector_name}")

    @abstractmethod
    async def initialize(self):
        """
        Initialize hardware/resources required for detection

        This method should:
        - Set up any required hardware interfaces
        - Validate capabilities
        - Prepare for detection

        Raises:
            RuntimeError: If initialization fails
        """
        pass

    @abstractmethod
    async def detect(self):
        """
        Main detection loop

        This method should:
        - Continuously monitor for events
        - Call evaluate_event() for each detected event
        - Handle errors gracefully

        Note: This runs in an async loop until self.running = False
        """
        pass

    @abstractmethod
    async def shutdown(self):
        """
        Cleanup resources

        This method should:
        - Release hardware resources
        - Close file handles
        - Clean up temporary data
        """
        pass

    async def start(self):
        """Start the detector"""
        if self.running:
            logger.warning(f"{self.detector_name} is already running")
            return

        logger.info(f"Starting {self.detector_name}...")

        try:
            # Initialize the detector
            await self.initialize()

            # Set running flag
            self.running = True

            # Run detection loop
            await self.detect()

        except Exception as e:
            logger.error(f"{self.detector_name} failed: {e}", exc_info=True)
            self.running = False
            raise

    async def stop(self):
        """Stop the detector gracefully"""
        if not self.running:
            return

        logger.info(f"Stopping {self.detector_name}...")
        self.running = False

        try:
            await self.shutdown()
        except Exception as e:
            logger.error(f"Error during {self.detector_name} shutdown: {e}")

        logger.info(f"{self.detector_name} stopped")

    async def evaluate_event(self, event_data: Dict[str, Any]):
        """
        Evaluate event against detection rules

        Args:
            event_data: Raw event data from detector

        Returns:
            True if threat was detected and reported, False otherwise
        """
        self.event_count += 1

        # Get applicable rules for this detector
        rule_category = self._get_rule_category()
        matches = self.rule_engine.evaluate(event_data, rule_set=rule_category)

        if matches:
            # Create and send threat
            threat = await self.create_threat(event_data, matches)
            await self.send_threat(threat)
            self.threat_count += 1
            return True

        return False

    async def create_threat(self, event: Dict[str, Any], rules: List[Any]) -> Dict[str, Any]:
        """
        Create standardized threat object

        Args:
            event: Raw event data
            rules: List of matched rules

        Returns:
            Standardized threat dictionary
        """
        # Calculate threat score (average of all matching rules)
        threat_score = self._calculate_threat_score(rules)
        risk_level = self._get_risk_level(threat_score)

        # Get current location
        location = await self.location_service.get_location()

        # Build threat object
        threat = {
            'timestamp': datetime.utcnow().isoformat(),
            'sensor_id': self.config.get('sensor_id'),
            'sensor_name': self.config.get('sensor_name'),
            'source': self.detector_name,
            'threat_type': rules[0].threat_type if rules else 'unknown',
            'threat_score': threat_score,
            'risk_level': risk_level,
            'threats_detected': [r.name for r in rules],
            'message': self._generate_message(event, rules),
            'raw_data': event,
            'metadata': self._get_metadata()
        }

        # Add location if available
        if location:
            threat['geolocation'] = {
                'lat': location['lat'],
                'lon': location['lon'],
                'accuracy': location.get('accuracy'),
                'source': location.get('source')
            }
            if 'city' in location:
                threat['city'] = location['city']
            if 'country' in location:
                threat['country'] = location['country']

        return threat

    async def send_threat(self, threat: Dict[str, Any]):
        """
        Send threat to dashboard via transport layer

        Args:
            threat: Threat dictionary
        """
        try:
            # Send via transport layer
            success = await self.transport.send(threat, topic='threats')

            if success:
                logger.info(
                    f"{self.detector_name} reported threat: "
                    f"{threat['threat_type']} (score: {threat['threat_score']:.2f})"
                )
            else:
                logger.warning(f"Failed to send threat from {self.detector_name}")

        except Exception as e:
            logger.error(f"Error sending threat: {e}")

    def _calculate_threat_score(self, rules: List[Any]) -> float:
        """
        Calculate aggregate threat score from matching rules

        Args:
            rules: List of matched rules

        Returns:
            Threat score between 0.0 and 1.0
        """
        if not rules:
            return 0.0

        # Weight rules by severity
        severity_weights = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.3,
            'info': 0.1
        }

        total_weight = 0.0
        weighted_sum = 0.0

        for rule in rules:
            weight = severity_weights.get(rule.severity.lower(), 0.5)
            total_weight += weight
            weighted_sum += weight

        if total_weight == 0:
            return 0.5

        # Normalize to 0-1 range
        score = min(1.0, weighted_sum / len(rules))
        return round(score, 3)

    def _get_risk_level(self, score: float) -> str:
        """
        Convert threat score to risk level

        Args:
            score: Threat score (0.0 - 1.0)

        Returns:
            Risk level string
        """
        if score >= 0.8:
            return 'critical'
        elif score >= 0.6:
            return 'high'
        elif score >= 0.4:
            return 'medium'
        elif score >= 0.2:
            return 'low'
        else:
            return 'info'

    def _generate_message(self, event: Dict[str, Any], rules: List[Any]) -> str:
        """
        Generate human-readable threat message

        Args:
            event: Raw event data
            rules: Matched rules

        Returns:
            Threat message string
        """
        if not rules:
            return f"Suspicious activity detected by {self.detector_name}"

        # Use first rule's name as basis
        primary_threat = rules[0].name

        if len(rules) == 1:
            return f"{primary_threat} detected"
        else:
            return f"Multiple threats detected: {primary_threat} (+{len(rules)-1} more)"

    def _get_metadata(self) -> Dict[str, Any]:
        """
        Get detector-specific metadata

        Returns:
            Metadata dictionary
        """
        return {
            'detector_version': '2.0.0',
            'event_count': self.event_count,
            'threat_count': self.threat_count
        }

    def _get_rule_category(self) -> str:
        """
        Get rule category for this detector

        Returns:
            Rule category string (e.g., 'usb', 'wifi', 'ble')
        """
        # Default implementation - override in subclasses
        name_lower = self.detector_name.lower()
        if 'usb' in name_lower:
            return 'usb'
        elif 'wifi' in name_lower:
            return 'wifi'
        elif 'ble' in name_lower or 'bluetooth' in name_lower:
            return 'ble'
        elif 'airdrop' in name_lower:
            return 'airdrop'
        elif 'network' in name_lower:
            return 'network'
        else:
            return 'all'

    def get_status(self) -> Dict[str, Any]:
        """
        Get detector status for health reporting

        Returns:
            Status dictionary
        """
        return {
            'name': self.detector_name,
            'running': self.running,
            'events_processed': self.event_count,
            'threats_detected': self.threat_count
        }
