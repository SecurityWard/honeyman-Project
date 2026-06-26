#!/usr/bin/env python3
"""
Base Detector Abstract Class

All detection modules must extend this class and implement
the required abstract methods.
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# How far back to keep per-(rule, target) cooldown timestamps. Bigger than
# any plausible rule cooldown, so it's effectively "long enough that nothing
# can be wrongly de-throttled" but small enough that the cache stays bounded.
_COOLDOWN_CACHE_MAX_AGE_SECONDS = 3600.0
_COOLDOWN_PRUNE_EVERY_SECONDS = 300.0


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
        self.throttled_count = 0

        # Per-(rule_id, event-identity) timestamps of the last sent threat.
        # See _filter_throttled — this is what stops the same rule from
        # re-firing on the same nearby device dozens of times a minute.
        self._cooldowns: Dict[Tuple[str, str], float] = {}
        self._cooldowns_last_pruned: float = 0.0

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
            # Per-(rule, target) cooldown so the same rule firing on the same
            # observed device doesn't get pushed to the backend every scan.
            survivors = self._filter_throttled(matches, event_data)
            if not survivors:
                return False

            threat = await self.create_threat(event_data, survivors)
            await self.send_threat(threat)
            self.threat_count += 1
            return True

        return False

    # ------------------------------------------------------------------ #
    # Per-(rule, target) throttling — drops repeat alerts for the same   #
    # rule/device pair inside a cooldown window. Honours either           #
    # `tuning.cooldown_seconds` directly, or derives it from              #
    # `tuning.max_alerts_per_hour` if present. No tuning → no throttle.   #
    # ------------------------------------------------------------------ #

    def _filter_throttled(
        self,
        rules: List[Any],
        event: Dict[str, Any],
    ) -> List[Any]:
        """Return the subset of rules that aren't currently in cooldown for
        this event's target identity. Updates the cooldown cache as a side
        effect, so a rule that passes here gets re-throttled for next time."""
        now = time.monotonic()
        self._maybe_prune_cooldowns(now)
        identity = self._event_identity(event)
        survivors: List[Any] = []
        for rule in rules:
            rule_id = getattr(rule, "rule_id", None) or getattr(rule, "name", "anon")
            cooldown = self._rule_cooldown_seconds(rule)
            key = (rule_id, identity)
            if cooldown <= 0:
                # No tuning declared → never throttle, but still update the
                # last-seen so observability stays accurate.
                self._cooldowns[key] = now
                survivors.append(rule)
                continue
            last = self._cooldowns.get(key)
            if last is None or (now - last) >= cooldown:
                self._cooldowns[key] = now
                survivors.append(rule)
            else:
                self.throttled_count += 1
                logger.debug(
                    "Throttled rule %s for %s (last fired %.1fs ago, cooldown %.1fs)",
                    rule_id, identity, now - last, cooldown,
                )
        return survivors

    @staticmethod
    def _event_identity(event: Dict[str, Any]) -> str:
        """A stable string identifying *what* this event is about, so the
        cooldown dedups one rule against the same observed device — not
        against every event of that detector. Falls through several
        common identifiers in priority order so each detector type lands
        on a reasonable key."""
        for key in (
            "device_mac",
            "src_host",
            "service_name",
            "device_id",
            "ssid",
            "bssid",
            "file_hash",
        ):
            v = event.get(key)
            if v:
                return f"{key}={v}"
        # USB-style triplet
        parts = [str(event.get(k, "")) for k in ("vendor_id", "product_id", "serial")]
        if any(parts):
            return "usb=" + ":".join(parts)
        return "anon"

    @staticmethod
    def _rule_cooldown_seconds(rule: Any) -> float:
        """Read cooldown from rule metadata.

        Preference order:
            tuning.cooldown_seconds       — explicit per-rule
            tuning.max_alerts_per_hour    — derive 3600/N as the spacing
        Both absent → return 0 (no throttling)."""
        tuning = getattr(rule, "tuning", None) or {}
        cooldown = tuning.get("cooldown_seconds")
        if cooldown is not None:
            try:
                return max(0.0, float(cooldown))
            except (TypeError, ValueError):
                return 0.0
        per_hour = tuning.get("max_alerts_per_hour")
        if per_hour:
            try:
                per_hour = float(per_hour)
                if per_hour > 0:
                    return 3600.0 / per_hour
            except (TypeError, ValueError):
                pass
        return 0.0

    def _maybe_prune_cooldowns(self, now: float) -> None:
        """Drop entries older than _COOLDOWN_CACHE_MAX_AGE_SECONDS so the
        cache stays bounded by 'unique (rule, target) pairs seen recently'
        rather than 'unique pairs since process start'."""
        if (now - self._cooldowns_last_pruned) < _COOLDOWN_PRUNE_EVERY_SECONDS:
            return
        cutoff = now - _COOLDOWN_CACHE_MAX_AGE_SECONDS
        before = len(self._cooldowns)
        self._cooldowns = {
            k: ts for k, ts in self._cooldowns.items() if ts >= cutoff
        }
        self._cooldowns_last_pruned = now
        after = len(self._cooldowns)
        if before != after:
            logger.debug(
                "Cooldown cache pruned: %d → %d entries", before, after,
            )

    async def create_threat(self, event: Dict[str, Any], rules: List[Any]) -> Dict[str, Any]:
        """
        Create a threat payload that matches the backend's POST /v2/threats schema.

        See backend app/schemas/threat.py — ThreatCreate. The
        envelope here is what the backend will accept directly; extra fields
        (sensor_name, message, etc.) are dropped by Pydantic so we don't
        bother sending them.

        Args:
            event: Raw event data from the detector
            rules: List of matched rule objects

        Returns:
            Threat dict ready to ship via transport.send(threat, topic='threats')
        """
        threat_score = self._calculate_threat_score(rules)
        severity = self._get_risk_level(threat_score)
        confidence = self._max_confidence(rules)

        # Pull a top-level latitude/longitude (backend stores them denormalised
        # on the threat row so the map can render without joining the sensor table).
        location = await self.location_service.get_location()

        threat: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat(),
            "sensor_id": self.config.get("sensor_id"),
            "threat_type": rules[0].threat_type if rules else "unknown",
            "detector_type": self._get_rule_category(),
            "severity": severity,
            "threat_score": threat_score,
            "matched_rules": self._serialise_rules(rules),
            "raw_event": event,
            "mitre_tactics": self._collect_mitre(rules, "tactics"),
            "mitre_techniques": self._collect_mitre(rules, "techniques"),
        }

        if confidence is not None:
            threat["confidence"] = confidence

        # Optional, well-known event fields the detectors commonly populate.
        for key in (
            "device_name", "device_mac", "device_ip",
            "src_host", "src_port", "dst_host", "dst_port",
        ):
            if event.get(key) is not None:
                threat[key] = event[key]

        if location:
            if location.get("lat") is not None:
                threat["latitude"] = location["lat"]
            if location.get("lon") is not None:
                threat["longitude"] = location["lon"]
            if location.get("city"):
                threat["city"] = location["city"]
            if location.get("country"):
                threat["country"] = location["country"]
            # Phase D — accuracy + source so the map can render a confidence circle
            if location.get("accuracy") is not None:
                threat["accuracy_meters"] = float(location["accuracy"])
            if location.get("source"):
                threat["location_method"] = location["source"]

        return threat

    @staticmethod
    def _serialise_rules(rules: List[Any]) -> List[Dict[str, Any]]:
        """Convert matched rule objects into dicts for the threat payload."""
        out: List[Dict[str, Any]] = []
        for rule in rules:
            entry = {
                "rule_id": getattr(rule, "rule_id", None),
                "name": getattr(rule, "name", None),
                "severity": getattr(rule, "severity", None),
            }
            confidence = getattr(rule, "confidence", None)
            if confidence is not None:
                entry["confidence"] = confidence
            out.append(entry)
        return out

    @staticmethod
    def _max_confidence(rules: List[Any]) -> Optional[float]:
        """Return the highest per-rule confidence in [0, 1], or None."""
        confidences = [
            getattr(r, "confidence", None) for r in rules
        ]
        confidences = [c for c in confidences if c is not None]
        if not confidences:
            return None
        return max(min(float(c), 1.0) for c in confidences)

    @staticmethod
    def _collect_mitre(rules: List[Any], kind: str) -> List[str]:
        """
        Pull MITRE ATT&CK tactics/techniques from rule metadata.

        Rule objects expose metadata via either an `mitre_attack` flat list
        (the YAML rules use this) or via `mitre_tactics` / `mitre_techniques`
        on the metadata dict. We accept both.
        """
        seen: List[str] = []
        for rule in rules:
            meta = getattr(rule, "metadata", None) or {}
            # New-style explicit fields
            for item in meta.get(f"mitre_{kind}", []) or []:
                if item not in seen:
                    seen.append(item)
            # Legacy flat list — best-effort: T1xxx ≈ technique, TA00xx ≈ tactic
            for item in meta.get("mitre_attack", []) or []:
                is_tactic = isinstance(item, str) and item.upper().startswith("TA")
                if kind == "tactics" and is_tactic and item not in seen:
                    seen.append(item)
                elif kind == "techniques" and not is_tactic and item not in seen:
                    seen.append(item)
        return seen

    async def send_threat(self, threat: Dict[str, Any]):
        """Send a threat payload to the backend via the transport layer."""
        try:
            success = await self.transport.send(threat, topic="threats")

            if success:
                score = threat.get("threat_score") or 0.0
                logger.info(
                    "%s reported threat: %s (severity=%s, score=%.2f)",
                    self.detector_name,
                    threat.get("threat_type", "unknown"),
                    threat.get("severity", "?"),
                    score,
                )
            else:
                logger.warning("Failed to send threat from %s", self.detector_name)

        except Exception as exc:
            logger.error("Error sending threat: %s", exc)

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
