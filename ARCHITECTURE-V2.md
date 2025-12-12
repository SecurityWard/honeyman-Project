# Honeyman Project Version 2.0 - Technical Architecture

**Document Version:** 1.0
**Last Updated:** 2025-10-23
**Status:** Planning & Design Phase

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [System Components](#system-components)
4. [Agent Architecture](#agent-architecture)
5. [Dashboard Architecture](#dashboard-architecture)
6. [Protocol Layer](#protocol-layer)
7. [Detection Rule Engine](#detection-rule-engine)
8. [Data Flow](#data-flow)
9. [Database Schema](#database-schema)
10. [Security Architecture](#security-architecture)
11. [Deployment Architecture](#deployment-architecture)
12. [API Specification](#api-specification)
13. [Migration Strategy](#migration-strategy)
14. [Performance & Scalability](#performance--scalability)

---

## Executive Summary

Honeyman V2 represents a complete architectural overhaul from a monolithic, manually-deployed detection system to a modular, cloud-native, agent-based platform. The core improvements focus on:

- **Ease of Deployment**: One-command installation reducing setup from 30+ minutes to under 5 minutes
- **Protocol Flexibility**: Multi-protocol support (MQTT, HTTP, WebSocket, gRPC) for diverse deployment scenarios
- **Rule-Based Detection**: Separation of detection logic from code, enabling live updates and A/B testing
- **Enterprise Dashboard**: Long-term storage, geolocation, advanced analytics, and real-time visualization
- **Scalability**: Support for hundreds of distributed sensors with centralized management

### Key Metrics Improvement

| Metric | V1 | V2 Target |
|--------|----|---------|
| Setup Time | 30-60 min | < 5 min |
| Technical Skill Required | Intermediate | Beginner |
| Protocol Options | 1 (HTTP) | 4+ (MQTT, HTTP, WS, gRPC) |
| Data Retention | None (in-memory) | 90+ days (configurable) |
| Geolocation Coverage | 0% | > 80% |
| Rule Update Time | Hours (code change) | Seconds (live push) |
| False Positive Rate | ~20% | < 5% (tunable) |

---

## Architecture Overview

### High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         HONEYMAN V2 PLATFORM                         │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                          SENSOR LAYER                                 │
│                                                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │   RPI5 #1    │  │   RPI5 #2    │  │   RPI5 #N    │              │
│  │ ┌──────────┐ │  │ ┌──────────┐ │  │ ┌──────────┐ │              │
│  │ │  Agent   │ │  │ │  Agent   │ │  │ │  Agent   │ │              │
│  │ └──────────┘ │  │ └──────────┘ │  │ └──────────┘ │              │
│  │ ┌──────────┐ │  │ ┌──────────┐ │  │ ┌──────────┐ │              │
│  │ │Detectors │ │  │ │Detectors │ │  │ │Detectors │ │              │
│  │ │WiFi BLE  │ │  │ │WiFi BLE  │ │  │ │WiFi BLE  │ │              │
│  │ │USB AirDr │ │  │ │USB AirDr │ │  │ │USB AirDr │ │              │
│  │ └──────────┘ │  │ └──────────┘ │  │ └──────────┘ │              │
│  │ ┌──────────┐ │  │ ┌──────────┐ │  │ ┌──────────┐ │              │
│  │ │OpenCanary│ │  │ │OpenCanary│ │  │ │OpenCanary│ │              │
│  │ │ Docker   │ │  │ │ Docker   │ │  │ │ Docker   │ │              │
│  │ └──────────┘ │  │ └──────────┘ │  │ └──────────┘ │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│         ↓                  ↓                  ↓                       │
└─────────┼──────────────────┼──────────────────┼───────────────────────┘
          │                  │                  │
          └──────────────────┴──────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────────┐
│                      TRANSPORT LAYER                                 │
│                                                                      │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐   │
│  │    MQTT    │  │    HTTP    │  │  WebSocket │  │    gRPC    │   │
│  │  (Primary) │  │ (Fallback) │  │(Real-time) │  │  (Future)  │   │
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘   │
│         ↓                ↓               ↓               ↓          │
└─────────┼────────────────┼───────────────┼───────────────┼──────────┘
          └────────────────┴───────────────┴───────────────┘
                                  ↓
┌─────────────────────────────────────────────────────────────────────┐
│                      INGESTION LAYER                                 │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              MQTT Broker (Mosquitto)                        │   │
│  │  Topics: sensors/{id}/threats, /heartbeat, /config          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              API Gateway (Node.js/Express)                   │   │
│  │  Routes: /api/v2/sensors, /threats, /rules, /analytics      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                       │
└─────────────────────────────┼───────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│                      PROCESSING LAYER                                │
│                                                                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐  │
│  │  Geolocation     │  │  Rule Engine     │  │   Correlation   │  │
│  │  Enrichment      │  │  Evaluation      │  │   Analysis      │  │
│  └──────────────────┘  └──────────────────┘  └─────────────────┘  │
│           ↓                     ↓                      ↓            │
└───────────┼─────────────────────┼──────────────────────┼────────────┘
            └─────────────────────┴──────────────────────┘
                                  ↓
┌─────────────────────────────────────────────────────────────────────┐
│                      STORAGE LAYER                                   │
│                                                                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐  │
│  │   PostgreSQL     │  │      Redis       │  │ Elasticsearch   │  │
│  │  + TimescaleDB   │  │   (Cache/RT)     │  │  (Optional)     │  │
│  │  (Long-term)     │  │                  │  │                 │  │
│  └──────────────────┘  └──────────────────┘  └─────────────────┘  │
│           ↓                     ↓                      ↓            │
└───────────┼─────────────────────┼──────────────────────┼────────────┘
            └─────────────────────┴──────────────────────┘
                                  ↓
┌─────────────────────────────────────────────────────────────────────┐
│                      PRESENTATION LAYER                              │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                  React Dashboard (SPA)                       │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │   │
│  │  │  Map     │ │ Sensors  │ │ Threats  │ │ Analytics│       │   │
│  │  │  View    │ │ Manager  │ │ Explorer │ │ Engine   │       │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐                    │   │
│  │  │  Rules   │ │  Alerts  │ │  System  │                    │   │
│  │  │  Editor  │ │  Config  │ │  Health  │                    │   │
│  │  └──────────┘ └──────────┘ └──────────┘                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↕                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              WebSocket (Socket.IO)                           │   │
│  │              Real-time Updates                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                      INTEGRATION LAYER                               │
│                                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │  Slack   │  │  Email   │  │   SIEM   │  │ Webhooks │           │
│  │  Discord │  │   SMS    │  │ Splunk   │  │  Custom  │           │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## System Components

### 1. Agent Component

**Package:** `honeyman-agent`
**Language:** Python 3.8+
**Distribution:** PyPI package

#### Core Modules

```python
honeyman/
├── agent.py                    # Main orchestrator
├── core/
│   ├── agent_core.py          # Agent lifecycle management
│   ├── plugin_manager.py      # Dynamic module loading
│   ├── config_manager.py      # Configuration validation
│   ├── heartbeat.py           # Health reporting & monitoring
│   └── capability_detector.py # Hardware capability detection
├── detectors/
│   ├── base_detector.py       # Abstract base class
│   ├── usb_detector.py        # USB threat detection
│   ├── wifi_detector.py       # WiFi threat detection
│   ├── ble_detector.py        # Bluetooth LE detection
│   ├── airdrop_detector.py    # AirDrop threat detection
│   └── network_detector.py    # OpenCanary integration
├── transport/
│   ├── protocol_handler.py    # Multi-protocol abstraction
│   ├── mqtt_client.py         # MQTT transport
│   ├── http_client.py         # HTTP/REST transport
│   ├── websocket_client.py    # WebSocket transport
│   └── grpc_client.py         # gRPC transport (future)
├── rules/
│   ├── rule_engine.py         # Rule evaluation engine
│   ├── rule_loader.py         # YAML rule parser
│   ├── rule_validator.py      # Rule syntax validation
│   ├── rule_updater.py        # Auto-update from dashboard
│   └── evaluators/
│       ├── condition_evaluator.py
│       ├── hash_evaluator.py
│       └── pattern_evaluator.py
└── utils/
    ├── logger.py              # Structured logging
    ├── crypto.py              # Encryption utilities
    └── metrics.py             # Performance metrics
```

#### Agent Responsibilities

- **Detection Orchestration**: Manage lifecycle of all detection modules
- **Hardware Abstraction**: Auto-detect and configure available sensors
- **Rule Application**: Apply detection rules to events in real-time
- **Data Collection**: Gather threat events from all detectors
- **Transport Management**: Send data via configured protocol with fallback
- **Self-Monitoring**: Report health metrics and performance stats
- **Auto-Update**: Download rule updates and software patches
- **Local Caching**: Queue data when dashboard is unreachable

---

### 2. Detection Modules

Each detector implements the `BaseDetector` interface:

```python
class BaseDetector(ABC):
    def __init__(self, rule_engine, transport, config):
        self.rule_engine = rule_engine
        self.transport = transport
        self.config = config
        self.running = False

    @abstractmethod
    def initialize(self):
        """Initialize hardware/resources"""
        pass

    @abstractmethod
    def detect(self):
        """Main detection loop"""
        pass

    @abstractmethod
    def shutdown(self):
        """Cleanup resources"""
        pass

    def evaluate_event(self, event_data):
        """Evaluate event against rules"""
        matches = self.rule_engine.evaluate(event_data)
        if matches:
            threat = self.create_threat(event_data, matches)
            self.transport.send(threat)

    def create_threat(self, event, rules):
        """Create standardized threat object"""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'sensor_id': self.config.sensor_id,
            'source': self.__class__.__name__,
            'threat_type': rules[0].threat_type,
            'threat_score': self.calculate_score(rules),
            'risk_level': self.get_risk_level(score),
            'threats_detected': [r.name for r in rules],
            'raw_data': event,
            'metadata': self.get_metadata()
        }
```

#### USB Detector

**File:** `detectors/usb_detector.py`

**Capabilities:**
- Real-time USB device enumeration (via pyudev)
- File hash calculation (SHA256, MD5)
- Malware hash database lookup (360+ signatures)
- BadUSB signature detection
- HID injection pattern recognition
- Filesystem scanning on mount
- Device behavior profiling

**Rules Applied:**
- `rules/usb/malware_signatures.yaml`
- `rules/usb/badusb_patterns.yaml`
- `rules/usb/device_behavior.yaml`

#### WiFi Detector

**File:** `detectors/wifi_detector.py`

**Capabilities:**
- Monitor mode packet capture (via scapy)
- Beacon frame analysis
- Evil twin AP detection (SSID correlation)
- Deauthentication attack detection
- Beacon flood identification
- Channel hopping detection
- Signal strength anomaly analysis
- Encryption downgrade detection

**Rules Applied:**
- `rules/wifi/evil_twin_detection.yaml`
- `rules/wifi/deauth_patterns.yaml`
- `rules/wifi/beacon_flooding.yaml`
- `rules/wifi/suspicious_ssids.yaml`

#### BLE Detector

**File:** `detectors/ble_detector.py`

**Capabilities:**
- BLE advertisement scanning (via bleak)
- Flipper Zero fingerprinting
- Device name pattern matching
- Service UUID spoofing detection
- Manufacturer data analysis
- MAC randomization abuse detection
- RSSI-based proximity analysis
- Rapid appearance/disappearance patterns

**Rules Applied:**
- `rules/ble/flipper_zero.yaml`
- `rules/ble/ble_spam.yaml`
- `rules/ble/device_spoofing.yaml`

#### AirDrop Detector

**File:** `detectors/airdrop_detector.py`

**Capabilities:**
- mDNS/Avahi service scanning
- AirDrop service identification
- Suspicious device name detection
- TXT record analysis
- Service announcement patterns
- Evil twin AirDrop detection

**Rules Applied:**
- `rules/airdrop/suspicious_services.yaml`
- `rules/airdrop/device_patterns.yaml`

#### Network Detector

**File:** `detectors/network_detector.py`

**Capabilities:**
- OpenCanary Docker integration
- Honeypot event parsing
- Multi-service monitoring (SSH, FTP, SMB, HTTP, etc.)
- Credential harvest detection
- Port scan identification
- Brute force pattern recognition

**Rules Applied:**
- `rules/network/port_scan_detection.yaml`
- `rules/network/brute_force.yaml`
- `rules/network/credential_harvesting.yaml`

---

### 3. Rule Engine Architecture

#### Rule Format (YAML)

```yaml
# rules/usb/malware_stuxnet.yaml
rule_id: usb_malware_001
name: "Stuxnet USB Worm Detection"
version: 2.1
enabled: true
severity: critical
threat_type: malware
category: usb_worm

# Condition evaluation logic
conditions:
  operator: OR  # AND, OR, NOT
  clauses:
    - type: file_hash_match
      field: sha256
      operator: in
      values:
        - "9c5e8a8e8f4e3c5d7b2a1f6e9d8c7b6a5e4d3c2b1a0f9e8d7c6b5a4e3d2c1b0"
        - "7a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4"

    - type: device_vendor
      field: vid
      operator: equals
      value: "0x1234"

    - type: file_pattern
      field: filename
      operator: regex
      pattern: "^(autorun\\.inf|~WTR.*\\.tmp)$"

# Actions to take when rule matches
actions:
  - type: log_threat
    severity: critical

  - type: alert_dashboard
    priority: high

  - type: local_action
    command: quarantine_device
    params:
      isolation: true

# Metadata for threat intelligence
metadata:
  mitre_attack:
    - T1091  # Replication Through Removable Media
    - T1092  # Communication Through Removable Media
  cve:
    - CVE-2010-2568
  references:
    - https://attack.mitre.org/techniques/T1091/
    - https://www.kaspersky.com/resource-center/threats/stuxnet
  tags:
    - worm
    - industrial_control
    - scada

# Tuning parameters
tuning:
  false_positive_weight: 0.1
  confidence_threshold: 0.85
  max_alerts_per_hour: 5
```

#### Rule Engine Implementation

```python
# rules/rule_engine.py

class RuleEngine:
    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self.rules = {}
        self.evaluators = {
            'file_hash_match': HashEvaluator(),
            'device_vendor': DeviceEvaluator(),
            'file_pattern': PatternEvaluator(),
            'network_pattern': NetworkEvaluator(),
            'behavioral': BehavioralEvaluator()
        }
        self.load_rules()

    def load_rules(self):
        """Load all YAML rules from directory"""
        for root, dirs, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith('.yaml') or file.endswith('.yml'):
                    rule_path = os.path.join(root, file)
                    rule = self.parse_rule(rule_path)
                    if rule and rule.get('enabled', True):
                        self.rules[rule['rule_id']] = rule

        logger.info(f"Loaded {len(self.rules)} detection rules")

    def evaluate(self, event_data: dict, rule_set: str = 'all') -> List[Rule]:
        """Evaluate event against active rules"""
        matches = []

        # Filter rules by category if specified
        active_rules = self._get_active_rules(rule_set)

        for rule_id, rule in active_rules.items():
            if self._evaluate_rule(event_data, rule):
                matches.append(rule)

        return matches

    def _evaluate_rule(self, data: dict, rule: dict) -> bool:
        """Evaluate single rule against data"""
        conditions = rule.get('conditions', {})
        operator = conditions.get('operator', 'AND')
        clauses = conditions.get('clauses', [])

        results = []
        for clause in clauses:
            evaluator = self.evaluators.get(clause['type'])
            if evaluator:
                result = evaluator.evaluate(data, clause)
                results.append(result)

        # Apply boolean logic
        if operator == 'AND':
            return all(results)
        elif operator == 'OR':
            return any(results)
        elif operator == 'NOT':
            return not any(results)

        return False

    def reload_rules(self):
        """Hot-reload rules without restart"""
        self.rules.clear()
        self.load_rules()
        logger.info("Rules reloaded successfully")
```

---

### 4. Transport Layer

#### Protocol Handler

```python
# transport/protocol_handler.py

class ProtocolHandler:
    def __init__(self, config: dict):
        self.config = config
        self.primary_protocol = config.get('protocol', 'mqtt')
        self.fallback_protocol = config.get('fallback', 'http')

        self.clients = {
            'mqtt': MQTTClient(config.get('mqtt', {})),
            'http': HTTPClient(config.get('http', {})),
            'websocket': WebSocketClient(config.get('websocket', {}))
        }

        self.active_client = self.clients[self.primary_protocol]
        self.queue = deque(maxlen=10000)  # Offline queue

    def send(self, data: dict) -> bool:
        """Send data with automatic fallback"""
        try:
            success = self.active_client.send(data)
            if success:
                self._flush_queue()
                return True
        except Exception as e:
            logger.error(f"Primary protocol failed: {e}")
            return self._try_fallback(data)

    def _try_fallback(self, data: dict) -> bool:
        """Attempt fallback protocol"""
        try:
            fallback = self.clients[self.fallback_protocol]
            success = fallback.send(data)
            if success:
                logger.warning(f"Using fallback protocol: {self.fallback_protocol}")
                return True
        except Exception as e:
            logger.error(f"Fallback protocol failed: {e}")

        # Queue for later
        self.queue.append(data)
        logger.info(f"Data queued for retry ({len(self.queue)} items)")
        return False
```

#### MQTT Client (Primary)

```python
# transport/mqtt_client.py

class MQTTClient:
    def __init__(self, config: dict):
        self.broker = config.get('broker', 'mqtt.honeyman.com')
        self.port = config.get('port', 8883)
        self.username = config.get('username')
        self.password = config.get('password')
        self.use_tls = config.get('use_tls', True)
        self.qos = config.get('qos', 1)

        self.client = mqtt.Client()
        self.client.username_pw_set(self.username, self.password)

        if self.use_tls:
            self.client.tls_set()

        self.connected = False
        self.connect()

    def connect(self):
        """Establish MQTT connection"""
        try:
            self.client.connect(self.broker, self.port, keepalive=60)
            self.client.loop_start()
            self.connected = True
            logger.info(f"Connected to MQTT broker: {self.broker}:{self.port}")
        except Exception as e:
            logger.error(f"MQTT connection failed: {e}")
            self.connected = False

    def send(self, data: dict) -> bool:
        """Publish threat data to MQTT"""
        if not self.connected:
            self.connect()

        if not self.connected:
            return False

        try:
            topic = f"honeyman/sensors/{data['sensor_id']}/threats"
            payload = json.dumps(data)

            result = self.client.publish(topic, payload, qos=self.qos)
            result.wait_for_publish(timeout=5)

            return result.is_published()
        except Exception as e:
            logger.error(f"MQTT publish failed: {e}")
            return False
```

#### Topic Structure

```
honeyman/
├── sensors/
│   ├── {sensor_id}/
│   │   ├── threats          # Threat events
│   │   ├── heartbeat        # Health status (every 60s)
│   │   ├── metrics          # Performance metrics
│   │   └── status           # Sensor status updates
│   │
├── dashboard/
│   ├── commands/{sensor_id} # Remote commands
│   ├── updates/{sensor_id}  # Software/rule updates
│   └── config/{sensor_id}   # Configuration updates
│
├── analytics/
│   ├── aggregated           # Pre-processed analytics
│   └── correlations         # Threat correlations
│
└── system/
    ├── health               # Platform health
    └── alerts               # System alerts
```

---

## Dashboard Architecture

### Technology Stack

**Frontend:**
- React 18 (UI framework)
- TypeScript (type safety)
- Material-UI v5 (design system)
- Leaflet.js (maps)
- Recharts (visualizations)
- Socket.IO client (real-time)
- React Query (data fetching)
- Zustand (state management)

**Backend:**
- Node.js 18+
- Express.js (REST API)
- Socket.IO (WebSocket)
- PostgreSQL 15 (primary storage)
- TimescaleDB 2.11+ (time-series extension)
- Redis 7 (caching, real-time data)
- Mosquitto (MQTT broker)
- Nginx (reverse proxy)

### Component Architecture

```
dashboard-v2/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── common/
│   │   │   │   ├── Header.tsx
│   │   │   │   ├── Sidebar.tsx
│   │   │   │   └── LoadingSpinner.tsx
│   │   │   ├── maps/
│   │   │   │   ├── ThreatMap.tsx
│   │   │   │   ├── HeatMap.tsx
│   │   │   │   └── ThreatMarker.tsx
│   │   │   ├── sensors/
│   │   │   │   ├── SensorGrid.tsx
│   │   │   │   ├── SensorCard.tsx
│   │   │   │   └── SensorDetails.tsx
│   │   │   ├── threats/
│   │   │   │   ├── ThreatList.tsx
│   │   │   │   ├── ThreatDetails.tsx
│   │   │   │   └── ThreatFilter.tsx
│   │   │   ├── analytics/
│   │   │   │   ├── ThreatChart.tsx
│   │   │   │   ├── VelocityChart.tsx
│   │   │   │   └── CorrelationGraph.tsx
│   │   │   └── rules/
│   │   │       ├── RuleEditor.tsx
│   │   │       ├── RuleList.tsx
│   │   │       └── RuleTester.tsx
│   │   │
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Sensors.tsx
│   │   │   ├── Threats.tsx
│   │   │   ├── Analytics.tsx
│   │   │   ├── Rules.tsx
│   │   │   ├── Alerts.tsx
│   │   │   └── Settings.tsx
│   │   │
│   │   ├── hooks/
│   │   │   ├── useWebSocket.ts
│   │   │   ├── useSensors.ts
│   │   │   ├── useThreats.ts
│   │   │   └── useAnalytics.ts
│   │   │
│   │   ├── services/
│   │   │   ├── api.ts
│   │   │   ├── websocket.ts
│   │   │   └── geolocation.ts
│   │   │
│   │   ├── store/
│   │   │   ├── sensorsStore.ts
│   │   │   ├── threatsStore.ts
│   │   │   └── uiStore.ts
│   │   │
│   │   └── utils/
│   │       ├── formatters.ts
│   │       ├── validators.ts
│   │       └── constants.ts
│   │
│   └── package.json
│
└── backend/
    ├── api/
    │   ├── server.js
    │   ├── routes/
    │   │   ├── sensors.js
    │   │   ├── threats.js
    │   │   ├── rules.js
    │   │   ├── analytics.js
    │   │   ├── alerts.js
    │   │   └── onboarding.js
    │   │
    │   ├── middleware/
    │   │   ├── auth.js
    │   │   ├── rateLimit.js
    │   │   └── validation.js
    │   │
    │   └── controllers/
    │       ├── sensorsController.js
    │       ├── threatsController.js
    │       └── rulesController.js
    │
    ├── database/
    │   ├── migrations/
    │   ├── models/
    │   │   ├── Sensor.js
    │   │   ├── Threat.js
    │   │   └── Rule.js
    │   └── queries/
    │       ├── sensorQueries.js
    │       ├── threatQueries.js
    │       └── analyticsQueries.js
    │
    ├── services/
    │   ├── mqttHandler.js
    │   ├── geolocationService.js
    │   ├── ruleSyncService.js
    │   ├── analyticsService.js
    │   └── alertingService.js
    │
    └── utils/
        ├── logger.js
        ├── crypto.js
        └── validators.js
```

---

## Database Schema

### PostgreSQL + TimescaleDB Schema

```sql
-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS postgis;

-- Sensors table
CREATE TABLE sensors (
    sensor_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    platform VARCHAR(100) NOT NULL,  -- rpi5, rpi4, linux, android

    -- Capabilities
    capabilities JSONB NOT NULL DEFAULT '{
        "wifi": false,
        "bluetooth": false,
        "usb": false,
        "network": false,
        "airdrop": false
    }',

    -- Location data
    location GEOGRAPHY(POINT, 4326),  -- PostGIS geography
    city VARCHAR(100),
    region VARCHAR(100),
    country VARCHAR(2),
    timezone VARCHAR(50),

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'offline',  -- online, offline, error
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat TIMESTAMPTZ,
    last_threat TIMESTAMPTZ,

    -- Configuration
    config JSONB,

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Indexes
    CONSTRAINT valid_status CHECK (status IN ('online', 'offline', 'error', 'maintenance'))
);

-- Indexes for sensors
CREATE INDEX idx_sensors_status ON sensors(status);
CREATE INDEX idx_sensors_location ON sensors USING GIST(location);
CREATE INDEX idx_sensors_last_heartbeat ON sensors(last_heartbeat DESC);

-- Threats table (Hypertable for time-series optimization)
CREATE TABLE threats (
    threat_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sensor_id UUID NOT NULL REFERENCES sensors(sensor_id) ON DELETE CASCADE,

    -- Temporal
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Threat classification
    source VARCHAR(100) NOT NULL,  -- usb_detector, wifi_detector, etc.
    threat_type VARCHAR(100) NOT NULL,  -- malware, evil_twin, flipper_zero, etc.
    detection_type VARCHAR(100),

    -- Severity
    threat_score FLOAT NOT NULL CHECK (threat_score >= 0 AND threat_score <= 1),
    risk_level VARCHAR(50) NOT NULL,  -- critical, high, medium, low, info

    -- Details
    threats_detected TEXT[],
    message TEXT,

    -- Source information
    src_host INET,
    src_port INTEGER,
    dst_host INET,
    dst_port INTEGER,

    -- Network/device info
    network_info JSONB,
    device_info JSONB,

    -- Geolocation (can differ from sensor location for network threats)
    geolocation GEOGRAPHY(POINT, 4326),
    city VARCHAR(100),
    country VARCHAR(2),

    -- Raw data
    raw_data JSONB,

    -- Metadata
    processed BOOLEAN DEFAULT false,
    false_positive BOOLEAN DEFAULT false,

    CONSTRAINT valid_risk_level CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'info'))
);

-- Convert to TimescaleDB hypertable
SELECT create_hypertable('threats', 'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- Indexes for threats
CREATE INDEX idx_threats_sensor_time ON threats(sensor_id, timestamp DESC);
CREATE INDEX idx_threats_type ON threats(threat_type);
CREATE INDEX idx_threats_score ON threats(threat_score DESC);
CREATE INDEX idx_threats_risk ON threats(risk_level, timestamp DESC);
CREATE INDEX idx_threats_source ON threats(source);
CREATE INDEX idx_threats_location ON threats USING GIST(geolocation);
CREATE INDEX idx_threats_src_host ON threats(src_host) WHERE src_host IS NOT NULL;

-- Rules table
CREATE TABLE rules (
    rule_id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(20) NOT NULL,

    -- Classification
    category VARCHAR(100) NOT NULL,  -- usb, wifi, ble, network, airdrop
    threat_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,

    -- Rule content
    rule_yaml TEXT NOT NULL,

    -- Status
    enabled BOOLEAN DEFAULT true,

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(100),

    -- Performance
    match_count INTEGER DEFAULT 0,
    false_positive_count INTEGER DEFAULT 0,

    CONSTRAINT valid_severity CHECK (severity IN ('critical', 'high', medium', 'low', 'info'))
);

-- Indexes for rules
CREATE INDEX idx_rules_category ON rules(category);
CREATE INDEX idx_rules_enabled ON rules(enabled) WHERE enabled = true;
CREATE INDEX idx_rules_severity ON rules(severity);

-- Sensor heartbeats (Hypertable)
CREATE TABLE sensor_heartbeats (
    heartbeat_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sensor_id UUID NOT NULL REFERENCES sensors(sensor_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- System metrics
    cpu_percent FLOAT,
    memory_percent FLOAT,
    disk_percent FLOAT,

    -- Detector status
    detectors_active JSONB,

    -- Network
    network_latency_ms FLOAT,

    -- Raw metrics
    metrics JSONB
);

SELECT create_hypertable('sensor_heartbeats', 'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

CREATE INDEX idx_heartbeats_sensor_time ON sensor_heartbeats(sensor_id, timestamp DESC);

-- Threat correlations
CREATE TABLE threat_correlations (
    correlation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Related threats
    threat_ids UUID[] NOT NULL,

    -- Pattern
    pattern_type VARCHAR(100) NOT NULL,  -- temporal, spatial, behavioral, cross-protocol
    pattern_description TEXT,

    -- Confidence
    confidence_score FLOAT NOT NULL CHECK (confidence_score >= 0 AND confidence_score <= 1),

    -- Temporal
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,

    -- Statistics
    threat_count INTEGER NOT NULL,

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_correlations_pattern ON threat_correlations(pattern_type);
CREATE INDEX idx_correlations_confidence ON threat_correlations(confidence_score DESC);

-- Analytics cache (for expensive queries)
CREATE TABLE analytics_cache (
    cache_key VARCHAR(255) PRIMARY KEY,
    data JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_analytics_cache_expires ON analytics_cache(expires_at);

-- Alert configurations
CREATE TABLE alert_configs (
    config_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT true,

    -- Trigger conditions
    conditions JSONB NOT NULL,

    -- Alert channels
    channels JSONB NOT NULL,  -- email, slack, webhook, etc.

    -- Rate limiting
    rate_limit_minutes INTEGER DEFAULT 60,
    last_triggered TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Alert history
CREATE TABLE alert_history (
    alert_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID REFERENCES alert_configs(config_id) ON DELETE CASCADE,
    threat_id UUID REFERENCES threats(threat_id) ON DELETE SET NULL,

    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    channel VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,  -- sent, failed, rate_limited

    error_message TEXT
);

CREATE INDEX idx_alert_history_config ON alert_history(config_id, timestamp DESC);
CREATE INDEX idx_alert_history_threat ON alert_history(threat_id);

-- Users (for dashboard authentication)
CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,

    role VARCHAR(50) NOT NULL DEFAULT 'viewer',  -- admin, analyst, viewer

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login TIMESTAMPTZ,

    CONSTRAINT valid_role CHECK (role IN ('admin', 'analyst', 'viewer'))
);

-- API keys
CREATE TABLE api_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,

    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    sensor_id UUID REFERENCES sensors(sensor_id) ON DELETE CASCADE,

    permissions JSONB NOT NULL DEFAULT '["read"]',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used TIMESTAMPTZ,

    revoked BOOLEAN DEFAULT false
);

CREATE INDEX idx_api_keys_hash ON api_keys(key_hash) WHERE revoked = false;
```

### Data Retention Policy

```sql
-- Automatic data retention (TimescaleDB)
-- Keep detailed threat data for 90 days
SELECT add_retention_policy('threats', INTERVAL '90 days');

-- Keep heartbeat data for 30 days
SELECT add_retention_policy('sensor_heartbeats', INTERVAL '30 days');

-- Continuous aggregates (pre-compute common queries)

-- Hourly threat summary
CREATE MATERIALIZED VIEW threats_hourly WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', timestamp) AS bucket,
    sensor_id,
    source,
    threat_type,
    COUNT(*) AS threat_count,
    AVG(threat_score) AS avg_threat_score,
    MAX(threat_score) AS max_threat_score,
    array_agg(DISTINCT risk_level) AS risk_levels
FROM threats
GROUP BY bucket, sensor_id, source, threat_type
WITH NO DATA;

-- Refresh policy (update every hour)
SELECT add_continuous_aggregate_policy('threats_hourly',
    start_offset => INTERVAL '3 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour'
);

-- Daily threat summary
CREATE MATERIALIZED VIEW threats_daily WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', timestamp) AS bucket,
    sensor_id,
    COUNT(*) AS total_threats,
    COUNT(DISTINCT threat_type) AS unique_threat_types,
    AVG(threat_score) AS avg_threat_score,
    COUNT(*) FILTER (WHERE risk_level = 'critical') AS critical_count,
    COUNT(*) FILTER (WHERE risk_level = 'high') AS high_count,
    COUNT(*) FILTER (WHERE risk_level = 'medium') AS medium_count,
    COUNT(*) FILTER (WHERE risk_level = 'low') AS low_count
FROM threats
GROUP BY bucket, sensor_id
WITH NO DATA;

SELECT add_continuous_aggregate_policy('threats_daily',
    start_offset => INTERVAL '7 days',
    end_offset => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 day'
);
```

---

## Data Flow

### 1. Threat Detection Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    DETECTION FLOW                                │
└─────────────────────────────────────────────────────────────────┘

1. Event Occurs
   ↓
2. Detector Captures Event
   (USB insertion, WiFi beacon, BLE advertisement, etc.)
   ↓
3. Rule Engine Evaluation
   ├─ Load applicable rules for detector
   ├─ Evaluate conditions against event data
   ├─ Calculate threat score
   └─ Determine risk level
   ↓
4. Threat Creation
   ├─ Standardize threat format
   ├─ Add metadata (sensor_id, timestamp, etc.)
   ├─ Include raw event data
   └─ Generate unique threat_id
   ↓
5. Transport Selection
   ├─ Try primary protocol (MQTT)
   ├─ Fallback to HTTP if MQTT fails
   └─ Queue locally if all protocols fail
   ↓
6. Send to Dashboard
   ├─ MQTT: Publish to sensors/{id}/threats
   └─ HTTP: POST to /api/v2/honeypot/data
   ↓
7. Dashboard Ingestion
   ├─ MQTT broker receives message
   ├─ Backend subscribes to topic
   └─ HTTP endpoint receives POST
   ↓
8. Processing Pipeline
   ├─ Validate threat data
   ├─ Enrich with geolocation (if IP available)
   ├─ Check for correlations with recent threats
   └─ Store in PostgreSQL
   ↓
9. Real-time Distribution
   ├─ Update Redis cache
   ├─ WebSocket broadcast to connected clients
   └─ Trigger alert rules (if configured)
   ↓
10. Client Display
    ├─ Update threat map
    ├─ Add to threat list
    ├─ Update statistics
    └─ Show notification (if critical)
```

### 2. Sensor Onboarding Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                  ONBOARDING FLOW                                 │
└─────────────────────────────────────────────────────────────────┘

1. User: Dashboard → "Add Sensor"
   ↓
2. Dashboard: Generate onboarding token
   ├─ Create unique token (JWT)
   ├─ Encode sensor name, permissions
   ├─ Set expiration (1 hour)
   └─ Display QR code + command
   ↓
3. User: Copy command to RPI5
   curl -sSL get.honeyman.sh | sudo bash -s -- <TOKEN>
   ↓
4. Installer Script Execution
   ├─ Validate token with dashboard API
   ├─ Detect platform (RPI5)
   ├─ Detect capabilities (WiFi, BLE, USB, etc.)
   └─ Send capability report to dashboard
   ↓
5. Dashboard: Generate sensor config
   ├─ Create sensor_id (UUID)
   ├─ Generate API key
   ├─ Create MQTT credentials
   ├─ Select detection rules based on capabilities
   └─ Return config package
   ↓
6. Installer: Download & Configure
   ├─ Download agent package
   ├─ Install dependencies
   ├─ Download detection rules
   ├─ Deploy OpenCanary stack
   ├─ Create systemd service
   └─ Start agent
   ↓
7. Agent: Initial Connection
   ├─ Connect to MQTT broker
   ├─ Send registration message
   ├─ Send first heartbeat
   └─ Begin detection
   ↓
8. Dashboard: Sensor Online
   ├─ Update sensor status = 'online'
   ├─ Display on sensors page
   ├─ WebSocket broadcast: new sensor
   └─ Ready to receive threats
```

### 3. Rule Update Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                   RULE UPDATE FLOW                               │
└─────────────────────────────────────────────────────────────────┘

1. Admin: Dashboard → Rules → Edit Rule
   ↓
2. Dashboard: Rule Editor
   ├─ Load rule YAML
   ├─ Validate syntax
   ├─ Test against sample data
   └─ Save to database
   ↓
3. Rule Sync Service (runs every 5 minutes)
   ├─ Check for rule updates (version comparison)
   ├─ Package updated rules
   └─ Publish to MQTT: dashboard/updates/{sensor_id}
   ↓
4. Agent: Receive Update
   ├─ Subscribe to dashboard/updates/{sensor_id}
   ├─ Download new rule package
   ├─ Validate rule syntax
   └─ Backup current rules
   ↓
5. Agent: Apply Update
   ├─ Stop affected detectors
   ├─ Replace rule files
   ├─ Reload rule engine
   ├─ Restart detectors
   └─ Confirm update via MQTT
   ↓
6. Dashboard: Update Confirmation
   ├─ Mark sensor as updated
   └─ Display update status
```

---

## Security Architecture

### 1. Authentication & Authorization

#### API Key Authentication

```javascript
// middleware/auth.js

const authenticateApiKey = async (req, res, next) => {
    const apiKey = req.header('X-API-Key') ||
                   req.header('Authorization')?.replace('Bearer ', '');

    if (!apiKey) {
        return res.status(401).json({ error: 'API key required' });
    }

    // Hash the provided key
    const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

    // Look up in database
    const key = await db.query(
        'SELECT * FROM api_keys WHERE key_hash = $1 AND revoked = false',
        [keyHash]
    );

    if (!key.rows[0]) {
        return res.status(401).json({ error: 'Invalid API key' });
    }

    // Check expiration
    if (key.rows[0].expires_at && new Date() > new Date(key.rows[0].expires_at)) {
        return res.status(401).json({ error: 'API key expired' });
    }

    // Update last_used
    await db.query(
        'UPDATE api_keys SET last_used = NOW() WHERE key_id = $1',
        [key.rows[0].key_id]
    );

    // Attach to request
    req.apiKey = key.rows[0];
    req.sensorId = key.rows[0].sensor_id;

    next();
};
```

#### Role-Based Access Control (RBAC)

```javascript
const roles = {
    admin: ['read', 'write', 'delete', 'manage_users', 'manage_sensors'],
    analyst: ['read', 'write', 'manage_rules'],
    viewer: ['read']
};

const requirePermission = (permission) => {
    return (req, res, next) => {
        const userRole = req.user.role;
        const permissions = roles[userRole] || [];

        if (!permissions.includes(permission)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }

        next();
    };
};

// Usage
app.delete('/api/v2/sensors/:id',
    authenticateUser,
    requirePermission('delete'),
    deleteSensor
);
```

### 2. Transport Security

#### TLS Configuration (MQTT)

```conf
# mosquitto.conf

# TLS/SSL
listener 8883
cafile /etc/mosquitto/ca_certificates/ca.crt
certfile /etc/mosquitto/certs/server.crt
keyfile /etc/mosquitto/certs/server.key
require_certificate false
use_identity_as_username false

# TLS version
tls_version tlsv1.3

# Authentication
allow_anonymous false
password_file /etc/mosquitto/passwd

# ACL
acl_file /etc/mosquitto/acl.conf
```

#### ACL Configuration

```conf
# /etc/mosquitto/acl.conf

# Sensors can only publish to their own topics
pattern read honeyman/sensors/%u/#
pattern write honeyman/sensors/%u/#

# Sensors can subscribe to dashboard commands
pattern read honeyman/dashboard/commands/%u
pattern read honeyman/dashboard/updates/%u

# Dashboard user has full access
user dashboard_admin
topic readwrite honeyman/#
```

### 3. Data Encryption

#### At Rest

- PostgreSQL: Transparent Data Encryption (TDE)
- Filesystem: LUKS encryption for sensitive directories
- Secrets: Encrypted using AES-256-GCM

#### In Transit

- All HTTP: TLS 1.3
- MQTT: TLS 1.3
- WebSocket: WSS (WebSocket Secure)

### 4. Input Validation

```javascript
// middleware/validation.js

const { body, param, query, validationResult } = require('express-validator');

const validateThreatSubmission = [
    body('type').isIn(['threats', 'status']),
    body('honeypot_id').optional().isUUID(),
    body('data').isArray().notEmpty(),
    body('data.*.timestamp').isISO8601(),
    body('data.*.threat_score').isFloat({ min: 0, max: 1 }),
    body('data.*.risk_level').isIn(['critical', 'high', 'medium', 'low', 'info']),

    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    }
];

app.post('/api/v2/honeypot/data',
    authenticateApiKey,
    validateThreatSubmission,
    receiveThreatData
);
```

### 5. Rate Limiting

```javascript
// middleware/rateLimit.js

const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('redis');

const redisClient = redis.createClient({
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT
});

// General API rate limiting
const generalLimiter = rateLimit({
    store: new RedisStore({
        client: redisClient,
        prefix: 'rl:general:'
    }),
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000, // 1000 requests per window
    message: 'Too many requests, please try again later'
});

// Stricter limit for threat submission
const threatLimiter = rateLimit({
    store: new RedisStore({
        client: redisClient,
        prefix: 'rl:threats:'
    }),
    windowMs: 60 * 1000, // 1 minute
    max: 60, // 60 requests per minute per sensor
    keyGenerator: (req) => req.sensorId, // Rate limit per sensor
    message: 'Threat submission rate limit exceeded'
});

app.use('/api/v2/', generalLimiter);
app.post('/api/v2/honeypot/data', threatLimiter, receiveThreatData);
```

---

## API Specification

### Base URL
```
Production: https://api.honeyman.com/v2
Development: http://localhost:3000/v2
```

### Authentication
All requests require an API key in the header:
```
X-API-Key: <your-api-key>
```
or
```
Authorization: Bearer <your-api-key>
```

### Endpoints

#### 1. Sensor Management

**List Sensors**
```http
GET /api/v2/sensors
Query Parameters:
  - status: string (online|offline|error)
  - limit: integer (default: 50)
  - offset: integer (default: 0)

Response 200:
{
  "sensors": [
    {
      "sensor_id": "uuid",
      "name": "RPI5-LasVegas",
      "platform": "rpi5",
      "capabilities": { "wifi": true, "ble": true, ... },
      "status": "online",
      "location": { "lat": 36.1699, "lon": -115.1398, "city": "Las Vegas" },
      "last_heartbeat": "2025-10-23T12:34:56Z",
      "threat_count_24h": 145
    }
  ],
  "total": 42,
  "limit": 50,
  "offset": 0
}
```

**Get Sensor Details**
```http
GET /api/v2/sensors/:sensor_id

Response 200:
{
  "sensor_id": "uuid",
  "name": "RPI5-LasVegas",
  "platform": "rpi5",
  "capabilities": { ... },
  "location": { ... },
  "status": "online",
  "first_seen": "2025-10-01T10:00:00Z",
  "last_heartbeat": "2025-10-23T12:34:56Z",
  "config": { ... },
  "stats": {
    "total_threats": 1234,
    "threats_24h": 145,
    "avg_threat_score": 0.65,
    "uptime_percent": 98.5
  }
}
```

**Update Sensor**
```http
PATCH /api/v2/sensors/:sensor_id
Body:
{
  "name": "New Name",
  "location": { "lat": 36.1699, "lon": -115.1398 },
  "config": { ... }
}

Response 200:
{
  "success": true,
  "sensor": { ... }
}
```

**Delete Sensor**
```http
DELETE /api/v2/sensors/:sensor_id

Response 200:
{
  "success": true,
  "message": "Sensor deleted successfully"
}
```

#### 2. Threat Management

**List Threats**
```http
GET /api/v2/threats
Query Parameters:
  - sensor_id: uuid
  - start_time: ISO8601 timestamp
  - end_time: ISO8601 timestamp
  - threat_type: string
  - risk_level: string (critical|high|medium|low|info)
  - min_score: float (0-1)
  - limit: integer (default: 100)
  - offset: integer (default: 0)

Response 200:
{
  "threats": [
    {
      "threat_id": "uuid",
      "sensor_id": "uuid",
      "timestamp": "2025-10-23T12:34:56Z",
      "source": "usb_detector",
      "threat_type": "malware",
      "threat_score": 0.95,
      "risk_level": "critical",
      "threats_detected": ["Stuxnet"],
      "message": "USB worm detected",
      "geolocation": { "lat": 36.1699, "lon": -115.1398 }
    }
  ],
  "total": 5432,
  "limit": 100,
  "offset": 0
}
```

**Get Threat Details**
```http
GET /api/v2/threats/:threat_id

Response 200:
{
  "threat_id": "uuid",
  "sensor_id": "uuid",
  "sensor_name": "RPI5-LasVegas",
  "timestamp": "2025-10-23T12:34:56Z",
  "source": "usb_detector",
  "threat_type": "malware",
  "detection_type": "hash_match",
  "threat_score": 0.95,
  "risk_level": "critical",
  "threats_detected": ["Stuxnet", "USB Worm"],
  "message": "Known USB worm detected via hash match",
  "network_info": { ... },
  "device_info": { ... },
  "geolocation": { ... },
  "raw_data": { ... },
  "related_threats": [ ... ],
  "timeline_context": [ ... ]
}
```

**Submit Threats (Sensor → Dashboard)**
```http
POST /api/v2/honeypot/data
Headers:
  X-API-Key: sensor-api-key

Body:
{
  "type": "threats",
  "honeypot_id": "sensor-uuid",
  "compressed": false,
  "data": [
    {
      "timestamp": "2025-10-23T12:34:56Z",
      "source": "usb_detector",
      "threat_type": "malware",
      "threat_score": 0.95,
      "risk_level": "critical",
      "threats_detected": ["Stuxnet"],
      "message": "USB worm detected",
      "device_info": { ... },
      "raw_data": { ... }
    }
  ]
}

Response 200:
{
  "success": true,
  "message": "threats data processed successfully",
  "count": 1
}
```

#### 3. Analytics

**Get Threat Statistics**
```http
GET /api/v2/analytics/stats
Query Parameters:
  - time_range: string (24h|7d|30d|90d|all)
  - sensor_id: uuid (optional)

Response 200:
{
  "time_range": "24h",
  "total_threats": 1234,
  "critical": 45,
  "high": 123,
  "medium": 567,
  "low": 499,
  "by_type": {
    "malware": 45,
    "evil_twin": 234,
    "flipper_zero": 12,
    ...
  },
  "by_source": {
    "usb_detector": 145,
    "wifi_detector": 789,
    ...
  },
  "threat_velocity": 51.4,  // threats per hour
  "unique_sources": 23,
  "hourly_breakdown": { ... }
}
```

**Get Threat Correlations**
```http
GET /api/v2/analytics/correlations
Query Parameters:
  - window_hours: integer (default: 24)
  - min_confidence: float (0-1, default: 0.7)

Response 200:
{
  "time_window_hours": 24,
  "total_threats_analyzed": 1234,
  "correlations": [
    {
      "pattern": "wifi_detector-evil_twin",
      "frequency": 45,
      "average_severity": 0.75,
      "confidence": 0.85,
      "first_seen": "2025-10-23T10:00:00Z",
      "last_seen": "2025-10-23T12:30:00Z"
    }
  ],
  "generated_at": "2025-10-23T12:34:56Z"
}
```

**Geographic Distribution**
```http
GET /api/v2/analytics/geography
Query Parameters:
  - time_range: string (24h|7d|30d)

Response 200:
{
  "threat_locations": [
    {
      "country": "US",
      "city": "Las Vegas",
      "lat": 36.1699,
      "lon": -115.1398,
      "threat_count": 234,
      "avg_threat_score": 0.65,
      "risk_distribution": {
        "critical": 12,
        "high": 45,
        "medium": 123,
        "low": 54
      }
    }
  ]
}
```

#### 4. Rule Management

**List Rules**
```http
GET /api/v2/rules
Query Parameters:
  - category: string (usb|wifi|ble|network|airdrop)
  - enabled: boolean
  - severity: string

Response 200:
{
  "rules": [
    {
      "rule_id": "usb_malware_001",
      "name": "Stuxnet USB Worm Detection",
      "version": "2.1",
      "category": "usb",
      "threat_type": "malware",
      "severity": "critical",
      "enabled": true,
      "match_count": 12,
      "false_positive_count": 0,
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": "2025-10-15T10:00:00Z"
    }
  ],
  "total": 127
}
```

**Get Rule**
```http
GET /api/v2/rules/:rule_id

Response 200:
{
  "rule_id": "usb_malware_001",
  "name": "Stuxnet USB Worm Detection",
  "version": "2.1",
  "category": "usb",
  "threat_type": "malware",
  "severity": "critical",
  "enabled": true,
  "rule_yaml": "...",  // Full YAML content
  "match_count": 12,
  "false_positive_count": 0,
  "performance_metrics": { ... },
  "created_at": "2025-01-01T00:00:00Z",
  "updated_at": "2025-10-15T10:00:00Z"
}
```

**Create/Update Rule**
```http
POST /api/v2/rules
Body:
{
  "rule_id": "custom_rule_001",
  "name": "Custom Threat Detection",
  "version": "1.0",
  "category": "usb",
  "threat_type": "custom",
  "severity": "high",
  "enabled": true,
  "rule_yaml": "..."  // YAML content
}

Response 200:
{
  "success": true,
  "rule": { ... }
}
```

**Delete Rule**
```http
DELETE /api/v2/rules/:rule_id

Response 200:
{
  "success": true,
  "message": "Rule deleted successfully"
}
```

#### 5. Onboarding

**Generate Onboarding Token**
```http
POST /api/v2/onboarding/token
Body:
{
  "sensor_name": "RPI5-DefCon",
  "expires_in_hours": 1
}

Response 200:
{
  "token": "eyJhbGc...",
  "expires_at": "2025-10-23T13:34:56Z",
  "install_command": "curl -sSL get.honeyman.sh | sudo bash -s -- eyJhbGc...",
  "qr_code_url": "https://api.honeyman.com/v2/onboarding/qr/abc123"
}
```

**Complete Onboarding (Installer → Dashboard)**
```http
POST /api/v2/onboarding/complete
Headers:
  Authorization: Bearer <onboarding-token>

Body:
{
  "platform": "rpi5",
  "capabilities": {
    "wifi": true,
    "bluetooth": true,
    "usb": true,
    "network": true,
    "airdrop": true
  },
  "system_info": {
    "cpu_cores": 4,
    "ram_mb": 8192,
    "storage_gb": 128
  }
}

Response 200:
{
  "sensor_id": "uuid",
  "api_key": "generated-api-key",
  "mqtt_credentials": {
    "broker": "mqtt.honeyman.com",
    "port": 8883,
    "username": "sensor-uuid",
    "password": "generated-password"
  },
  "config": {
    "protocol": "mqtt",
    "heartbeat_interval": 60,
    "rule_update_interval": 300
  },
  "rules": {
    "usb": "https://api.honeyman.com/v2/rules/usb/latest.tar.gz",
    "wifi": "https://api.honeyman.com/v2/rules/wifi/latest.tar.gz",
    ...
  },
  "malware_db_url": "https://api.honeyman.com/v2/data/malware_hashes.db"
}
```

---

## Migration Strategy

### V1 to V2 Migration Paths

#### Option A: Parallel Deployment (Recommended)

**Timeline:** 2-4 weeks

```
Week 1: Infrastructure Setup
├─ Deploy V2 dashboard infrastructure
├─ Set up PostgreSQL + TimescaleDB
├─ Deploy MQTT broker
├─ Configure monitoring
└─ Run acceptance tests

Week 2-3: Gradual Migration
├─ Migrate 1-2 sensors to V2 as pilot
├─ Monitor for issues
├─ Compare data between V1 and V2
├─ Tune configurations
└─ Migrate remaining sensors (batches of 5-10)

Week 4: Validation & Cutover
├─ Verify all sensors on V2
├─ Validate data completeness
├─ Performance testing
├─ Deprecate V1 infrastructure
└─ Update documentation
```

**Steps:**

1. **Deploy V2 Infrastructure**
```bash
# On VPS
cd dashboard-v2
docker-compose up -d postgres redis mosquitto
npm install
npm run migrate  # Database migrations
npm run build
npm start
```

2. **Pilot Migration (1 sensor)**
```bash
# On pilot RPI
curl -sSL get.honeyman.sh/v2 | sudo bash -s -- <TOKEN>

# Verify
systemctl status honeyman-agent
journalctl -u honeyman-agent -f

# Check dashboard shows sensor online
```

3. **Data Validation**
```sql
-- Compare threat counts
SELECT COUNT(*) FROM threats WHERE sensor_id = 'pilot-sensor-uuid';

-- Check data quality
SELECT
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE geolocation IS NOT NULL) as with_location,
    AVG(threat_score) as avg_score
FROM threats
WHERE sensor_id = 'pilot-sensor-uuid'
  AND timestamp > NOW() - INTERVAL '24 hours';
```

4. **Batch Migration**
```bash
# Create migration script
#!/bin/bash
# migrate-sensors.sh

SENSORS=(
    "rpi-sensor-01"
    "rpi-sensor-02"
    "rpi-sensor-03"
)

for sensor in "${SENSORS[@]}"; do
    echo "Migrating $sensor..."

    # Generate token for sensor
    TOKEN=$(curl -X POST https://api.honeyman.com/v2/onboarding/token \
        -H "X-API-Key: $ADMIN_KEY" \
        -d "{\"sensor_name\": \"$sensor\"}" | jq -r '.token')

    # SSH to sensor and run installer
    ssh $sensor "curl -sSL get.honeyman.sh/v2 | sudo bash -s -- $TOKEN"

    echo "$sensor migrated"
    sleep 30  # Wait before next sensor
done
```

5. **Deprecate V1**
```bash
# After all sensors migrated and validated
# On each sensor
sudo systemctl stop honeypot.target
sudo systemctl disable honeypot.target

# On V1 VPS
docker-compose down
# Archive V1 data
pg_dump honeyman_v1 > honeyman_v1_archive_$(date +%Y%m%d).sql
```

#### Option B: In-Place Upgrade (Advanced)

**Timeline:** 1 week (requires downtime)

```
Day 1: Preparation
├─ Backup all V1 data
├─ Export Elasticsearch data
├─ Test V2 deployment in staging
└─ Create rollback plan

Day 2: Infrastructure Update
├─ Deploy V2 dashboard
├─ Run database migrations
└─ Import historical data

Day 3-5: Agent Updates
├─ Auto-update all agents via script
├─ Monitor for issues
└─ Fix any failures

Day 6-7: Validation
├─ Verify all sensors online
├─ Check data integrity
└─ Performance testing
```

**Historical Data Import**

```python
#!/usr/bin/env python3
# scripts/import-v1-data.py

import json
from elasticsearch import Elasticsearch
from datetime import datetime
import psycopg2

# Connect to V1 Elasticsearch
es_v1 = Elasticsearch(['http://localhost:9200'])

# Connect to V2 PostgreSQL
pg_v2 = psycopg2.connect(
    dbname='honeyman_v2',
    user='honeyman',
    password='password',
    host='localhost'
)

def import_threats(sensor_mapping):
    """Import threats from V1 ES to V2 PostgreSQL"""

    query = {
        "query": {"match_all": {}},
        "size": 1000
    }

    scroll = es_v1.search(index="honeypot-logs-new", body=query, scroll='5m')
    scroll_id = scroll['_scroll_id']
    hits = scroll['hits']['hits']

    total_imported = 0

    while hits:
        batch = []

        for hit in hits:
            source = hit['_source']

            # Map V1 data to V2 schema
            threat = {
                'sensor_id': sensor_mapping.get(source.get('honeypot_id')),
                'timestamp': source.get('timestamp'),
                'source': source.get('source'),
                'threat_type': source.get('threat_type'),
                'threat_score': source.get('threat_score', 0.5),
                'risk_level': source.get('risk_level', 'medium'),
                'threats_detected': source.get('threats_detected', []),
                'message': source.get('message'),
                'raw_data': json.dumps(source)
            }

            batch.append(threat)

        # Bulk insert
        insert_threats_batch(pg_v2, batch)
        total_imported += len(batch)

        print(f"Imported {total_imported} threats...")

        # Get next batch
        scroll = es_v1.scroll(scroll_id=scroll_id, scroll='5m')
        hits = scroll['hits']['hits']

    print(f"Total imported: {total_imported}")

def insert_threats_batch(conn, threats):
    """Bulk insert threats"""
    cursor = conn.cursor()

    insert_query = """
        INSERT INTO threats (
            sensor_id, timestamp, source, threat_type,
            threat_score, risk_level, threats_detected, message, raw_data
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    values = [
        (
            t['sensor_id'], t['timestamp'], t['source'], t['threat_type'],
            t['threat_score'], t['risk_level'], t['threats_detected'],
            t['message'], t['raw_data']
        )
        for t in threats
    ]

    cursor.executemany(insert_query, values)
    conn.commit()

if __name__ == '__main__':
    # Map V1 sensor IDs to V2 UUIDs
    sensor_mapping = {
        'honeyman-01': 'uuid-1',
        'rpi-honeypot-001': 'uuid-2'
    }

    import_threats(sensor_mapping)
```

---

## Performance & Scalability

### Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Agent to Dashboard Latency** | < 500ms (p99) | Time from detection to dashboard display |
| **Dashboard Load Time** | < 2s | Initial page load |
| **Real-time Update Latency** | < 100ms | WebSocket message delivery |
| **Database Query Performance** | < 50ms (p95) | Threat list queries |
| **Rule Evaluation** | < 10ms per event | Agent-side rule engine |
| **MQTT Throughput** | > 10,000 msg/s | Broker capacity |
| **Concurrent Sensors** | > 500 | Dashboard capacity |

### Scalability Strategies

#### 1. Database Optimization

**TimescaleDB Compression**
```sql
-- Enable compression for older data
ALTER TABLE threats SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'sensor_id,threat_type',
    timescaledb.compress_orderby = 'timestamp DESC'
);

-- Compress chunks older than 7 days
SELECT add_compression_policy('threats', INTERVAL '7 days');
```

**Indexing Strategy**
- B-tree indexes for exact matches (sensor_id, threat_type)
- BRIN indexes for time-series data (timestamp)
- GiST indexes for geospatial queries (location)
- Partial indexes for common filters (WHERE risk_level = 'critical')

#### 2. Caching Layer (Redis)

```javascript
// services/cache.js

const redis = require('redis');
const client = redis.createClient({
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT
});

const CACHE_TTL = {
    THREAT_STATS: 60,        // 1 minute
    SENSOR_LIST: 300,        // 5 minutes
    ANALYTICS: 600,          // 10 minutes
    GEOLOCATION: 86400       // 24 hours
};

async function getCachedThreatStats(timeRange) {
    const cacheKey = `stats:threats:${timeRange}`;

    // Try cache first
    const cached = await client.get(cacheKey);
    if (cached) {
        return JSON.parse(cached);
    }

    // Compute from database
    const stats = await computeThreatStats(timeRange);

    // Store in cache
    await client.setex(
        cacheKey,
        CACHE_TTL.THREAT_STATS,
        JSON.stringify(stats)
    );

    return stats;
}
```

#### 3. Horizontal Scaling

**Load Balancer Configuration (Nginx)**
```nginx
upstream honeyman_api {
    least_conn;
    server api-1.honeyman.internal:3000;
    server api-2.honeyman.internal:3000;
    server api-3.honeyman.internal:3000;
}

upstream honeyman_mqtt {
    hash $remote_addr consistent;
    server mqtt-1.honeyman.internal:8883;
    server mqtt-2.honeyman.internal:8883;
}

server {
    listen 443 ssl http2;
    server_name api.honeyman.com;

    ssl_certificate /etc/ssl/certs/honeyman.crt;
    ssl_certificate_key /etc/ssl/private/honeyman.key;

    location /api/ {
        proxy_pass http://honeyman_api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    location /socket.io/ {
        proxy_pass http://honeyman_api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

#### 4. Database Sharding (Future)

For > 1000 sensors:

```
Sharding Strategy: By sensor_id hash
├─ Shard 1: sensors A-F (PostgreSQL instance 1)
├─ Shard 2: sensors G-M (PostgreSQL instance 2)
├─ Shard 3: sensors N-S (PostgreSQL instance 3)
└─ Shard 4: sensors T-Z (PostgreSQL instance 4)

Routing Layer: Citus or manual application-level sharding
```

#### 5. Monitoring & Observability

**Prometheus Metrics**
```javascript
// utils/metrics.js

const client = require('prom-client');

// Create metrics
const threatsProcessed = new client.Counter({
    name: 'honeyman_threats_processed_total',
    help: 'Total number of threats processed',
    labelNames: ['sensor_id', 'threat_type', 'risk_level']
});

const threatProcessingDuration = new client.Histogram({
    name: 'honeyman_threat_processing_duration_seconds',
    help: 'Threat processing duration',
    buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1]
});

const activeSensors = new client.Gauge({
    name: 'honeyman_active_sensors',
    help: 'Number of currently active sensors'
});

// Usage
async function processThreat(threat) {
    const end = threatProcessingDuration.startTimer();

    try {
        await saveThreatToDatabase(threat);

        threatsProcessed.inc({
            sensor_id: threat.sensor_id,
            threat_type: threat.threat_type,
            risk_level: threat.risk_level
        });
    } finally {
        end();
    }
}
```

**Grafana Dashboards**
- Threat volume over time
- Sensor health status
- API response times
- Database performance
- MQTT broker metrics
- Cache hit rates

---

## Deployment Architecture

### Production Deployment (Kubernetes - Optional)

```yaml
# k8s/deployment.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: honeyman-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: honeyman-api
  template:
    metadata:
      labels:
        app: honeyman-api
    spec:
      containers:
      - name: api
        image: honeyman/dashboard-api:v2.0.0
        ports:
        - containerPort: 3000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: honeyman-secrets
              key: database-url
        - name: REDIS_URL
          value: "redis://redis-service:6379"
        - name: MQTT_BROKER
          value: "mqtt://mosquitto-service:1883"
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /api/v2/health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/v2/health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: honeyman-api
spec:
  selector:
    app: honeyman-api
  ports:
  - port: 80
    targetPort: 3000
  type: LoadBalancer
```

### Docker Compose (Simpler Deployment)

```yaml
# docker-compose-v2.yml

version: '3.8'

services:
  postgres:
    image: timescale/timescaledb:2.11.0-pg15
    environment:
      POSTGRES_DB: honeyman_v2
      POSTGRES_USER: honeyman
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./database/migrations:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data
    ports:
      - "6379:6379"
    restart: unless-stopped

  mosquitto:
    image: eclipse-mosquitto:2
    volumes:
      - ./mqtt/mosquitto.conf:/mosquitto/config/mosquitto.conf
      - ./mqtt/certs:/mosquitto/certs
      - mosquitto-data:/mosquitto/data
    ports:
      - "1883:1883"
      - "8883:8883"
    restart: unless-stopped

  api:
    build: ./dashboard-v2/backend
    environment:
      NODE_ENV: production
      DATABASE_URL: postgres://honeyman:${POSTGRES_PASSWORD}@postgres:5432/honeyman_v2
      REDIS_URL: redis://redis:6379
      MQTT_BROKER: mqtt://mosquitto:1883
      HOSTINGER_API_KEY: ${HOSTINGER_API_KEY}
    ports:
      - "3000:3000"
    depends_on:
      - postgres
      - redis
      - mosquitto
    restart: unless-stopped

  frontend:
    build: ./dashboard-v2/frontend
    environment:
      REACT_APP_API_URL: https://api.honeyman.com/v2
      REACT_APP_WS_URL: wss://api.honeyman.com
    ports:
      - "80:80"
    depends_on:
      - api
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
    ports:
      - "443:443"
    depends_on:
      - api
      - frontend
    restart: unless-stopped

volumes:
  postgres-data:
  redis-data:
  mosquitto-data:
```

---

## Conclusion

Honeyman V2 represents a fundamental architectural transformation focusing on:

1. **Ease of Use**: One-command sensor deployment
2. **Flexibility**: Multi-protocol support for diverse environments
3. **Maintainability**: Rule-based detection separate from code
4. **Scalability**: Designed to support hundreds of sensors
5. **Intelligence**: Long-term storage, geolocation, advanced analytics

The architecture is designed to grow from a single sensor deployment to an enterprise-scale threat intelligence platform while maintaining simplicity for individual users.

---

**Next Steps:**
1. Review and approve architecture
2. Begin Phase 1 implementation (Foundation)
3. Develop agent prototype
4. Build onboarding system
5. Deploy pilot infrastructure

For questions or clarifications, please refer to the companion document: `V2-OVERVIEW.md`
