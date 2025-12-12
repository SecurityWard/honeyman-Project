# HONEYMAN V2 - IMPLEMENTATION PLAN

**Version:** 1.0
**Date:** 2025-11-29
**Status:** Planning Phase
**Based On:** HONEYMAN_V2_SUMMARY.md

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Gap Analysis - V1 to V2](#gap-analysis---v1-to-v2)
3. [Architecture Changes Required](#architecture-changes-required)
4. [Component Breakdown](#component-breakdown)
5. [Implementation Phases](#implementation-phases)
6. [File Structure Changes](#file-structure-changes)
7. [Database Migration Plan](#database-migration-plan)
8. [Development Roadmap](#development-roadmap)
9. [Testing Strategy](#testing-strategy)
10. [Deployment Strategy](#deployment-strategy)

---

## Executive Summary

This document outlines the complete implementation plan to transform Honeyman from V1 (monolithic, manually deployed) to V2 (modular, cloud-native, agent-based platform with global dashboard).

### Key Goals

✅ **Reduce deployment time from 30-60 minutes to <5 minutes**
✅ **Enable centralized management of 100+ sensors**
✅ **Implement hot-reload rule engine for zero-downtime updates**
✅ **Add global dashboard with geo-location visualization**
✅ **Support multiple transport protocols (MQTT primary, HTTP fallback)**
✅ **Achieve 90+ day data retention with TimescaleDB**

### Timeline

**Target:** 6 months from start
**Phases:** 6 major phases (detailed below)
**MVP:** 3 months (Phases 1-3)

---

## Gap Analysis - V1 to V2

### Current V1 Architecture

```
V1 Architecture (Monolithic)
├── Detection Scripts (Python)
│   ├── enhanced_usb_detector.py (~1,200 LOC)
│   ├── enhanced_ble_detector.py (~1,100 LOC)
│   ├── wifi_enhanced_detector.py
│   ├── airdrop_threat_detector.py
│   └── multi_vector_detection.py
├── Data Forwarder (HTTP only)
│   └── hostinger_data_forwarder.py
├── Dashboard (Basic HTML)
│   ├── index.html
│   └── enhanced_dashboard.html
├── Storage (Elasticsearch)
│   ├── In-memory (last 50K events)
│   └── No long-term retention
└── Deployment
    ├── Manual installation (20+ steps)
    ├── Individual sensor configuration
    └── No centralized management
```

### V2 Target Architecture

```
V2 Architecture (Distributed, Agent-Based)
├── Sensor Layer (Raspberry Pi)
│   ├── honeyman-agent (PyPI package)
│   │   ├── Core orchestrator
│   │   ├── Plugin manager
│   │   ├── Rule engine (YAML-based)
│   │   ├── Detectors (modular)
│   │   └── Transport layer (MQTT/HTTP/WS)
│   └── OpenCanary (Docker)
├── Transport Layer
│   ├── MQTT broker (Mosquitto + TLS)
│   ├── HTTP/REST fallback
│   └── WebSocket (future)
├── Dashboard Backend (VPS)
│   ├── Node.js + Express API
│   ├── PostgreSQL + TimescaleDB
│   ├── Redis (cache + real-time)
│   └── MQTT subscriber
├── Dashboard Frontend
│   ├── React 18 + TypeScript
│   ├── Leaflet.js (maps)
│   ├── Recharts (analytics)
│   └── Socket.IO (real-time)
└── Deployment
    ├── One-command installation
    ├── Auto-registration
    └── Centralized management
```

### What Needs to Change

| Component | V1 Current State | V2 Required | Change Type |
|-----------|------------------|-------------|-------------|
| **Detection Logic** | Embedded in Python code | YAML rule files | **Major Refactor** |
| **Agent Architecture** | Standalone scripts | Unified agent package | **New Development** |
| **Transport** | HTTP POST only | MQTT (primary) + HTTP fallback | **New Development** |
| **Dashboard** | Static HTML + Elasticsearch | React SPA + Node.js API | **Complete Rebuild** |
| **Database** | Elasticsearch (in-memory) | PostgreSQL + TimescaleDB | **New Infrastructure** |
| **Installation** | 20+ manual steps | One-command curl installer | **New Development** |
| **Sensor Management** | None | Centralized dashboard | **New Development** |
| **Data Retention** | None (in-memory) | 90+ days (configurable) | **New Infrastructure** |
| **Geolocation** | None | GPS → WiFi → IP fallback | **New Development** |
| **Rules Management** | Code changes required | Hot-reload via MQTT | **New Development** |

---

## Architecture Changes Required

### 1. Sensor (Agent) Changes

#### Current V1 Structure
```
/src/detectors/
├── usb_enhanced_detector.py      (standalone script)
├── ble_enhanced_detector.py      (standalone script)
├── wifi_enhanced_detector.py     (standalone script)
├── airdrop_threat_detector.py    (standalone script)
└── multi_vector_detection.py     (standalone script)
```

#### V2 Target Structure
```
/honeyman-agent/                   (PyPI package)
├── setup.py
├── honeyman/
│   ├── __init__.py
│   ├── agent.py                   (main orchestrator)
│   ├── core/
│   │   ├── agent_core.py          (lifecycle management)
│   │   ├── plugin_manager.py      (dynamic module loading)
│   │   ├── config_manager.py      (configuration validation)
│   │   ├── heartbeat.py           (health reporting)
│   │   └── capability_detector.py (hardware detection)
│   ├── detectors/
│   │   ├── base_detector.py       (abstract base class)
│   │   ├── usb_detector.py        (refactored with rules)
│   │   ├── ble_detector.py        (refactored with rules)
│   │   ├── wifi_detector.py       (refactored with rules)
│   │   ├── airdrop_detector.py    (refactored with rules)
│   │   └── network_detector.py    (OpenCanary integration)
│   ├── transport/
│   │   ├── protocol_handler.py    (multi-protocol abstraction)
│   │   ├── mqtt_client.py         (MQTT transport)
│   │   ├── http_client.py         (HTTP/REST transport)
│   │   └── websocket_client.py    (WebSocket transport)
│   ├── rules/
│   │   ├── rule_engine.py         (rule evaluation)
│   │   ├── rule_loader.py         (YAML parser)
│   │   ├── rule_validator.py      (syntax validation)
│   │   └── rule_updater.py        (auto-update from dashboard)
│   ├── services/
│   │   └── location_service.py    (GPS/WiFi/IP geolocation)
│   └── utils/
│       ├── logger.py
│       ├── crypto.py
│       └── metrics.py
└── rules/                         (detection rules)
    ├── usb/
    │   ├── malware_signatures.yaml
    │   ├── badusb_patterns.yaml
    │   └── device_behavior.yaml
    ├── wifi/
    │   ├── evil_twin_detection.yaml
    │   ├── deauth_patterns.yaml
    │   └── beacon_flooding.yaml
    ├── ble/
    │   ├── flipper_zero.yaml
    │   ├── ble_spam.yaml
    │   └── device_spoofing.yaml
    ├── airdrop/
    │   └── suspicious_services.yaml
    └── network/
        ├── port_scan_detection.yaml
        └── brute_force.yaml
```

**Migration Steps:**
1. Extract detection logic from V1 scripts into YAML rules
2. Refactor detector classes to extend `BaseDetector`
3. Implement rule engine to evaluate YAML rules
4. Add multi-protocol transport layer
5. Package as installable Python package

---

### 2. Dashboard Backend Changes

#### V2 New Infrastructure
```
/dashboard-v2/
├── backend/
│   ├── package.json
│   ├── server.js                  (main Express app)
│   ├── routes/
│   │   ├── sensors.js             (sensor management API)
│   │   ├── threats.js             (threat data API)
│   │   ├── rules.js               (rule management API)
│   │   ├── analytics.js           (analytics API)
│   │   ├── alerts.js              (alerting API)
│   │   └── onboarding.js          (sensor registration API)
│   ├── controllers/
│   │   ├── sensorsController.js
│   │   ├── threatsController.js
│   │   └── rulesController.js
│   ├── middleware/
│   │   ├── auth.js                (API key authentication)
│   │   ├── rateLimit.js           (rate limiting)
│   │   └── validation.js          (input validation)
│   ├── services/
│   │   ├── mqttHandler.js         (MQTT broker subscriber)
│   │   ├── geolocationService.js  (IP/WiFi geolocation)
│   │   ├── ruleSyncService.js     (rule distribution to sensors)
│   │   ├── analyticsService.js    (pre-computed analytics)
│   │   └── alertingService.js     (alert dispatch)
│   ├── database/
│   │   ├── migrations/            (TimescaleDB migrations)
│   │   ├── models/
│   │   │   ├── Sensor.js
│   │   │   ├── Threat.js
│   │   │   └── Rule.js
│   │   └── queries/
│   │       ├── sensorQueries.js
│   │       ├── threatQueries.js
│   │       └── analyticsQueries.js
│   └── utils/
│       ├── logger.js
│       ├── crypto.js
│       └── validators.js
└── frontend/
    ├── package.json
    ├── public/
    ├── src/
    │   ├── components/
    │   │   ├── common/
    │   │   ├── maps/              (Leaflet.js components)
    │   │   ├── sensors/           (sensor management UI)
    │   │   ├── threats/           (threat explorer)
    │   │   ├── analytics/         (charts and graphs)
    │   │   └── rules/             (rule editor)
    │   ├── pages/
    │   │   ├── Dashboard.tsx
    │   │   ├── Sensors.tsx
    │   │   ├── Threats.tsx
    │   │   ├── Analytics.tsx
    │   │   └── Rules.tsx
    │   ├── hooks/
    │   │   ├── useWebSocket.ts
    │   │   ├── useSensors.ts
    │   │   └── useThreats.ts
    │   ├── services/
    │   │   ├── api.ts
    │   │   └── websocket.ts
    │   └── store/
    │       ├── sensorsStore.ts
    │       └── threatsStore.ts
    └── tsconfig.json
```

**Development Steps:**
1. Set up Node.js + Express backend
2. Implement PostgreSQL + TimescaleDB schema
3. Create REST API endpoints
4. Implement MQTT subscriber service
5. Build React frontend
6. Integrate Leaflet.js for maps
7. Implement Socket.IO for real-time updates

---

### 3. MQTT Broker Infrastructure

**New Component:** Mosquitto MQTT broker on VPS

```yaml
# docker-compose-v2.yml (on VPS)
services:
  mosquitto:
    image: eclipse-mosquitto:2
    volumes:
      - ./mqtt/mosquitto.conf:/mosquitto/config/mosquitto.conf
      - ./mqtt/certs:/mosquitto/certs
      - mosquitto-data:/mosquitto/data
    ports:
      - "1883:1883"   # MQTT
      - "8883:8883"   # MQTT over TLS
    restart: unless-stopped
```

**Configuration:**
```conf
# mosquitto.conf
listener 8883
cafile /mosquitto/certs/ca.crt
certfile /mosquitto/certs/server.crt
keyfile /mosquitto/certs/server.key
require_certificate false
tls_version tlsv1.3

allow_anonymous false
password_file /mosquitto/passwd

acl_file /mosquitto/acl.conf
```

**ACL Configuration:**
```conf
# acl.conf
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

**Setup Steps:**
1. Deploy Mosquitto on VPS
2. Generate TLS certificates (Let's Encrypt)
3. Configure per-sensor credentials
4. Set up ACL for topic security
5. Test MQTT connectivity

---

### 4. Database Migration

**Replace:** Elasticsearch (in-memory)
**With:** PostgreSQL 15 + TimescaleDB 2.11+

#### Schema Creation
```sql
-- Enable extensions
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS postgis;

-- Sensors table
CREATE TABLE sensors (
    sensor_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    platform VARCHAR(100) NOT NULL,
    capabilities JSONB NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'offline',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat TIMESTAMPTZ,
    config JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Threats table (hypertable)
CREATE TABLE threats (
    threat_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sensor_id UUID NOT NULL REFERENCES sensors(sensor_id) ON DELETE CASCADE,
    sensor_name VARCHAR(255) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source VARCHAR(100) NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    threat_score FLOAT NOT NULL,
    risk_level VARCHAR(50) NOT NULL,
    geolocation GEOGRAPHY(POINT, 4326),
    geolocation_accuracy FLOAT,
    geolocation_source VARCHAR(20),
    city VARCHAR(100),
    country VARCHAR(2),
    threats_detected TEXT[],
    message TEXT,
    raw_data JSONB
);

-- Convert to TimescaleDB hypertable
SELECT create_hypertable('threats', 'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- Rules table
CREATE TABLE rules (
    rule_id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(20) NOT NULL,
    category VARCHAR(100) NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    rule_yaml TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add indexes
CREATE INDEX idx_threats_sensor_time ON threats(sensor_id, timestamp DESC);
CREATE INDEX idx_threats_location ON threats USING GIST(geolocation);
CREATE INDEX idx_threats_type ON threats(threat_type);
CREATE INDEX idx_threats_score ON threats(threat_score DESC);
```

**Migration from V1 Elasticsearch:**
1. Export existing Elasticsearch data
2. Transform to V2 schema format
3. Import to PostgreSQL
4. Validate data completeness
5. Set up continuous aggregates for analytics

---

### 5. One-Command Installer

**New Component:** Automated sensor installation script

```bash
#!/bin/bash
# install.sh - Honeyman V2 Sensor Installer
# Usage: curl -sSL get.honeyman.sh | sudo bash -s -- <TOKEN>

set -e

ONBOARDING_TOKEN="$1"
DASHBOARD_URL="${DASHBOARD_URL:-https://api.honeyman.com}"

echo "╔════════════════════════════════════════╗"
echo "║   Honeyman V2 Sensor Installer        ║"
echo "╚════════════════════════════════════════╝"

# 1. Validate token
echo "[1/7] Validating onboarding token..."
curl -sf "$DASHBOARD_URL/v2/onboarding/validate" \
    -H "Authorization: Bearer $ONBOARDING_TOKEN" > /tmp/honeyman-config.json

# 2. Detect platform
echo "[2/7] Detecting platform..."
PLATFORM=$(cat /proc/device-tree/model 2>/dev/null | grep -o "Raspberry Pi [0-9]" || echo "linux")

# 3. Detect capabilities
echo "[3/7] Detecting hardware capabilities..."
HAS_WIFI=$(iw dev 2>/dev/null && echo "true" || echo "false")
HAS_BLE=$(hcitool dev 2>/dev/null | grep -q "hci0" && echo "true" || echo "false")

# 4. Install dependencies
echo "[4/7] Installing dependencies..."
apt-get update -qq
apt-get install -y python3 python3-pip docker.io docker-compose

# 5. Install honeyman-agent
echo "[5/7] Installing honeyman-agent..."
pip3 install honeyman-agent

# 6. Configure agent
echo "[6/7] Configuring agent..."
SENSOR_ID=$(jq -r '.sensor_id' /tmp/honeyman-config.json)
mkdir -p /etc/honeyman
cat > /etc/honeyman/config.yaml <<EOF
sensor_id: $SENSOR_ID
sensor_name: $(jq -r '.sensor_name' /tmp/honeyman-config.json)
api_key: $(jq -r '.api_key' /tmp/honeyman-config.json)

mqtt:
  broker: $(jq -r '.mqtt_credentials.broker' /tmp/honeyman-config.json)
  port: $(jq -r '.mqtt_credentials.port' /tmp/honeyman-config.json)
  username: $(jq -r '.mqtt_credentials.username' /tmp/honeyman-config.json)
  password: $(jq -r '.mqtt_credentials.password' /tmp/honeyman-config.json)
  use_tls: true

detectors:
  wifi: $HAS_WIFI
  bluetooth: $HAS_BLE
  usb: true
  network: true
EOF

# 7. Start services
echo "[7/7] Starting honeyman services..."
systemctl enable honeyman-agent
systemctl start honeyman-agent

echo "✅ Installation complete!"
echo "Sensor ID: $SENSOR_ID"
echo "Dashboard: $DASHBOARD_URL"
```

---

## Component Breakdown

### Phase 1: Foundation (Months 1-2)

**Goal:** Build core infrastructure and agent prototype

#### Tasks
1. **Agent Core Development**
   - [ ] Create Python package structure
   - [ ] Implement `BaseDetector` abstract class
   - [ ] Build plugin manager for dynamic detector loading
   - [ ] Create configuration management system
   - [ ] Implement heartbeat service

2. **Rule Engine Prototype**
   - [ ] Design YAML rule schema
   - [ ] Build YAML rule parser
   - [ ] Implement rule evaluator
   - [ ] Create rule validator
   - [ ] Test rule engine with sample rules

3. **Transport Layer**
   - [ ] Implement MQTT client
   - [ ] Implement HTTP client fallback
   - [ ] Build protocol abstraction layer
   - [ ] Add offline queueing
   - [ ] Test multi-protocol failover

4. **Infrastructure Setup**
   - [ ] Deploy Mosquitto MQTT broker on VPS
   - [ ] Set up PostgreSQL + TimescaleDB
   - [ ] Configure Redis
   - [ ] Set up development environment

**Deliverable:** Working agent prototype that can connect to MQTT broker and send test events

---

### Phase 2: Detector Refactoring (Months 2-3)

**Goal:** Refactor V1 detectors to use rule engine

#### Tasks
1. **USB Detector Refactor**
   - [ ] Extract detection logic from V1 code
   - [ ] Create YAML rules for malware signatures
   - [ ] Create YAML rules for BadUSB patterns
   - [ ] Refactor detector to extend `BaseDetector`
   - [ ] Test with real USB devices

2. **WiFi Detector Refactor**
   - [ ] Extract evil twin detection logic
   - [ ] Create YAML rules for WiFi attacks
   - [ ] Refactor detector to extend `BaseDetector`
   - [ ] Test with monitor mode capture

3. **BLE Detector Refactor**
   - [ ] Extract Flipper Zero detection logic
   - [ ] Create YAML rules for BLE threats
   - [ ] Refactor detector to extend `BaseDetector`
   - [ ] Test with BLE devices

4. **Network Detector Integration**
   - [ ] Integrate OpenCanary as detection module
   - [ ] Create YAML rules for network attacks
   - [ ] Build OpenCanary event parser
   - [ ] Test with honeypot services

5. **Location Service**
   - [ ] Implement GPS location service
   - [ ] Implement WiFi positioning (Google Geolocation API)
   - [ ] Implement IP geolocation fallback
   - [ ] Test location accuracy

**Deliverable:** Feature-complete agent with all V1 detection capabilities using rules

---

### Phase 3: Dashboard Backend (Months 3-4)

**Goal:** Build API backend and data ingestion

#### Tasks
1. **API Server Setup**
   - [ ] Set up Node.js + Express project
   - [ ] Implement authentication middleware
   - [ ] Implement rate limiting
   - [ ] Set up CORS and security headers

2. **Database Layer**
   - [ ] Create TimescaleDB schema
   - [ ] Write database migrations
   - [ ] Create ORM models (Sensor, Threat, Rule)
   - [ ] Implement query builders

3. **MQTT Integration**
   - [ ] Build MQTT subscriber service
   - [ ] Implement threat data ingestion
   - [ ] Implement heartbeat processing
   - [ ] Add geolocation enrichment

4. **API Endpoints**
   - [ ] Sensor management endpoints
   - [ ] Threat data endpoints
   - [ ] Analytics endpoints
   - [ ] Rule management endpoints
   - [ ] Onboarding endpoints

5. **Real-Time Services**
   - [ ] Implement Socket.IO server
   - [ ] Build Redis pub/sub integration
   - [ ] Implement real-time threat broadcasting

**Deliverable:** Functional backend API with all endpoints

---

### Phase 4: Dashboard Frontend (Months 4-5)

**Goal:** Build React dashboard with maps and analytics

#### Tasks
1. **React Application Setup**
   - [ ] Create React + TypeScript project
   - [ ] Set up routing (React Router)
   - [ ] Configure state management (Zustand)
   - [ ] Set up API client (React Query)

2. **Core UI Components**
   - [ ] Header and navigation
   - [ ] Sidebar menu
   - [ ] Loading states
   - [ ] Error boundaries
   - [ ] Toast notifications

3. **Threat Map**
   - [ ] Integrate Leaflet.js
   - [ ] Implement marker clustering
   - [ ] Add heat map overlay
   - [ ] Build location detail view
   - [ ] Add filtering controls

4. **Sensor Management**
   - [ ] Sensor grid/list view
   - [ ] Sensor detail page
   - [ ] Sensor configuration editor
   - [ ] Real-time status updates

5. **Threat Explorer**
   - [ ] Threat list with filters
   - [ ] Threat detail view
   - [ ] Timeline visualization
   - [ ] Export functionality

6. **Analytics Dashboard**
   - [ ] Threat trend charts (Recharts)
   - [ ] Severity distribution graphs
   - [ ] Velocity metrics
   - [ ] Geographic analytics

7. **Rule Editor**
   - [ ] YAML rule editor (syntax highlighting)
   - [ ] Rule validator
   - [ ] Rule test interface
   - [ ] Rule deployment UI

**Deliverable:** Complete web dashboard

---

### Phase 5: Onboarding & Deployment (Month 5-6)

**Goal:** One-command installation and sensor provisioning

#### Tasks
1. **Installer Script**
   - [ ] Write bash installation script
   - [ ] Implement platform detection
   - [ ] Implement capability detection
   - [ ] Add error handling and rollback

2. **Onboarding Flow**
   - [ ] Build token generation API
   - [ ] Create onboarding UI in dashboard
   - [ ] Generate QR codes for tokens
   - [ ] Implement auto-registration

3. **PyPI Package**
   - [ ] Prepare honeyman-agent for PyPI
   - [ ] Write setup.py
   - [ ] Create documentation
   - [ ] Publish to PyPI

4. **Rule Distribution**
   - [ ] Implement rule sync service
   - [ ] Build rule update mechanism
   - [ ] Add version control
   - [ ] Test hot-reload

5. **Testing & Documentation**
   - [ ] Write user documentation
   - [ ] Create video tutorials
   - [ ] Beta testing with 5-10 sensors
   - [ ] Fix critical bugs

**Deliverable:** Production-ready platform

---

### Phase 6: Advanced Features (Month 6+)

**Goal:** Enterprise features and optimizations

#### Tasks
1. **Alerting Integrations**
   - [ ] Discord webhook
   - [ ] Slack integration
   - [ ] Email notifications (SMTP)
   - [ ] PagerDuty integration

2. **Analytics Enhancements**
   - [ ] Cross-protocol correlation
   - [ ] Attack velocity detection
   - [ ] Threat clustering
   - [ ] Behavioral baseline learning

3. **Performance Optimization**
   - [ ] Database query optimization
   - [ ] Redis caching strategy
   - [ ] Frontend performance tuning
   - [ ] Load testing

4. **Security Hardening**
   - [ ] Security audit
   - [ ] Penetration testing
   - [ ] Rate limiting refinement
   - [ ] Input sanitization review

**Deliverable:** Enterprise-grade platform

---

## File Structure Changes

### Before (V1)
```
honeyman-Project/
├── src/
│   ├── detectors/              (standalone scripts)
│   ├── forwarders/             (HTTP forwarder)
│   └── utils/
├── dashboard/                  (static HTML)
│   ├── index.html
│   └── enhanced_dashboard.html
├── docker-compose.yml          (OpenCanary + Elasticsearch)
├── scripts/                    (installation helpers)
└── web/                        (static files)
```

### After (V2)
```
honeyman-v2/
├── agent/                      (NEW - Python package)
│   ├── setup.py
│   ├── honeyman/
│   │   ├── agent.py
│   │   ├── core/
│   │   ├── detectors/
│   │   ├── transport/
│   │   ├── rules/
│   │   └── services/
│   └── rules/                  (YAML rule files)
├── dashboard-v2/               (NEW - Full stack app)
│   ├── backend/                (Node.js + Express)
│   │   ├── routes/
│   │   ├── controllers/
│   │   ├── services/
│   │   └── database/
│   └── frontend/               (React + TypeScript)
│       └── src/
│           ├── components/
│           ├── pages/
│           └── services/
├── deployment/                 (NEW - Infrastructure)
│   ├── docker/
│   │   └── docker-compose-v2.yml
│   ├── k8s/                    (Kubernetes manifests)
│   └── terraform/              (future)
├── scripts/                    (NEW - Installation)
│   └── install.sh              (one-command installer)
└── docs/                       (NEW - Documentation)
    ├── API.md
    ├── DEPLOYMENT.md
    └── RULES.md
```

---

## Database Migration Plan

### Step 1: Export V1 Data
```bash
# Export from Elasticsearch
elasticdump \
  --input=http://localhost:9200/honeypot-logs-new \
  --output=/backup/v1-threats.json \
  --type=data
```

### Step 2: Transform Data
```python
# scripts/migrate-v1-to-v2.py
import json
import psycopg2
from datetime import datetime

def migrate_threats():
    # Load V1 data
    with open('/backup/v1-threats.json') as f:
        v1_data = [json.loads(line) for line in f]

    # Connect to V2 database
    conn = psycopg2.connect(
        dbname='honeyman_v2',
        user='honeyman',
        password='password',
        host='localhost'
    )

    cursor = conn.cursor()

    for hit in v1_data:
        source = hit['_source']

        # Map V1 to V2 schema
        cursor.execute("""
            INSERT INTO threats (
                sensor_id, sensor_name, timestamp, source,
                threat_type, threat_score, risk_level,
                threats_detected, message, raw_data
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            source.get('honeypot_id'),
            source.get('honeypot_name', 'Unknown'),
            source.get('timestamp'),
            source.get('source'),
            source.get('threat_type'),
            source.get('threat_score', 0.5),
            source.get('risk_level', 'medium'),
            source.get('threats_detected', []),
            source.get('message'),
            json.dumps(source)
        ))

    conn.commit()
    cursor.close()
    conn.close()
```

### Step 3: Validate Migration
```sql
-- Compare counts
SELECT COUNT(*) FROM threats;

-- Check data quality
SELECT
    COUNT(*) as total,
    COUNT(DISTINCT sensor_id) as sensors,
    MIN(timestamp) as earliest,
    MAX(timestamp) as latest,
    AVG(threat_score) as avg_score
FROM threats;
```

---

## Development Roadmap

### Month 1
- ✅ Week 1: Architecture review and approval
- ✅ Week 2: Set up development environment
- 🔄 Week 3: Agent core implementation (50%)
- 📋 Week 4: Rule engine prototype

### Month 2
- 📋 Week 1: Transport layer (MQTT + HTTP)
- 📋 Week 2: USB detector refactor
- 📋 Week 3: WiFi detector refactor
- 📋 Week 4: BLE detector refactor

### Month 3
- 📋 Week 1: Network detector + location service
- 📋 Week 2: Dashboard backend setup
- 📋 Week 3: Database schema + API endpoints
- 📋 Week 4: MQTT integration + Socket.IO

### Month 4
- 📋 Week 1: React app setup + core components
- 📋 Week 2: Threat map implementation
- 📋 Week 3: Sensor management UI
- 📋 Week 4: Threat explorer

### Month 5
- 📋 Week 1: Analytics dashboard + charts
- 📋 Week 2: Rule editor UI
- 📋 Week 3: Onboarding flow + installer
- 📋 Week 4: PyPI package + documentation

### Month 6
- 📋 Week 1: Beta testing
- 📋 Week 2: Bug fixes + optimizations
- 📋 Week 3: Security hardening
- 📋 Week 4: Production deployment

---

## Testing Strategy

### Unit Testing
```bash
# Agent tests
cd agent
pytest tests/ --cov=honeyman

# Backend tests
cd dashboard-v2/backend
npm test

# Frontend tests
cd dashboard-v2/frontend
npm test
```

### Integration Testing
1. **Agent → MQTT → Backend**
   - Test threat detection and transmission
   - Test offline queueing
   - Test protocol fallback

2. **Backend → Database**
   - Test data ingestion
   - Test analytics queries
   - Test data retention

3. **Backend → Frontend**
   - Test API endpoints
   - Test real-time updates
   - Test WebSocket connectivity

### Load Testing
```bash
# Test with 100 simulated sensors
cd testing
./simulate-sensors.sh 100

# Monitor performance
docker stats
```

### Security Testing
- [ ] Penetration testing of API
- [ ] MQTT ACL validation
- [ ] SQL injection testing
- [ ] XSS testing
- [ ] Rate limiting verification

---

## Deployment Strategy

### Option A: Parallel Deployment (Recommended)

**Timeline:** 2-4 weeks

```
Week 1: Infrastructure
├─ Deploy V2 dashboard on VPS
├─ Set up PostgreSQL + TimescaleDB
├─ Deploy MQTT broker
└─ Run acceptance tests

Week 2-3: Gradual Migration
├─ Migrate 1-2 pilot sensors
├─ Monitor for issues
├─ Compare V1 vs V2 data
└─ Migrate remaining sensors (batches)

Week 4: Cutover
├─ Verify all sensors on V2
├─ Validate data completeness
├─ Deprecate V1 infrastructure
└─ Archive V1 data
```

### Option B: In-Place Upgrade

**Timeline:** 1 week (requires downtime)

```
Day 1: Preparation
├─ Backup all V1 data
├─ Export Elasticsearch
├─ Test V2 in staging
└─ Create rollback plan

Day 2: Infrastructure
├─ Deploy V2 dashboard
├─ Run migrations
└─ Import historical data

Day 3-5: Agent Updates
├─ Auto-update all agents
├─ Monitor for failures
└─ Fix critical issues

Day 6-7: Validation
├─ Verify all sensors online
├─ Check data integrity
└─ Performance testing
```

---

## Success Criteria

### Phase 1 (Foundation)
- ✅ Agent can connect to MQTT broker
- ✅ Rule engine can evaluate YAML rules
- ✅ Transport layer supports failover

### Phase 2 (Detectors)
- ✅ All V1 detectors refactored
- ✅ 100% feature parity with V1
- ✅ Rules hot-reload without restart

### Phase 3 (Backend)
- ✅ All API endpoints functional
- ✅ Real-time updates working
- ✅ 90+ day data retention

### Phase 4 (Frontend)
- ✅ Dashboard loads in <2s
- ✅ Map displays threats correctly
- ✅ All filters and searches work

### Phase 5 (Deployment)
- ✅ One-command install works
- ✅ Sensor onboarding <5 minutes
- ✅ Beta test with 10+ sensors

### Phase 6 (Production)
- ✅ 99.9% uptime
- ✅ <100ms real-time latency
- ✅ Support 100+ concurrent sensors

---

## Risk Mitigation

### Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| MQTT broker instability | High | Use managed service (AWS IoT Core) as backup |
| Database performance | Medium | Implement aggressive caching, continuous aggregates |
| Agent package size | Low | Minimize dependencies, optional modules |
| Rule syntax errors | Medium | Comprehensive validator, syntax highlighting |
| Geolocation accuracy | Low | Fallback chain (GPS → WiFi → IP) |

### Operational Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Migration data loss | High | Multiple backups, validation scripts |
| Sensor connectivity | Medium | Offline queue, auto-retry |
| Breaking API changes | Medium | Versioned API endpoints |
| User adoption | Low | Comprehensive docs, video tutorials |

---

## Next Steps

1. **Review and approve this implementation plan**
2. **Set up development environment**
   - Clone repository
   - Install dependencies
   - Configure VPS access
3. **Begin Phase 1 implementation**
   - Create agent package structure
   - Implement rule engine prototype
   - Deploy MQTT broker
4. **Weekly progress reviews**
   - Track completion against roadmap
   - Adjust timeline as needed

---

## Questions for Clarification

1. **VPS Selection:** Which VPS provider? (Hostinger, DigitalOcean, AWS?)
2. **Budget:** Any constraints on infrastructure costs?
3. **Beta Testers:** Do we have 5-10 users willing to test early?
4. **Domain:** Do we have a domain for the dashboard? (e.g., dashboard.honeyman.com)
5. **TLS Certificates:** Let's Encrypt or paid certificate?
6. **Monitoring:** Should we integrate Prometheus + Grafana?

---

**Last Updated:** 2025-11-29
**Version:** 1.0
**Status:** Ready for Review
