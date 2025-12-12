# Honeyman Project Version 2.0 - Overview

**Vision:** Transform Honeyman from a manually-deployed detection system into a scalable, cloud-native platform that anyone can deploy in minutes.

**Document Version:** 1.0
**Last Updated:** 2025-10-23
**Status:** Planning Phase

---

## Table of Contents

1. [What is Honeyman V2?](#what-is-honeyman-v2)
2. [Why Version 2?](#why-version-2)
3. [Key Improvements](#key-improvements)
4. [User Experience](#user-experience)
5. [Technical Highlights](#technical-highlights)
6. [Detection Capabilities](#detection-capabilities)
7. [Dashboard Features](#dashboard-features)
8. [Deployment Options](#deployment-options)
9. [Roadmap](#roadmap)
10. [FAQ](#faq)

---

## What is Honeyman V2?

Honeyman V2 is a complete architectural reimagining of the Honeyman Project - a multi-vector threat detection platform that monitors for wireless, network, and USB-based attacks in real-time.

### The Vision

**V1:** A powerful but complex detection system requiring technical expertise to deploy and maintain.

**V2:** A platform where anyone can:
- Deploy a sensor in under 5 minutes with one command
- Monitor threats in real-time on an interactive map
- Manage dozens of sensors from a centralized dashboard
- Update detection logic without touching code
- Access months of historical threat data

---

## Why Version 2?

### Problems with V1

1. **Complex Setup**
   - Required 30-60 minutes of manual configuration
   - Multiple commands to run
   - Easy to misconfigure
   - Hard to replicate across multiple sensors

2. **No Historical Data**
   - All threat data in memory
   - Lost on restart
   - No way to analyze past threats
   - No long-term trending

3. **Maintenance Burden**
   - Detection logic embedded in code
   - Updating signatures requires code changes
   - No central management of sensors
   - Each sensor configured independently

4. **Limited Visibility**
   - Basic dashboard with limited insights
   - No geolocation
   - No sensor management interface
   - No advanced analytics

5. **Single Protocol**
   - HTTP only
   - High bandwidth usage
   - Not suitable for cellular/limited connections

### V2 Solutions

| Problem | V2 Solution |
|---------|-------------|
| Complex setup | One-command installation via curl |
| No historical data | PostgreSQL + TimescaleDB (90+ days retention) |
| Maintenance burden | Rule-based detection with live updates |
| Limited visibility | React dashboard with maps, analytics, sensor management |
| Single protocol | MQTT, HTTP, WebSocket, gRPC support |

---

## Key Improvements

### 1. One-Command Sensor Deployment

**V1:**
```bash
# 20+ commands, 30-60 minutes
git clone <repo>
sudo apt update
sudo apt install python3-pip docker.io docker-compose nodejs npm...
pip3 install -r requirements.txt
# Edit .env file manually
# Edit configuration files
docker-compose up -d
./install-systemd-services.sh
sudo systemctl enable honeypot.target
sudo systemctl start honeypot.target
# Verify everything is working...
```

**V2:**
```bash
# 1 command, 5 minutes
curl -sSL get.honeyman.sh | sudo bash -s -- <TOKEN>
```

The installer automatically:
- Detects hardware capabilities
- Installs all dependencies
- Downloads detection rules
- Configures services
- Registers with dashboard
- Starts threat detection

### 2. Rule-Based Detection Engine

**V1:** Detection logic embedded in Python code
```python
# usb_enhanced_detector.py - line 234
if device.vid == "0x1234" and file_hash in malware_db:
    threat_score = 0.95
    threat_type = "malware"
    # ... 100+ lines of logic
```

**V2:** YAML rules separate from code
```yaml
# rules/usb/malware_stuxnet.yaml
rule_id: usb_malware_001
name: "Stuxnet USB Worm Detection"
severity: critical

conditions:
  - type: file_hash_match
    values: ["9c5e8a8e...", "7a3f2e1d..."]
  - type: device_vendor
    value: "0x1234"

actions:
  - alert_dashboard
  - quarantine_device
```

**Benefits:**
- Update rules via dashboard UI (no coding)
- A/B test detection logic
- Share rules with community
- Version control built-in
- Live updates to sensors

### 3. Long-Term Data Storage

**V1:** In-memory storage (last 50,000 threats)
- Data lost on restart
- No historical analysis
- No trend identification

**V2:** PostgreSQL + TimescaleDB
- 90+ days retention (configurable)
- Time-series optimized
- Advanced analytics
- Historical trending
- Correlation analysis

**Example Queries:**
```sql
-- Find attack patterns over time
SELECT
    date_trunc('hour', timestamp) as hour,
    threat_type,
    COUNT(*) as count
FROM threats
WHERE timestamp > NOW() - INTERVAL '30 days'
GROUP BY hour, threat_type
ORDER BY hour DESC;

-- Geographic threat distribution
SELECT
    country,
    city,
    COUNT(*) as threat_count,
    AVG(threat_score) as avg_severity
FROM threats
WHERE timestamp > NOW() - INTERVAL '7 days'
  AND geolocation IS NOT NULL
GROUP BY country, city
ORDER BY threat_count DESC;
```

### 4. Interactive Geolocation Dashboard

**V1:** Basic threat list
```
[ ] Threat 1: WiFi evil twin detected
[ ] Threat 2: USB malware detected
[ ] Threat 3: Port scan detected
```

**V2:** Interactive map with analytics

```
┌────────────────────────────────────────────────────────────┐
│  🌍 Global Threat Map                                      │
│  ┌──────────────────────────────────────────────────────┐ │
│  │         🗺️  Interactive World Map                    │ │
│  │                                                       │ │
│  │    🔴 Las Vegas (145 threats)                        │ │
│  │         └─ Critical: 12, High: 45, Medium: 88       │ │
│  │                                                       │ │
│  │    🟡 San Francisco (23 threats)                     │ │
│  │         └─ High: 3, Medium: 15, Low: 5              │ │
│  │                                                       │ │
│  └──────────────────────────────────────────────────────┘ │
│                                                            │
│  Filters: [All Types ▼] [Last 24h ▼] [Severity: All ▼]   │
│                                                            │
│  📊 Threat Timeline                                        │
│  ▁▂▃▅▄▃▅█▆▄▃▂▁ (Interactive chart showing activity)     │
└────────────────────────────────────────────────────────────┘
```

**Features:**
- Click markers for threat details
- Heat map view for density
- Filter by type, severity, time
- Time-lapse visualization
- Export threat data

### 5. Multi-Protocol Communication

**V1:** HTTP only
- 100% bandwidth = HTTP POST
- High latency
- Battery drain on mobile
- Not suitable for cellular

**V2:** Protocol flexibility
- **MQTT** (90% less bandwidth, perfect for mobile)
- **HTTP** (compatibility, fallback)
- **WebSocket** (real-time bidirectional)
- **gRPC** (high performance, future)

**Bandwidth Comparison:**
```
Same threat event sent via different protocols:

HTTP:     2.4 KB (JSON payload + headers)
MQTT:     0.3 KB (binary protocol, QoS 1)
Savings:  87.5% less bandwidth

Over 1000 threats/day:
HTTP:     2.4 MB/day
MQTT:     0.3 MB/day
Savings:  2.1 MB/day per sensor
```

### 6. Centralized Sensor Management

**V1:** Each sensor configured independently
- No visibility into sensor health
- Manual updates required
- No remote configuration
- Hard to manage at scale

**V2:** Dashboard-based management

```
┌────────────────────────────────────────────────────────────┐
│  Sensors (42 total)                            [+ Add New] │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ 🟢 RPI5-LasVegas        Platform: RPI5    Uptime: 99% │ │
│  │    Detectors: WiFi BLE USB Network AirDrop            │ │
│  │    Threats (24h): 145   Last seen: 2m ago             │ │
│  │    [Configure] [Update] [View Logs] [Restart]         │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ 🟢 RPI5-DefCon          Platform: RPI5    Uptime: 95% │ │
│  │    Detectors: WiFi BLE USB Network                    │ │
│  │    Threats (24h): 89    Last seen: 5m ago             │ │
│  │    [Configure] [Update] [View Logs] [Restart]         │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ 🔴 RPI4-Seattle         Platform: RPI4    Uptime: 0%  │ │
│  │    Status: Offline (last seen: 2h ago)                │ │
│  │    [Investigate] [Alert History]                      │ │
│  └───────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
```

**Features:**
- Real-time sensor status
- Remote configuration updates
- Rule deployment
- Log viewer
- Performance metrics
- Alert configuration

---

## User Experience

### Scenario 1: First-Time User with RPI5

**User:** Security enthusiast with a Raspberry Pi 5, wants to detect threats at DefCon

**V1 Experience:**
1. Find GitHub repo
2. Read 30-page README
3. SSH to RPI
4. Run 20+ commands
5. Edit config files
6. Troubleshoot errors
7. 60 minutes later: sensor running
8. No dashboard access (requires VPS setup)

**V2 Experience:**
1. Visit dashboard.honeyman.com
2. Sign up / log in
3. Click "Add Sensor"
4. Copy one command
5. SSH to RPI, paste command
6. Wait 5 minutes
7. See sensor online on dashboard
8. Watch threats appear on map in real-time

**Time:** 5 minutes
**Commands:** 1
**Configuration files edited:** 0
**Technical skill required:** Beginner (can copy/paste)

---

### Scenario 2: Security Researcher Managing 20 Sensors

**User:** Researcher deploying sensors at multiple conferences

**V1 Experience:**
- Manually configure each sensor
- No way to see all sensors at once
- Update detection logic: SSH to each sensor, edit code
- Check sensor health: SSH to each sensor
- Collect data: Export Elasticsearch from each sensor

**V2 Experience:**
- Deploy all sensors with same onboarding flow
- View all 20 sensors on one dashboard
- Update rules once, auto-push to all sensors
- See health status at a glance
- Export all data from central dashboard

---

### Scenario 3: Updating Malware Signatures

**V1:**
```bash
# SSH to each sensor
ssh sensor1.local
cd /path/to/honeyman
# Edit Python code
vim src/detectors/usb_enhanced_detector.py
# Add new hash on line 567
# Restart service
sudo systemctl restart honeypot-usb-enhanced
# Repeat for 10 sensors...
```

**V2:**
```
1. Dashboard → Rules → USB Malware Detection
2. Click "Add Hash"
3. Paste: 9c5e8a8e8f4e3c5d7b2a1f6e9d8c7b6a...
4. Click "Save & Deploy"
5. All sensors updated in < 30 seconds
```

---

## Technical Highlights

### Agent Architecture

**Modular Design:**
```
honeyman-agent (Python package)
├── Core Agent (orchestration)
├── Plugin Manager (dynamic loading)
├── Detection Modules
│   ├── USB Detector
│   ├── WiFi Detector
│   ├── BLE Detector
│   ├── AirDrop Detector
│   └── Network Detector
├── Rule Engine (YAML-based)
├── Transport Layer (MQTT/HTTP/WebSocket)
└── Auto-updater
```

**Key Features:**
- **Auto-detection:** Identifies available hardware (WiFi adapter, Bluetooth, etc.)
- **Hot-reload:** Apply rule updates without restart
- **Offline queue:** Cache threats when dashboard unreachable
- **Self-healing:** Auto-restart on failures
- **Minimal footprint:** < 200MB RAM, < 5% CPU

---

### Dashboard Architecture

**Modern Stack:**
```
Frontend:
├── React 18 (UI framework)
├── TypeScript (type safety)
├── Leaflet.js (interactive maps)
├── Recharts (data visualization)
└── Material-UI (design system)

Backend:
├── Node.js + Express (REST API)
├── PostgreSQL + TimescaleDB (storage)
├── Redis (caching, real-time)
├── Mosquitto (MQTT broker)
└── Socket.IO (WebSocket)
```

**Performance:**
- Page load: < 2s
- Real-time updates: < 100ms latency
- Database queries: < 50ms (p95)
- Supports: 500+ concurrent sensors

---

### Database Design

**Time-Series Optimized:**
```sql
-- Hypertable for efficient time-series queries
CREATE TABLE threats (
    threat_id UUID PRIMARY KEY,
    sensor_id UUID,
    timestamp TIMESTAMPTZ,
    threat_type VARCHAR(100),
    threat_score FLOAT,
    geolocation GEOGRAPHY(POINT),
    ...
);

-- Automatic partitioning by time
SELECT create_hypertable('threats', 'timestamp',
    chunk_time_interval => INTERVAL '1 day'
);

-- Continuous aggregates (pre-computed analytics)
CREATE MATERIALIZED VIEW threats_hourly AS
SELECT
    time_bucket('1 hour', timestamp) as hour,
    sensor_id,
    COUNT(*) as threat_count,
    AVG(threat_score) as avg_score
FROM threats
GROUP BY hour, sensor_id;

-- Auto-refresh every hour
SELECT add_continuous_aggregate_policy(...);

-- Data retention (auto-delete old data)
SELECT add_retention_policy('threats', INTERVAL '90 days');
```

**Benefits:**
- 10x faster queries vs regular PostgreSQL
- Automatic data compression (75% space savings)
- Built-in downsampling
- Horizontal scalability

---

## Detection Capabilities

### All V1 Capabilities Maintained

| Detection Vector | Capabilities | V2 Status |
|------------------|--------------|-----------|
| **USB** | • 360+ malware hashes<br>• BadUSB signatures<br>• HID injection detection<br>• Filesystem scanning | ✅ Enhanced with rules |
| **WiFi** | • Evil twin detection<br>• Deauth attacks<br>• Beacon flooding<br>• Suspicious SSIDs | ✅ Enhanced with rules |
| **BLE** | • Flipper Zero detection<br>• Device spoofing<br>• RSSI analysis<br>• Behavior profiling | ✅ Enhanced with rules |
| **AirDrop** | • mDNS scanning<br>• Suspicious services<br>• TXT record analysis | ✅ Enhanced with rules |
| **Network** | • OpenCanary stack<br>• SSH/FTP/SMB/HTTP<br>• Port scan detection<br>• Brute force | ✅ Enhanced with rules |

### New Capabilities in V2

1. **Cross-Protocol Correlation**
   - Detect coordinated attacks across multiple vectors
   - Example: USB attack followed by WiFi exfiltration

2. **Behavioral Analysis**
   - Track device/network behavior over time
   - Detect anomalies based on historical patterns

3. **Threat Intelligence Integration**
   - Auto-update IOCs from threat feeds
   - Community rule sharing

4. **Machine Learning** (Future)
   - Auto-classification of unknown threats
   - Predictive threat modeling

---

## Dashboard Features

### 1. Overview Dashboard

**Real-Time Metrics:**
- Total threats (lifetime, 24h, 1h)
- Active sensors count
- Average threat score
- Threat velocity (per hour)

**Visualizations:**
- Threat activity timeline
- Threat type distribution (pie chart)
- Severity breakdown (bar chart)
- Geographic heat map

**Quick Actions:**
- Add new sensor
- Export threat data
- View critical alerts
- System health status

---

### 2. Threat Map

**Features:**
- Interactive world map (Leaflet.js)
- Cluster markers for dense areas
- Color-coded by severity
  - 🔴 Critical (score > 0.8)
  - 🟠 High (score > 0.6)
  - 🟡 Medium (score > 0.4)
  - 🟢 Low (score > 0.2)
- Click marker for threat details
- Filter by time, type, severity
- Heat map overlay
- Time-lapse playback

**Example:**
```
User clicks Las Vegas marker:

┌─────────────────────────────────────────┐
│  📍 Las Vegas, NV                       │
├─────────────────────────────────────────┤
│  Total Threats: 145                     │
│  Critical: 12   High: 45   Medium: 88  │
│                                         │
│  Top Threats:                           │
│  • Evil Twin AP (45 detections)        │
│  • USB Malware (12 detections)         │
│  • Port Scans (23 detections)          │
│                                         │
│  Active Sensors:                        │
│  • RPI5-DefCon-Main (98 threats)       │
│  • RPI5-DefCon-Backup (47 threats)     │
│                                         │
│  [View Details] [Filter] [Export]       │
└─────────────────────────────────────────┘
```

---

### 3. Sensors Management

**Grid/List View:**
- Sensor name, platform, status
- Capability badges (WiFi, BLE, USB, etc.)
- Last heartbeat time
- Uptime percentage
- Threat count (24h)

**Sensor Details:**
- System information (CPU, RAM, storage)
- Network configuration
- Enabled detectors
- Performance metrics
- Configuration viewer/editor

**Actions:**
- Update rules
- Restart sensor
- View logs (real-time)
- Edit configuration
- Download diagnostics
- Delete sensor

---

### 4. Threats Explorer

**Advanced Filtering:**
```
┌──────────────────────────────────────────────────────────┐
│  Filters                                                  │
├──────────────────────────────────────────────────────────┤
│  Time Range:    [Last 24 hours ▼]                        │
│  Sensor:        [All sensors ▼]                          │
│  Threat Type:   [☑ Malware ☑ Evil Twin ☐ Port Scan]     │
│  Risk Level:    [☑ Critical ☑ High ☐ Medium ☐ Low]      │
│  Score Range:   [0.7] ━━━━●━━━━ [1.0]                   │
│  Source IP:     [___________________]                     │
│                                                           │
│  [Apply Filters] [Reset] [Save as Preset]                │
└──────────────────────────────────────────────────────────┘
```

**Threat List:**
- Sortable columns (timestamp, score, type)
- Expandable rows for details
- Bulk actions (export, mark false positive)
- Timeline view option

**Threat Details:**
- Full event data
- Related threats (correlation)
- Sensor information
- Timeline context (30 min before/after)
- Mitigation recommendations
- Export options (JSON, PDF)

---

### 5. Analytics Dashboard

**Pre-built Reports:**
1. **Threat Trends**
   - Threats over time (hourly, daily, weekly)
   - Type distribution
   - Severity trends

2. **Sensor Performance**
   - Uptime statistics
   - Detection rates
   - False positive rates

3. **Geographic Analysis**
   - Threat distribution by country/city
   - Attack source mapping
   - Sensor coverage map

4. **Correlation Insights**
   - Cross-protocol attacks
   - Temporal patterns
   - Behavioral clusters

**Custom Queries:**
```sql
-- SQL editor for custom analytics
SELECT
    date_trunc('day', timestamp) as day,
    threat_type,
    COUNT(*) as count
FROM threats
WHERE sensor_id = 'uuid'
  AND timestamp > NOW() - INTERVAL '30 days'
GROUP BY day, threat_type
ORDER BY day DESC;
```

**Export Options:**
- CSV, JSON, PDF
- Scheduled reports (email)
- Grafana integration

---

### 6. Rules Management

**Rule Library:**
- Browse all detection rules
- Filter by category (USB, WiFi, BLE, etc.)
- Search by name, threat type
- Sort by match count, effectiveness

**Rule Editor:**
```yaml
# In-browser YAML editor with syntax highlighting

rule_id: custom_rule_001
name: "Custom Evil Twin Detection"
version: 1.0
enabled: true
category: wifi
threat_type: evil_twin
severity: high

conditions:
  operator: AND
  clauses:
    - type: ssid_match
      pattern: "^(DefCon|DEF CON)$"
    - type: signal_strength
      operator: greater_than
      value: -50

actions:
  - alert_dashboard
  - log_pcap

# [Test Rule] [Validate] [Save] [Deploy]
```

**Features:**
- Syntax validation
- Test against sample data
- Version history
- A/B testing
- Deploy to specific sensors or all
- Community rule marketplace (future)

---

### 7. Alerting & Integrations

**Alert Channels:**
- Email (SMTP)
- SMS (Twilio)
- Slack
- Discord
- Microsoft Teams
- PagerDuty
- Custom webhooks

**Alert Configuration:**
```json
{
  "name": "Critical Threat Alert",
  "enabled": true,
  "conditions": {
    "risk_level": "critical",
    "threat_score_min": 0.8
  },
  "channels": ["email", "slack"],
  "rate_limit_minutes": 60,
  "message_template": "🚨 Critical threat detected: {{threat_type}}"
}
```

**SIEM Integration:**
- Splunk (via HTTP Event Collector)
- ELK Stack (via Logstash)
- QRadar (via Syslog)
- Custom exporters

---

## Deployment Options

### Option 1: Hosted Dashboard (Easiest)

**Use Honeyman's hosted dashboard at dashboard.honeyman.com**

**Pros:**
- No infrastructure to manage
- Always up-to-date
- Automatic backups
- 99.9% uptime SLA

**Cons:**
- Requires internet connection
- Data stored on Honeyman servers
- Subscription cost (future)

**Setup:**
1. Create account at dashboard.honeyman.com
2. Add sensor via web UI
3. Run installer on RPI5
4. Done!

---

### Option 2: Self-Hosted Dashboard (Advanced)

**Run your own dashboard on a VPS or on-premises server**

**Pros:**
- Full control over data
- Customizable
- No external dependencies
- Free (open source)

**Cons:**
- Requires server management
- Manual updates
- Backup responsibility

**Setup:**
```bash
# On your VPS
git clone https://github.com/honeyman/honeyman-v2
cd honeyman-v2/dashboard-v2

# Configure environment
cp .env.example .env
nano .env  # Set passwords, keys, etc.

# Deploy with Docker Compose
docker-compose up -d

# Initialize database
docker-compose exec api npm run migrate

# Dashboard available at http://your-vps-ip:3000
```

**Requirements:**
- VPS with 2GB+ RAM
- 20GB+ disk space
- Public IP (for sensors to connect)
- Domain name (optional, recommended)

---

### Option 3: Kubernetes Deployment (Enterprise)

**Deploy on Kubernetes for high availability**

**Pros:**
- Horizontal scaling
- Auto-healing
- Load balancing
- Enterprise-grade reliability

**Cons:**
- Complex setup
- Kubernetes knowledge required
- Higher resource requirements

**Setup:**
```bash
# Deploy to Kubernetes cluster
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/mosquitto.yaml
kubectl apply -f k8s/api.yaml
kubectl apply -f k8s/frontend.yaml
kubectl apply -f k8s/ingress.yaml
```

---

## Roadmap

### Phase 1: Foundation (Months 1-2)
- ✅ Architecture design
- ✅ Database schema
- 🔄 Agent core implementation
- 🔄 Protocol abstraction layer
- 🔄 Rule engine prototype
- 🔄 MQTT broker setup

**Deliverable:** Working agent prototype with MQTT communication

---

### Phase 2: Agent Development (Months 2-3)
- 🔄 Refactor USB detector to use rules
- 🔄 Refactor WiFi detector to use rules
- 🔄 Refactor BLE detector to use rules
- 🔄 OpenCanary integration
- 🔄 Auto-updater implementation
- 🔄 Installer script

**Deliverable:** Feature-complete agent with all V1 detection capabilities

---

### Phase 3: Dashboard Backend (Months 3-4)
- 🔄 PostgreSQL + TimescaleDB setup
- 🔄 API endpoints implementation
- 🔄 MQTT broker integration
- 🔄 Geolocation enrichment
- 🔄 Sensor management API
- 🔄 Rule management API
- 🔄 Analytics queries

**Deliverable:** Functional backend API with all endpoints

---

### Phase 4: Dashboard Frontend (Months 4-5)
- 🔄 React application setup
- 🔄 Interactive map component
- 🔄 Sensor management UI
- 🔄 Threat explorer
- 🔄 Analytics dashboard
- 🔄 Rule editor
- 🔄 Alert configuration

**Deliverable:** Complete web dashboard

---

### Phase 5: Onboarding & UX (Month 5-6)
- 🔄 Onboarding portal
- 🔄 Installer script refinement
- 🔄 Documentation
- 🔄 Video tutorials
- 🔄 User testing
- 🔄 Beta program

**Deliverable:** Production-ready platform

---

### Phase 6: Advanced Features (Month 6+)
- 📋 A/B testing framework
- 📋 Machine learning integration
- 📋 Advanced correlation engine
- 📋 Community rule marketplace
- 📋 Threat prediction
- 📋 Attack attribution

**Deliverable:** Enterprise-grade threat intelligence platform

---

## FAQ

### General Questions

**Q: Will V2 replace V1?**
A: Yes, eventually. V2 includes all V1 capabilities plus many improvements. V1 will be maintained for 6 months after V2 release, then deprecated.

**Q: Can I migrate my V1 sensors to V2?**
A: Yes! We provide migration scripts and parallel deployment options. See [ARCHITECTURE-V2.md](ARCHITECTURE-V2.md) for details.

**Q: Is V2 backward compatible with V1?**
A: The dashboard can receive data from V1 agents in compatibility mode, but full features require V2 agent.

**Q: When will V2 be released?**
A: Target: 6 months from project start. Beta program earlier.

---

### Technical Questions

**Q: What platforms are supported?**
A:
- **Tested:** Raspberry Pi 4, Raspberry Pi 5, Ubuntu 22.04+
- **Should work:** Debian, Arch Linux, Fedora
- **Future:** Android, macOS, Windows (WSL)

**Q: What are the minimum requirements?**
A:
- **Raspberry Pi:** RPI4 with 4GB RAM (RPI5 with 8GB recommended)
- **Storage:** 32GB minimum, 64GB+ recommended
- **Network:** Internet connection for dashboard communication

**Q: Can I run without internet?**
A: Yes, with limitations:
- Agent runs locally and stores threats
- No real-time dashboard updates
- Automatic rule updates disabled
- Data syncs when connection restored

**Q: How much bandwidth does it use?**
A:
- **MQTT mode:** ~100-500 KB/day per sensor
- **HTTP mode:** ~1-5 MB/day per sensor
- **Heartbeats:** ~50 KB/day

**Q: Is it secure?**
A: Yes:
- All communications use TLS 1.3
- API key authentication
- MQTT ACLs for topic isolation
- Database encryption at rest (optional)
- Regular security audits

**Q: Can I customize detection rules?**
A: Absolutely! That's a core V2 feature. Edit rules via dashboard UI or write custom YAML rules.

**Q: Does it support multiple users?**
A: Yes, with role-based access control:
- **Admin:** Full control
- **Analyst:** View/edit rules, view threats
- **Viewer:** Read-only access

---

### Deployment Questions

**Q: Can I deploy multiple sensors from one dashboard?**
A: Yes! That's the primary use case. Manage hundreds of sensors from one dashboard.

**Q: Do I need a VPS?**
A:
- **Hosted option:** No VPS needed (use dashboard.honeyman.com)
- **Self-hosted:** Yes, requires VPS or on-premises server

**Q: What cloud providers are supported?**
A: Any provider that supports Docker or Kubernetes:
- AWS, GCP, Azure
- DigitalOcean, Linode
- Hetzner, OVH
- On-premises

**Q: Can sensors communicate peer-to-peer?**
A: Not in V2.0. Future feature for mesh deployments.

---

### Data & Privacy Questions

**Q: Where is my data stored?**
A:
- **Hosted:** On Honeyman's servers (encrypted)
- **Self-hosted:** Your VPS/server (you control)

**Q: Is my data private?**
A: Yes:
- **Hosted:** We never share your data. See privacy policy.
- **Self-hosted:** You have complete control.

**Q: Can I export my data?**
A: Yes! Export via:
- Dashboard UI (CSV, JSON, PDF)
- API (programmatic access)
- Direct database access (self-hosted)

**Q: How long is data retained?**
A: Configurable:
- Default: 90 days
- Can extend to 1+ year
- Automatic archival available

**Q: Is data anonymized?**
A: Configurable:
- Option to redact PII (IP addresses, device IDs)
- Geographic data can be coarsened (city-level vs exact coordinates)

---

### Pricing Questions

**Q: Is V2 free?**
A: V2 is open source (MIT license). Free forever for self-hosted deployments.

**Q: What about the hosted dashboard?**
A: Pricing TBD. Will have a free tier for hobbyists and paid tiers for advanced features.

**Q: Do I need to pay for sensors?**
A: No. Agent software is free and open source.

---

### Development Questions

**Q: Can I contribute to V2?**
A: Yes! We welcome contributions:
- Code (agent, dashboard, rules)
- Documentation
- Bug reports
- Feature requests
- Detection rules

**Q: Is the code open source?**
A: Yes, MIT license. Fork, modify, distribute freely.

**Q: What programming languages?**
A:
- **Agent:** Python 3.8+
- **Dashboard backend:** Node.js (JavaScript)
- **Dashboard frontend:** React (TypeScript)
- **Rules:** YAML

**Q: How can I write custom detectors?**
A: Implement the `BaseDetector` interface:
```python
from honeyman.detectors import BaseDetector

class MyCustomDetector(BaseDetector):
    def initialize(self):
        # Setup code
        pass

    def detect(self):
        # Main detection loop
        while self.running:
            event = self.get_event()
            self.evaluate_event(event)
```

---

## Getting Started

### I'm a new user with a Raspberry Pi 5

**Quick Start:**
1. Visit **dashboard.honeyman.com** (or your self-hosted URL)
2. Sign up / log in
3. Click **"Add New Sensor"**
4. Copy the installation command
5. SSH to your RPI5
6. Paste and run the command
7. Wait ~5 minutes
8. See your sensor online in the dashboard
9. Watch threats appear in real-time!

**Next Steps:**
- Explore the threat map
- Configure alerting (Slack, email)
- Customize detection rules
- Deploy more sensors

---

### I'm upgrading from V1

**Migration Guide:**
1. Read [ARCHITECTURE-V2.md](ARCHITECTURE-V2.md) - Migration section
2. Choose migration strategy (parallel or in-place)
3. Deploy V2 dashboard infrastructure
4. Migrate sensors one-by-one or in batches
5. Validate data and functionality
6. Deprecate V1

**Support:**
- Migration scripts provided
- Community forums
- 1-on-1 migration assistance (enterprise)

---

### I'm a developer wanting to contribute

**Development Setup:**
```bash
# Clone repo
git clone https://github.com/honeyman/honeyman-v2
cd honeyman-v2

# Agent development
cd agent
python3 -m venv venv
source venv/bin/activate
pip install -e .
pytest tests/

# Dashboard development
cd ../dashboard-v2

# Backend
cd backend
npm install
npm run dev

# Frontend
cd ../frontend
npm install
npm start
```

**Contribution Guidelines:**
- Read CONTRIBUTING.md
- Check open issues for tasks
- Submit PRs with tests
- Follow code style guidelines

---

## Conclusion

Honeyman V2 transforms threat detection from a technical project into an accessible platform. Whether you're deploying one sensor at a conference or managing dozens across the globe, V2 provides:

✅ **Simplicity:** One-command deployment
✅ **Scalability:** Hundreds of sensors from one dashboard
✅ **Intelligence:** Advanced analytics and geolocation
✅ **Flexibility:** Multi-protocol support for any environment
✅ **Maintainability:** Rule-based detection with live updates

**The vision:** Make advanced threat detection accessible to everyone, from hobbyists to enterprises.

---

## Resources

- **Architecture Details:** [ARCHITECTURE-V2.md](ARCHITECTURE-V2.md)
- **Current System (V1):** [README.md](README.md)
- **Capabilities:** [CAPABILITIES.md](CAPABILITIES.md)
- **GitHub Repo:** https://github.com/honeyman/honeyman-v2 (coming soon)
- **Community:** Discord, Forums (links TBD)

---

**Questions? Feedback?**

Open an issue on GitHub or join our community forums!

**Last Updated:** 2025-10-23
**Document Version:** 1.0
