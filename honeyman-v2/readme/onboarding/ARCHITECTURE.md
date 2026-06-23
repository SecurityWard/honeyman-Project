# HONEYMAN V2 - Complete Architecture

## Overview

Honeyman V2 is a portable, modular honeypot and threat detection system designed for Raspberry Pi. It features **zero-account sensor onboarding** — anyone can deploy a sensor with a single command, and it automatically registers with the global dashboard.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          USER'S RASPBERRY PI                                │
│                                                                             │
│  $ curl -sSL https://honeymanproject.com/install | bash                            │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    INTERACTIVE SETUP                                 │   │
│  │  • User picks name: "defcon-hotel"                                  │   │
│  │  • User picks location: "Las Vegas, NV"                             │   │
│  │  • Hardware auto-detected                                           │   │
│  │  • User selects modules: [USB] [BLE] [WiFi] [AirDrop] [Network]    │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│  ┌──────────────────────────────▼──────────────────────────────────────┐   │
│  │                    DETECTION MODULES (Modular)                       │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       │   │
│  │  │   USB   │ │   BLE   │ │  WiFi   │ │ AirDrop │ │ Network │       │   │
│  │  │Detector │ │Detector │ │Detector │ │Detector │ │Honeypot │       │   │
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘       │   │
│  │       └───────────┴───────────┴───────────┴───────────┘             │   │
│  │                               │                                      │   │
│  │                    ┌──────────▼──────────┐                          │   │
│  │                    │    ALERT ENGINE     │◄── /etc/honeyman/rules/  │   │
│  │                    │  (Hot-Reload YAML)  │    (inotify watched)     │   │
│  │                    └──────────┬──────────┘                          │   │
│  │                    ┌──────────▼──────────┐                          │   │
│  │                    │   SQLite Buffer     │ (Offline resilience)     │   │
│  │                    └──────────┬──────────┘                          │   │
│  └───────────────────────────────┼──────────────────────────────────────┘   │
└──────────────────────────────────┼──────────────────────────────────────────┘
                                   │
                    HTTPS POST     │    MQTT/TLS 1.3
                  (registration)   │    (events)
                                   │
┌──────────────────────────────────┼──────────────────────────────────────────┐
│                              VPS LAYER                                      │
│                                  │                                          │
│  ┌───────────────────────────────┴────────────────────────────────────┐    │
│  │                                                                     │    │
│  │  ┌─────────────────────┐         ┌─────────────────────┐          │    │
│  │  │  PROVISIONING API   │         │   MOSQUITTO BROKER  │          │    │
│  │  │  (Flask/FastAPI)    │────────▶│   (MQTT over TLS)   │          │    │
│  │  │                     │ Add ACL │                     │          │    │
│  │  │  POST /api/register │         │   Port 8883         │          │    │
│  │  │  • Generate ID      │         │   Dynamic ACL       │          │    │
│  │  │  • Generate secret  │         │   Per-sensor auth   │          │    │
│  │  │  • Return creds     │         │                     │          │    │
│  │  └─────────────────────┘         └──────────┬──────────┘          │    │
│  │                                              │                     │    │
│  │  ┌──────────────────────────────────────────┼─────────────────┐   │    │
│  │  │                     BACKEND SERVICES     │                 │   │    │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌────▼────────┐       │   │    │
│  │  │  │ TimescaleDB │  │    Redis    │  │   MQTT      │       │   │    │
│  │  │  │ (events +   │◄─│  (pub/sub)  │◄─│  Collector  │       │   │    │
│  │  │  │  sensors)   │  │             │  │             │       │   │    │
│  │  │  └──────┬──────┘  └──────┬──────┘  └─────────────┘       │   │    │
│  │  │         │                │                                │   │    │
│  │  │         └────────────────┴──────────┐                    │   │    │
│  │  │                                     │                    │   │    │
│  │  │                          ┌──────────▼──────────┐         │   │    │
│  │  │                          │     FLASK API      │         │   │    │
│  │  │                          │   + SSE Streaming  │         │   │    │
│  │  │                          └──────────┬─────────┘         │   │    │
│  │  └─────────────────────────────────────┼──────────────────┘   │    │
│  │                                        │                       │    │
│  └────────────────────────────────────────┼───────────────────────┘    │
│                                           │                            │
└───────────────────────────────────────────┼────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           GLOBAL DASHBOARD                                  │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │  🍯 HONEYMAN GLOBAL DASHBOARD                    47 sensors online    │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │                                                                       │ │
│  │   ┌─────────────────────────────────────────────────────────────┐    │ │
│  │   │                    WORLD MAP                                │    │ │
│  │   │              (Leaflet.js + Geo-location)                    │    │ │
│  │   │                                                             │    │ │
│  │   │    [US: 23 sensors]     [EU: 15 sensors]    [APAC: 9]      │    │ │
│  │   │         ●●●                  ●●                 ●          │    │ │
│  │   │                                                             │    │ │
│  │   └─────────────────────────────────────────────────────────────┘    │ │
│  │                                                                       │ │
│  │   THREAT FEED (Real-time)              │  VELOCITY: 12 events/hr    │ │
│  │   ┌────────────────────────────────────┴────────────────────────┐   │ │
│  │   │ 🔴 CRITICAL │ defcon-hotel-7x9k │ BadUSB    │ Las Vegas    │   │ │
│  │   │ 🟠 HIGH     │ coffee-2wq4       │ Flipper   │ Seattle      │   │ │
│  │   │ 🟡 MEDIUM   │ airport-m3np      │ Evil Twin │ Denver       │   │ │
│  │   └─────────────────────────────────────────────────────────────┘   │ │
│  │                                                                       │ │
│  │   SENSOR STATUS                                                       │ │
│  │   ┌─────────────────────────────────────────────────────────────┐   │ │
│  │   │ defcon-hotel-7x9k │ Las Vegas │ 🟢 │ USB,BLE,WiFi,Net     │   │ │
│  │   │ coffee-2wq4       │ Seattle   │ 🟢 │ USB,BLE,Net          │   │ │
│  │   │ airport-m3np      │ Denver    │ 🟡 │ USB,WiFi,AirDrop,Net │   │ │
│  │   └─────────────────────────────────────────────────────────────┘   │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Zero-Account Sensor Onboarding

### Design Principles

1. **No user accounts** — Sensors are anonymous, self-registering devices
2. **Single command install** — `curl ... | bash` with interactive setup
3. **Self-selected names** — User picks name, system adds random suffix for uniqueness
4. **Auto-provisioning** — Credentials generated server-side, no admin involvement
5. **Immediate dashboard appearance** — Sensor visible within seconds of registration

### Onboarding Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: User runs install command                               │
│ $ curl -sSL https://honeymanproject.com/install | bash                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: Interactive setup prompts                               │
│ • Enter sensor name: defcon-hotel                               │
│ • Enter location: Las Vegas, NV                                 │
│ • Select modules: [X] USB [X] BLE [X] WiFi [ ] AirDrop [X] Net │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: Script POSTs to provisioning API                        │
│ POST https://api.honeymanproject.com/v1/sensors/register               │
│ {                                                               │
│   "requested_name": "defcon-hotel",                             │
│   "location": "Las Vegas, NV",                                  │
│   "modules": ["usb", "ble", "wifi", "network"],                │
│   "hardware": {"model": "Pi 4", "ram_gb": 4, ...}              │
│ }                                                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: API provisions sensor                                   │
│ • Generates unique ID: defcon-hotel-7x9k                        │
│ • Generates secret: a7b9c2d4e6f8...                            │
│ • Adds credentials to Mosquitto ACL                             │
│ • Inserts sensor record in database                             │
│ • Returns credentials + broker info                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 5: Script configures local sensor                          │
│ • Writes /etc/honeyman/config.yaml                              │
│ • Writes /etc/honeyman/credentials                              │
│ • Enables selected module systemd services                      │
│ • Starts honeyman service                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 6: Sensor connects to MQTT broker                          │
│ • Authenticates with generated credentials                      │
│ • Publishes to honeypot/{sensor_id}/health                     │
│ • Appears on dashboard with green status                        │
└─────────────────────────────────────────────────────────────────┘
```

### Unique ID Generation

```
User input:    "defcon-hotel"
                    │
                    ▼
Sanitize:      "defcon-hotel" (lowercase, alphanum + hyphens, max 20 chars)
                    │
                    ▼
Add suffix:    "defcon-hotel" + "-" + "7x9k" (4 random chars)
                    │
                    ▼
Final ID:      "defcon-hotel-7x9k"
```

Suffix character set: `abcdefghjkmnpqrstuvwxyz23456789` (no ambiguous chars: 0/O, 1/l/I)

### Abuse Prevention

| Protection | Implementation |
|------------|----------------|
| Rate limiting | 10 registrations per IP per hour |
| Stale cleanup | Delete sensors with no heartbeat for 30 days |
| Anomaly detection | Flag sensors sending only garbage data |
| Resource limits | Max 1000 sensors total (adjustable) |

---

## MQTT Topic Structure

```
honeypot/
├── {sensor_id}/
│   ├── events          # Threat events (QoS 1)
│   ├── health          # Heartbeat + status (QoS 0, retained)
│   └── alerts          # High-severity events (QoS 1)
├── global/
│   └── announcements   # System-wide messages
└── control/
    ├── rules           # Rule updates (VPS → sensors)
    └── commands        # Remote commands (restart, update, etc.)
```

### Event Payload Schema

```json
{
  "event_id": "evt_a7b9c2d4",
  "sensor_id": "defcon-hotel-7x9k",
  "timestamp": "2025-11-15T14:23:45.123Z",
  "module": "usb",
  "event_type": "badusb_detected",
  "severity": "critical",
  "confidence": 0.95,
  "details": {
    "vendor_id": "1337",
    "product_id": "DEAD",
    "device_name": "USB Input Device",
    "threat_indicators": ["hid_interface", "suspicious_vid", "rapid_enumeration"]
  },
  "location": {
    "name": "Las Vegas, NV",
    "lat": 36.1699,
    "lon": -115.1398
  }
}
```

### Health Payload Schema

```json
{
  "sensor_id": "defcon-hotel-7x9k",
  "timestamp": "2025-11-15T14:23:45.123Z",
  "status": "online",
  "uptime_seconds": 86400,
  "modules": {
    "usb": "running",
    "ble": "running",
    "wifi": "running",
    "airdrop": "disabled",
    "network": "running"
  },
  "system": {
    "cpu_percent": 23.5,
    "memory_percent": 45.2,
    "disk_percent": 32.1,
    "temperature_c": 52.3
  },
  "stats": {
    "events_24h": 142,
    "alerts_24h": 3
  }
}
```

---

## Detection Modules

All modules are independent and can be enabled/disabled per-sensor.

### Module Compatibility Matrix

| Module | Pi Zero W | Pi Zero 2 W | Pi 3B+ | Pi 4 | Pi 5 |
|--------|-----------|-------------|--------|------|------|
| USB | ✓ | ✓ | ✓ | ✓ | ✓ |
| BLE | ✗ | ✓ | ✓ | ✓ | ✓ |
| WiFi | ✓* | ✓* | ✓ | ✓ | ✓ |
| AirDrop | ✓* | ✓* | ✓ | ✓ | ✓ |
| Network | ✓ | ✓ | ✓ | ✓ | ✓ |

*\* Requires external WiFi adapter with monitor mode*

### Detection Capabilities

#### USB Module
- BadUSB / Rubber Ducky detection (95% confidence)
- OMG Cable detection (90% confidence)
- HID injection timing analysis (85% confidence)
- Malicious file signature scanning (80% confidence)
- Process spawn monitoring (85% confidence)

#### BLE Module
- Flipper Zero identification (90% confidence)
- MAC spoofing detection (80% confidence)
- Beacon flooding detection (85% confidence)
- Evil twin BLE detection (75% confidence)
- BLE spam detection (90% confidence)

#### WiFi Module
- Evil Twin AP detection (85% confidence)
- Deauthentication attacks (90% confidence)
- Beacon flooding (80% confidence)
- Rogue AP detection (75% confidence)
- WPS attacks (85% confidence)

#### AirDrop Module
- Bonjour/mDNS abuse (75% confidence)
- AWDL exploitation (70% confidence)
- Service flood detection (80% confidence)
- Name spoofing (70% confidence)

#### Network Module (OpenCanary)
- SSH brute force (95% confidence)
- HTTP credential harvesting (95% confidence)
- SMB enumeration (90% confidence)
- Telnet login attempts (95% confidence)
- FTP/MySQL/Redis probing (90% confidence)

---

## Alert Engine

### Separation of Concerns

```
┌─────────────────────┐     ┌─────────────────────┐
│  DETECTION MODULES  │     │    ALERT ENGINE     │
│  (Python scripts)   │────▶│   (Rule processor)  │
│                     │     │                     │
│  • Detect threats   │     │  • Evaluate rules   │
│  • Calculate scores │     │  • Determine action │
│  • Emit raw events  │     │  • Route alerts     │
└─────────────────────┘     └─────────────────────┘
         │                           │
         │                           ▼
         │                  ┌─────────────────────┐
         │                  │   /etc/honeyman/    │
         │                  │   rules/*.yaml      │
         │                  │                     │
         │                  │  (inotify watched,  │
         │                  │   hot-reload)       │
         │                  └─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Detection script   │
│  outputs raw event  │
│  to alert engine    │
│  via unix socket    │
└─────────────────────┘
```

### Rule File Format

```yaml
# /etc/honeyman/rules/usb_rules.yaml
version: 1
module: usb

rules:
  - name: badusb_critical
    description: "BadUSB device with high confidence"
    conditions:
      all:
        - field: threat_score
          operator: ">="
          value: 0.8
        - field: device_type
          operator: "=="
          value: "hid"
    severity: critical
    actions:
      - mqtt_publish
      - local_log
      - webhook
    cooldown_seconds: 60

  - name: suspicious_usb_device
    description: "USB device with suspicious indicators"
    conditions:
      any:
        - field: vendor_id
          operator: "in"
          value: ["1337", "DEAD", "BEEF", "FFFF"]
        - field: device_name
          operator: "contains"
          value: ["rubber", "ducky", "flipper", "badusb"]
    severity: high
    actions:
      - mqtt_publish
      - local_log
    cooldown_seconds: 30
```

### Hot-Reload Mechanism

```python
# Alert engine watches rule files with inotify
# On change: reload rules without restart

import inotify.adapters

def watch_rules():
    i = inotify.adapters.Inotify()
    i.add_watch('/etc/honeyman/rules')
    
    for event in i.event_gen(yield_nones=False):
        (_, type_names, path, filename) = event
        if 'IN_CLOSE_WRITE' in type_names and filename.endswith('.yaml'):
            reload_rules(f"{path}/{filename}")
```

---

## Global Dashboard Features

### Map Visualization
- Interactive world map (Leaflet.js)
- Sensor markers with status colors (green/yellow/red)
- Threat heat map overlay
- Click sensor to see details
- Cluster view for dense areas

### Threat Feed
- Real-time event stream (SSE)
- Color-coded by severity
- Filterable by: module, severity, sensor, time range
- Click to expand full event details

### Attack Velocity
- Events per minute/hour/day charts
- Trend indicators (↑ increasing, ↓ decreasing, → stable)
- Burst detection alerts

### Sensor Status
- Online/offline/degraded indicators
- Last heartbeat timestamp
- Active modules list
- System health (CPU, memory, temp)
- Events in last 24h

---

## File Structure

```
/etc/honeyman/
├── config.yaml              # Main configuration
├── credentials              # Sensor ID + secret (chmod 600)
└── rules/                   # Alert rules (hot-reload)
    ├── usb_rules.yaml
    ├── ble_rules.yaml
    ├── wifi_rules.yaml
    ├── airdrop_rules.yaml
    └── network_rules.yaml

/opt/honeyman/
├── bin/
│   ├── honeyman             # Main controller
│   ├── usb_detector.py
│   ├── ble_detector.py
│   ├── wifi_detector.py
│   ├── airdrop_detector.py
│   └── alert_engine.py
├── lib/                     # Shared libraries
└── share/
    └── yara/                # YARA rules for USB detection

/var/lib/honeyman/
├── honeyman.db              # SQLite buffer for offline events
└── state/                   # Module state files

/var/log/honeyman/
├── honeyman.log             # Main log
├── alerts.log               # Alert-specific log
└── modules/                 # Per-module logs
```

---

## VPS Components

### Required Services

| Service | Purpose | Port |
|---------|---------|------|
| Provisioning API | Sensor registration | 443 (HTTPS) |
| Mosquitto | MQTT broker | 8883 (TLS) |
| TimescaleDB | Event storage | 5432 (internal) |
| Redis | Pub/sub for dashboard | 6379 (internal) |
| Dashboard API | REST + SSE | 443 (HTTPS) |
| Nginx | Reverse proxy | 80/443 |

### Deployment

```bash
# VPS setup (Docker Compose)
docker-compose -f docker-compose.vps.yml up -d
```

---

## Security Considerations

### Sensor Security
- Credentials stored with chmod 600
- TLS 1.3 for all MQTT connections
- SQLite buffer encrypted at rest
- No inbound ports required on sensor

### VPS Security
- Rate limiting on registration API
- Per-sensor MQTT ACLs (can only publish to own topics)
- Automatic cleanup of stale sensors
- No sensitive data in MQTT payloads

### Data Privacy
- No user accounts = no PII
- Location is optional and self-reported
- Sensor IDs are pseudonymous
- Events contain only threat data, not user data
