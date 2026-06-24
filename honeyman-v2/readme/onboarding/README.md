# Honeyman — Zero-Account Sensor Onboarding Architecture

## Overview

This directory contains the architecture implementing **zero-account sensor onboarding**. Users can deploy sensors without creating accounts — sensors self-register with a single command.

## Key Design Decisions

### 1. No User Accounts
- Sensors are anonymous, self-registering devices
- No PII collected
- No authentication management needed

### 2. Self-Selected Names with Random Suffix
- User picks a friendly name: `defcon-hotel`
- System adds random suffix: `defcon-hotel-7x9k`
- Guarantees uniqueness without coordination

### 3. Separated Alert Logic
- Detection scripts emit raw events
- Alert engine evaluates rules from YAML files
- Rules can be updated on-the-fly via inotify
- Rules can be pushed from VPS via MQTT control channel

### 4. Modular Detection
- Each module (USB, BLE, WiFi, AirDrop, Network) is independent
- Modules enable/disable based on detected hardware
- Works on any Raspberry Pi model

## Directory Structure

```
v2_architecture/
├── ARCHITECTURE.md          # Complete architecture documentation
├── README.md                 # This file
│
├── sensor/                   # Raspberry Pi sensor components
│   └── install.sh           # One-command installer with interactive setup
│
└── vps/                      # VPS/cloud components
    ├── docker-compose.yml   # Full VPS deployment
    ├── provisioning_api.py  # Sensor registration API
    │
    ├── provisioning/
    │   └── requirements.txt # Python dependencies
    │
    └── mosquitto/
        ├── mosquitto.conf   # MQTT broker config
        └── acl              # Access control list template
```

## Onboarding Flow

```
User runs:
  curl -sSL https://honeymanproject.com/install | bash
       │
       ▼
┌─────────────────────────────────────────┐
│  Interactive Setup                       │
│  • Enter name: "defcon-hotel"           │
│  • Enter location: "Las Vegas"          │
│  • Select modules: USB, BLE, WiFi, Net  │
└─────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│  POST /api/v1/sensors/register          │
│  {                                       │
│    "requested_name": "defcon-hotel",    │
│    "location": "Las Vegas",             │
│    "modules": ["usb","ble","wifi","net"]│
│  }                                       │
└─────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│  API Response                            │
│  {                                       │
│    "sensor_id": "defcon-hotel-7x9k",    │
│    "secret": "a7b9c2d4...",             │
│    "broker": {...}                       │
│  }                                       │
└─────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│  Sensor connects to MQTT broker          │
│  Appears on dashboard immediately        │
└─────────────────────────────────────────┘
```

## API Endpoints

### Provisioning API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/sensors/register` | Register new sensor (rate limited) |
| GET | `/api/v1/sensors` | List all sensors |
| GET | `/api/v1/sensors/<id>` | Get sensor details |
| DELETE | `/api/v1/sensors/<id>` | Remove sensor |
| POST | `/api/v1/sensors/<id>/heartbeat` | Update last_seen |
| GET | `/api/v1/stats` | Global statistics |
| GET | `/api/v1/health` | Health check |

### Registration Request

```json
{
  "requested_name": "defcon-hotel",
  "location": "Las Vegas, NV",
  "latitude": 36.1699,
  "longitude": -115.1398,
  "modules": ["usb", "ble", "wifi", "airdrop", "network"],
  "hardware": {
    "model": "Raspberry Pi 4",
    "ram_gb": 4,
    "has_ble": true,
    "has_wifi": true,
    "has_wifi_monitor": true
  }
}
```

### Registration Response

```json
{
  "sensor_id": "defcon-hotel-7x9k",
  "secret": "a7b9c2d4e6f8901234567890abcdef...",
  "broker": {
    "host": "broker.honeymanproject.com",
    "port": 8883,
    "ca_cert": "-----BEGIN CERTIFICATE-----..."
  },
  "topics": {
    "events": "honeypot/defcon-hotel-7x9k/events",
    "health": "honeypot/defcon-hotel-7x9k/health",
    "alerts": "honeypot/defcon-hotel-7x9k/alerts"
  },
  "dashboard_url": "https://dashboard.honeymanproject.com/sensor/defcon-hotel-7x9k"
}
```

## MQTT Topics

```
honeypot/
├── {sensor_id}/
│   ├── events          # Threat events
│   ├── health          # Heartbeat (retained)
│   └── alerts          # High-severity events
├── global/
│   └── announcements   # System-wide messages
└── control/
    ├── rules           # Rule updates
    └── commands        # Remote commands
```

## Alert Rules Format

Rules are YAML files in `/etc/honeyman/rules/`:

```yaml
version: 1
module: usb

rules:
  - name: badusb_critical
    description: "BadUSB device detected"
    conditions:
      all:
        - field: threat_score
          operator: ">="
          value: 0.8
    severity: critical
    actions: [mqtt_publish, local_log]
    cooldown_seconds: 60
```

Rules support:
- `all` (AND) and `any` (OR) condition groups
- Operators: `==`, `!=`, `>`, `>=`, `<`, `<=`, `in`, `contains`
- Actions: `mqtt_publish`, `local_log`, `webhook`, `email`
- Cooldown to prevent alert storms

## Abuse Prevention

| Protection | Implementation |
|------------|----------------|
| Rate limiting | 10 registrations per IP per hour |
| Stale cleanup | Auto-delete sensors silent for 30 days |
| Resource limits | Max 1000 sensors (configurable) |

## Dashboard Features

- **Geo-location map** with sensor markers
- **Threat feed** with severity coloring
- **Attack velocity** graphs
- **Sensor status** (online/offline/degraded)
- **Module status** per sensor

## What Still Needs Implementation

1. **MQTT Collector** - Service that subscribes to `honeypot/#` and writes to TimescaleDB
2. **Dashboard Frontend** - React app with Leaflet.js maps
3. **Alert Engine** - Rule processor with inotify file watching
4. **Detection Modules** - The actual USB, BLE, WiFi, AirDrop, Network detectors
5. **Rule Distribution** - MQTT-based rule push from VPS to sensors

## Integration with Existing Code

The existing detection scripts in the project should be integrated:
- `enhanced_usb_detector.py` → USB module
- `enhanced_ble_detector.py` → BLE module
- `wifi_detector_component.sh` → WiFi module
- `airdrop_detector_component.sh` → AirDrop module
- `network_honeypot_component.sh` → Network module

These need to be modified to:
1. Output events to the alert engine (via unix socket or queue)
2. Read configuration from `/etc/honeyman/config.yaml`
3. Respect module enable/disable flags
