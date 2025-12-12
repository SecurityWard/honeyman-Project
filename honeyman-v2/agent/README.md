# Honeyman Agent V2

Multi-vector threat detection agent for Raspberry Pi and embedded systems.

## Features

- **Modular Architecture**: Plugin-based detector system
- **Rule-Based Detection**: YAML rules with hot-reload support
- **Multi-Protocol Transport**: MQTT (primary) + HTTP fallback
- **Geolocation**: GPS → WiFi → IP fallback chain
- **Offline Resilience**: Automatic queueing when dashboard unreachable
- **Self-Monitoring**: Heartbeat service with system metrics

## Installation

### From PyPI
```bash
pip install honeyman-agent
```

### From Source
```bash
cd agent
pip install -e .
```

## Quick Start

### 1. Create Configuration

```bash
sudo mkdir -p /etc/honeyman
sudo nano /etc/honeyman/config.yaml
```

```yaml
sensor_id: sensor_001
sensor_name: "DefCon-2025-Portable"

transport:
  protocol: mqtt
  mqtt:
    broker: mqtt.honeyman.com
    port: 8883
    username: sensor_001
    password: <your-password>
    use_tls: true

detectors:
  usb: true
  wifi: true
  bluetooth: true
  network: true
  airdrop: false

rules_dir: /etc/honeyman/rules
```

### 2. Download Detection Rules

```bash
sudo mkdir -p /etc/honeyman/rules
# Download rules from dashboard or use samples
```

### 3. Run Agent

```bash
# Run directly
honeyman-agent -c /etc/honeyman/config.yaml

# Or as systemd service
sudo systemctl start honeyman-agent
```

## Architecture

```
honeyman/
├── agent.py                  # Main orchestrator
├── core/
│   ├── config_manager.py     # Configuration management
│   ├── plugin_manager.py     # Dynamic detector loading
│   └── heartbeat.py          # Health reporting
├── detectors/
│   ├── base_detector.py      # Abstract base class
│   ├── usb_detector.py       # USB threat detection
│   ├── wifi_detector.py      # WiFi attack detection
│   ├── ble_detector.py       # Bluetooth LE detection
│   ├── airdrop_detector.py   # AirDrop abuse detection
│   └── network_detector.py   # Network honeypot
├── transport/
│   ├── protocol_handler.py   # Multi-protocol abstraction
│   ├── mqtt_client.py        # MQTT transport
│   └── http_client.py        # HTTP fallback
├── rules/
│   ├── rule_engine.py        # Rule evaluation engine
│   ├── rule_loader.py        # YAML parser
│   └── evaluators/           # Condition evaluators
└── services/
    └── location_service.py   # Geolocation