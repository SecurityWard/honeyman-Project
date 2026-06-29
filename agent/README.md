# Honeyman Agent

Multi-vector threat detection agent for Raspberry Pi and embedded Linux.

## Features

- **Modular detectors**: USB, WiFi, BLE, AirDrop, Network honeypot
- **YAML rule engine** — rules under `/etc/honeyman/rules/` load at agent startup. Drop in a new YAML or edit an existing one, then `sudo systemctl restart honeyman-agent` to pick it up.
- **HTTPS + per-sensor API key** transport (MQTT optional)
- **Geolocation chain**: operator-pinned manual → GPS via `gpsd` → WiFi positioning via Mozilla Location Service (or Google with your key) → IP fallback. Every threat carries `accuracy_meters` + `location_method` so the dashboard can draw a confidence circle
- **Offline resilience**: SQLite-backed FIFO buffer at `/var/lib/honeyman/buffer.db` — survives agent restarts
- **Heartbeat** with system metrics + current location, so idle sensors stay on the map

## Installation

### From source

```bash
cd agent
pip install -e .
```

### Production deploy

Use the install script:

```bash
curl -sSL https://honeymanproject.com/install | bash
```

It self-registers the sensor with the backend, captures the one-time API key, and sets up systemd. See `deployment/install.sh`.

## Quick Start (manual)

### 1. Register the sensor

```bash
curl -X POST https://api.honeymanproject.com/api/v2/sensors/register \
  -H 'Content-Type: application/json' \
  -d '{"requested_name": "test-pi", "capabilities": {"usb": true, "wifi": false}}'
```

The response includes a one-time `api_key`. Save it now - it cannot be retrieved again.

### 2. Write the API key to disk (mode 0600)

```bash
sudo mkdir -p /etc/honeyman
echo 'hms_xxxxxxxxxxxxxxxxxxxxxxxx' | sudo tee /etc/honeyman/api_key > /dev/null
sudo chmod 600 /etc/honeyman/api_key
```

### 3. Drop a config

```bash
sudo cp example_config.yaml /etc/honeyman/config.yaml
sudo $EDITOR /etc/honeyman/config.yaml   # set sensor_id from the registration response
```

### 4. Run

```bash
honeyman-agent -c /etc/honeyman/config.yaml --verbose
```

The first heartbeat should appear on the dashboard within ~60 seconds.

## Architecture

```
honeyman/
  agent.py                  Main orchestrator
  core/
    config_manager.py       YAML config loader
    plugin_manager.py       Detector loading
    heartbeat.py            Periodic POST /sensors/{id}/heartbeat
  detectors/
    base_detector.py        Abstract base + create_threat() envelope
    usb_detector.py
    wifi_detector.py
    ble_detector.py
    airdrop_detector.py
    network_detector.py
  transport/
    protocol_handler.py     HTTPS-default multi-protocol mux
    http_client.py          HTTPS+Bearer-API-key client
    mqtt_client.py          Optional MQTT client (only inited when configured)
  rules/
    rule_engine.py          Rule evaluation
    rule_loader.py          YAML parser
    evaluators/             Condition evaluators
  services/
    location_service.py     GPS / WiFi / IP geolocation
```

## Configuration

See [`example_config.yaml`](example_config.yaml). Key fields:

| Field | Purpose |
|---|---|
| `sensor_id` | Returned by `/sensors/register`, used in heartbeat URL |
| `transport.protocol` | `https` (default) or `mqtt` |
| `transport.https.api_key_file` | Path to a file containing the plaintext API key (mode 0600) |
| `transport.https.base_url` | Backend host, e.g. `https://api.honeymanproject.com` |
| `detectors.<name>` | Toggle per detector; install.sh sets these from detected hardware |
| `rules_dir` | Directory of YAML rules; the engine watches it for changes |

## API key handling

The agent reads the API key from a file (default `/etc/honeyman/api_key`) at startup. The plaintext is sent as `Authorization: Bearer <key>` on every write. The backend stores only a SHA256 hash and rejects any request whose hash does not match - and additionally verifies the key belongs to the `sensor_id` in the path or payload.

If the key file is missing the agent will log a warning at startup and POSTs will fail with 401. To rotate a key, the operator deletes the sensor on the backend (manually for now), re-runs the install script, and replaces the file.

## Threat payload schema

`BaseDetector.create_threat()` produces a dict matching the backend's `ThreatCreate` schema directly:

```python
{
    "timestamp":       "2026-05-09T22:00:00.000",
    "sensor_id":       "defcon-hotel-7x9k",
    "threat_type":     "usb_rubber_ducky",
    "detector_type":   "usb",                # one of: usb, wifi, ble, network, airdrop
    "severity":        "critical",           # derived from rule weights
    "threat_score":    0.95,
    "confidence":      0.98,                 # max across matched rules
    "matched_rules": [
        {"rule_id": "usb_rubber_ducky_001", "name": "...", "severity": "critical", "confidence": 0.98}
    ],
    "raw_event":       { ... },              # original event from the detector
    "mitre_tactics":   ["TA0008"],           # parsed from rule metadata
    "mitre_techniques":["T1200"],
    "latitude":        37.7749,              # top-level - NOT nested
    "longitude":       -122.4194,
    "city":            "San Francisco",
    "country":         "US",
    "device_name":     "...",                # optional, populated when event has them
    "device_mac":      "...",
    "device_ip":       "...",
    "src_host":        "...", "src_port": ..., "dst_host": "...", "dst_port": ...,
}
```

Detectors emit raw `event` dicts; the base class enriches with location, severity, MITRE tags, and ships via `transport.send(threat, topic='threats')`.

## Tests

```bash
pip install -e .
python -m honeyman.agent --config /etc/honeyman/config.yaml --verbose

# Standalone detector smoke tests:
python test_usb_detector.py
python test_wifi_detector.py
python test_ble_detector.py
python test_network_detector.py
python test_airdrop_detector.py
```

## Status

See `../../PROJECT-PLAN.md` at the repo root for current phase and roadmap.
