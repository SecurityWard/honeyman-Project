# Changelog

All notable changes to the Honeyman Project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### V2 Phase A / B / C — 2026-05

**Phase A — End-to-end transport, schema alignment, API-key auth**
- Agent: HTTPS+API-key is now the default transport. MQTT moved to opt-in (`transport.protocol: mqtt`, only initialized when explicitly configured)
- Agent: `BaseDetector.create_threat()` emits a payload matching the backend's `ThreatCreate` schema directly (`detector_type`, `severity`, `matched_rules`, `raw_event`, top-level `latitude`/`longitude`)
- Agent: `HeartbeatService` emits backend's `SensorHeartbeat` shape (`is_online`, `enabled_detectors` as list, `system_info`, `location` for the map)
- Agent: HTTP client reads API key from `/etc/honeyman/api_key` (mode 0600), sends `Authorization: Bearer <key>` on all writes
- Backend: removed JWT/RBAC/User model; reads are public, writes use per-sensor API keys (SHA256-hashed)
- Backend: `POST /api/v2/sensors/register` returns one-time plaintext API key + ID; `authenticated_sensor` dep enforces key ↔ sensor_id binding
- Backend: Alembic migration drops `users`, adds `api_key_hash` to `sensors`, drops `is_acknowledged`/`acknowledged_*` columns from `threats`
- Frontend: removed JWT interceptor, login flows, and acknowledge/delete UI
- Ops: `honeyman-v2/deployment/phase_a_apply.sh` — idempotent operator script for TimescaleDB install + schema reset + smoke test

**Phase B — Self-register onboarding**
- `install.sh` rewritten for the V2 self-register flow: calls `/api/v2/sensors/register`, captures one-time API key, drops V2 config + systemd unit
- New `AddSensorPage` on the dashboard with a copy-able install command and non-interactive variant, wired into nav

**Phase C — Resilience + central rule sync**
- New `transport/offline_buffer.py`: SQLite-backed persistent FIFO at `/var/lib/honeyman/buffer.db`. Survives agent restarts; bounded at 10k rows
- `ProtocolHandler` now uses the SQLite buffer (with deque fallback). On reconnect it batches the drain (100 at a time) with ack-on-success and stops on first failure to avoid hammering a flaky backend
- New backend endpoint `GET /api/v2/rules`: returns `{version, count, generated_at, rules: [{path, category, sha256, content}]}`. Supports `?since_version=…` for short-circuit. Authenticated by sensor API key
- 37 default rules seeded into `honeyman-v2/dashboard-v2/backend/rules/` from the agent tree (single source of truth for what gets pushed)
- New agent service `core/rule_sync.py`: polls the backend every 5 min (disabled by default; opt-in via `rule_sync.enabled: true`). Writes new/changed YAML to `/etc/honeyman/rules/`. Path-traversal-protected. Preserves any rule with a `<rule>.yaml.local` marker file alongside it
- Wired into agent lifecycle (`HoneymanAgent.initialize` / `.start` / `.stop`)

### Removed
- `archive/v2-removed-auth/` — old `auth.py`, JWT `security.py`, User model + schema
- `archive/v2-removed-onboarding/` — duplicate standalone Flask `provisioning_api.py`
- `archive/v1/` — V1 monolithic codebase, kept for reference



### Added
- **Malware Hash Database**: Comprehensive 360+ signature database for USB threat detection
  - 62 USB worm signatures (Stuxnet, Conficker, Agent.btz, Flame, Gauss, DarkTequila)
  - 53 BadUSB/HID attack payloads (Rubber Ducky, Bash Bunny, Malduino, O.MG Cable, Teensy)
  - 40 ransomware variants (WannaCry, Petya, NotPetya, Bad Rabbit, LockBit, BlackCat, Hive)
  - 28 credential stealers (Mimikatz, LaZagne, RedLine, Raccoon, AZORult, Vidar)
  - 20 penetration testing tools (Metasploit, Kali tools, Hak5 payloads, P4wnP1)
- **Enhanced USB Detection**: Real-time SHA256/MD5 hash calculation with < 100ms lookup
- **USB Enhanced Detector** (`usb_enhanced_detector.py`): Advanced USB threat detection system
- **WiFi Enhanced Detector** (`wifi_enhanced_detector.py`): Improved WiFi threat analysis
- **BLE Enhanced Detector**: Enhanced Bluetooth Low Energy threat detection
- **Hash Management Tools**: `data/add_malware_hashes.py` for database management
- **Threat Feed Updater**: Automated threat intelligence feed updates (`src/utils/threat_feed_updater.py`)
- **Data Synchronization Scripts**: `resync_all_threats.py` and `resync_dashboard_data.py`
- **Event Management**: DefCon event data management tools
- **Enhanced Systemd Services**: Service files for all enhanced detectors

### Changed
- **USB Detection Architecture**: Migrated from basic detection to hash-based malware identification
- **Service Management**: Consolidated systemd services in `deployment/systemd/`
- **Dashboard**: Updated to enhanced dashboard with improved visualizations
- **.gitignore**: Added exceptions for malware database and threat feed cache
- **README.md**: Updated with new capabilities and malware hash database information
- **CAPABILITIES.md**: Expanded USB threat detection section with detailed hash detection capabilities

### Removed
- Duplicate dashboard HTML files (minimal, simple, test, working variants)
- Obsolete control scripts (phase3a, phase3b, old control.sh)
- Backup configuration files (docker-compose.yml.backup)
- Obsolete systemd services (honeypot-usb-advanced, honeypot-wifi-detector)
- Duplicate hash database scripts
- Empty systemd directory (superseded by deployment/systemd/)

### Fixed
- Volume label detection for suspicious USB devices (e.g., "STARKILLER")
- Storage device mount retry logic for delayed filesystem availability
- WiFi whitelist configuration integration
- Service startup dependencies and ordering

### Security
- Implemented real-time malware hash verification for all USB-mounted files
- Added BadUSB device signature detection (Teensy, Arduino Leonardo, Digispark, Flipper Zero)
- Enhanced volume label pattern matching for attack device identification
- Improved autorun.inf detection and analysis

## [1.0.0] - 2024-09-01 - Initial Release

### Added
- Multi-vector threat detection system
- WiFi threat detection (evil twins, deauth attacks, suspicious SSIDs)
- Bluetooth LE threat detection (Flipper Zero, suspicious devices)
- AirDrop threat detection
- USB device monitoring
- OpenCanary honeypot integration
- Elasticsearch + Kibana analytics stack
- Real-time dashboard with Socket.IO
- Docker Compose deployment
- Systemd service management
- Noise reduction and filtering (99% false positive reduction)
- Cross-protocol threat correlation
- VPS data forwarding and aggregation
- Professional web dashboard
- API endpoints for threat intelligence
- Comprehensive logging and rotation
- Multi-stage deployment scripts

### Security
- Network honeypots (SSH, FTP, SMB, HTTP)
- Corporate web portal decoy
- Canary document tracking
- Real-time alert forwarding
- Threat intelligence integration

## [0.1.0] - 2024-07-30 - Project Inception

### Added
- Initial project structure
- Basic USB detection
- OpenCanary configuration
- Simple logging system
- Docker support
- Basic documentation

---

## Legend

- **Added**: New features
- **Changed**: Changes to existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security improvements
