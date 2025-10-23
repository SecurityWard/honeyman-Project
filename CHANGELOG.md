# Changelog

All notable changes to the Honeyman Project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
