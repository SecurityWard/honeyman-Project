# Changelog

All notable changes to the Honeyman Project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Rule hot-reload actually works now — 2026-06

The agent README, `example_config.yaml`, and the rule_engine /
rule_sync docstrings all claimed "edit a YAML, the inotify watcher
picks it up, no restart needed." There was no watcher. `reload_rules()`
existed as a method but nothing called it — every rule edit on a
live sensor required `systemctl restart honeyman-agent`.

- New `honeyman/core/rule_watcher.py` — `watchdog`-backed file
  watcher running in its own thread, marshalling `reload_rules()`
  callbacks back to the asyncio loop via `call_soon_threadsafe`,
  with a 1-second debounce so editors that write+rename-save don't
  trigger five reloads in a row. Triggers on create/modify/delete/
  move of any `.yaml` or `.yml` under `rules_dir`.
- Wired into the agent lifecycle next to `rule_sync`. `get_status()`
  reports its state for diagnostics.
- Graceful degradation: if `watchdog` isn't installed (older sensors
  that pre-date this change), the service logs one warning and
  becomes a no-op. The agent still runs; rule edits just need a
  restart, same as before.
- `watchdog>=3.0.0` added to `setup.py`. New `rule_watcher` block in
  example_config.yaml; defaults are safe so existing configs need no
  edits.
- Docs corrected — README, example_config.yaml comments, and
  rule_sync.py docstring no longer lie.

### Operations hygiene — 2026-06

- `.github/workflows/ci.yml` — minimum push/PR pipeline: backend
  modules compile, agent installs cleanly + compiles, frontend builds
  via `tsc -b && vite build`, and `install.sh` + deployment shell
  scripts parse via `bash -n`. Intentionally excludes Postgres/Redis
  integration tests and lint gates.
- `honeyman-v2/deployment/ops/` — installable artifacts for the things
  every production deploy needs but the app doesn't ship by default:
  - `postgres-backup.sh` + `honeyman-backup.cron` — nightly
    `pg_dump` of `honeyman_v2` to `/var/backups/honeyman/`, 14-day
    retention, logs to syslog, cron emails root on non-zero exit.
  - `honeyman.logrotate` — daily rotation of
    `/var/log/honeyman-backend.log`, 14 compressed copies,
    `copytruncate` so uvicorn doesn't need a reload. Closes the
    "log grows unbounded" item from SECURITY.md §7.
  - `healthcheck.sh` + `honeyman-healthcheck.service` +
    `honeyman-healthcheck.timer` — every 5 minutes, probe
    `${API_BASE}/health` and a public read endpoint, log to syslog
    on success, exit non-zero (and optionally POST a webhook) on
    failure. No external SaaS dependency.
- README operability row updated; SECURITY.md §7 trimmed.

### Security audit & documentation pass — 2026-06

- Pentester-style audit of the deployed surface produced 14 actionable
  findings; fixes shipped in three commits:
  - `POST /sensors/register` now rate-limited at 10/hour/IP via slowapi
    with Redis-backed storage (multi-worker uvicorn was silently letting
    through 4× the cap on in-memory counters).
  - WebSocket endpoint caps total connections at `MAX_CONNECTIONS=500`,
    refuses over-cap clients with a 1013 close. Inbound channel reads
    and discards with a 1 KB cap, then closes 1009 on overflow.
  - `/threats` `sort_by` constrained by regex allowlist; threat payload
    schemas have `max_length` caps on list/string fields and `ge/le` on
    ports.
  - `nginx/honeyman.conf` sets `client_max_body_size 256k;` on the API
    block.
  - `agent/honeyman/core/rule_sync.py` validates rule paths by resolve +
    `relative_to`, replacing the heuristic string check.
  - `dashboard-v2/backend/app/api/rules.py` no longer echoes the
    absolute rules-directory path back to the client on a 503.
- Added `RELEASE-CHECKLIST.md` — executable runbook (MUST/SHOULD/NICE)
  for onboarding, USB/BLE/network detection, backend ingest, dashboard
  UI, persistence, operability, and detector tuning.
- Renamed `HONEYMAN-V2-PLAN.md` → `PROJECT-PLAN.md`. Scrubbed
  "V1 → V2 sequel" framing from `README.md`, `PROJECT-PLAN.md`,
  `SECURITY.md`, and `CHANGELOG.md`. Real path/version strings
  (`/api/v2/`, the `honeyman-v2/` directory, the `honeyman_v2` DB) are
  untouched.

### Post-deploy fixes & UX polish — 2026-06

A batch of fixes shaken out by the first real Pi onboarding and the first
real session of the public dashboard.

**Onboarding / install.sh**

- `https://honeymanproject.com/install` now serves the actual `install.sh`
  as `text/plain` via an nginx `location = /install` block (was returning
  the SPA's `index.html`; `bash` choked on `<!doctype html>` line 1).
- `install.sh` reattaches stdin to `/dev/tty` so `read -rp "Sensor name"`
  works under `curl … | bash`. First attempt redirected stdin globally
  with `exec`, which stalled bash before pre-flight; second attempt uses
  per-`read` `< "$TTY_IN"`.
- `install.sh` registration payload built via a Python heredoc with the
  delimiter quoted (`<<'PY'`) and all values passed in via env vars.
  Earlier version inlined `${MOD_USB}` etc. and Python choked on bash's
  lowercase `true` (`NameError: name 'true' is not defined`).
- `install.sh` detects single-WiFi-adapter Pis (one `iw dev` interface
  that's also the default route) and refuses to default WiFi/AirDrop
  detection on for them — defaults would otherwise put the only adapter
  into monitor mode and disconnect the installer from itself.
- `install.sh` now ships the malware-hash DB (`data/malware_hashes.db`,
  ~360 signatures) to `/var/lib/honeyman/malware_hashes.db`. Previously
  the USB detector was silently disabling its file-hash branch.
- `setup.py` declares `aiohttp>=3.9.0`; dropped unused declared deps
  (`requests`, `netifaces`, `python-dotenv`, `python-json-logger`,
  `cryptography`).

**Agent runtime**

- `PluginManager.load_detector` now uses an explicit `{name: (module,
  class)}` table — was deriving class names by title-casing the config
  key, which produced `BluetoothDetector` (missing) instead of
  `BleDetector` and `AirdropDetector` instead of `AirDropDetector`.
  Both `'bluetooth'` and `'ble'` resolve to `BleDetector` now.
- `BleDetector`, `NetworkDetector`, `AirDropDetector` constructors
  accept `location_service` and pass arguments through to `BaseDetector`
  in the right order. The old `(config, rule_engine, transport)`
  signature mangled the base attributes.
- `HoneymanAgent.start()` no longer calls `_send_registration()` —
  install.sh registers via curl, the agent should just heartbeat. The
  old call POSTed `{"type":"registration","sensor_name":…}` to
  `/sensors/register` and got 422 forever because the schema requires
  `requested_name`, queuing the broken payload into the offline buffer.
- `BaseDetector.evaluate_event` enforces per-(rule, target) cooldown.
  Honours `tuning.cooldown_seconds` (preferred) or derives the spacing
  from `tuning.max_alerts_per_hour`. Identity derived from the most
  identifying field on the event (`device_mac` > `src_host` >
  `service_name` > `vendor:product:serial` > …). The cache prunes
  hourly. Was previously letting the BLE `mac_randomization` rule fire
  60+ times in three minutes from neighbours' phones.

**Backend / dashboard**

- `POST /api/v2/threats` publishes the serialized `ThreatResponse` to
  the Redis `threats:realtime` channel after commit, so the WebSocket
  broadcast layer actually relays HTTPS-delivered threats. Only the MQTT
  subscriber was publishing before, which meant the live feed was
  permanently empty under the HTTPS-default transport.
- `GET /api/v2/sensors` computes `total_threats_detected` and
  `threats_last_24h` with two bulk GROUP-BY queries instead of reading
  the never-updated counter columns on the sensors row.
- `GET /api/v2/analytics/trends` uses `date_trunc('hour' | 'day' |
  'week', …)` instead of `'hourly' | 'daily' | 'weekly'` — the API
  values were passed straight into PostgreSQL, which raised
  `InvalidParameterValueError` on every call so the trends chart was
  empty.

**Frontend**

- Dashboard "Real-Time Threat Feed" rows are expandable `<details>`
  elements showing the matched rule (name + rule_id), confidence/score,
  device MAC/IP, MITRE tags (linked to attack.mitre.org), and a
  pretty-printed `raw_event` payload. Seeded from REST so it isn't
  empty until the first WS frame arrives; dedupes by id.
- Threat map popup rewritten with the same expanded info and the
  field-name fixes (`confidence_score` → `confidence`, `mac_address` →
  `device_mac`, `ip_address` → `device_ip`) — the popup was rendering
  `NaN%` for confidence.
- Sensors page rows are clickable; navigate to
  `/dashboard?sensor_id=…`. Dashboard reads the param, filters the
  threat feed and WebSocket subscription to that sensor, re-centers the
  map on the sensor's coords, and shows a blue filter banner with a
  back-link and clear button.
- Add Sensor page now leads with a red "you are deliberately inviting
  attacks" callout before the amber single-adapter hardware note.
- Sensors page no longer renders blank — was reading `sensorsData.items`
  but the API returns `sensorsData.sensors`. Same for `status`,
  `location`, `total_threats`, `last_seen` (all renamed in the current schema).
- BLE rule `mac_randomization` shipped `enabled: true` despite its own
  metadata declaring `false_positive_prone: true` and matching every
  randomized MAC; now `enabled: false`. Operators can opt in.

**Repository hygiene**

- nginx config snapshotted to `honeyman-v2/deployment/nginx/honeyman.conf`
  + a deployment README so the site can be rebuilt from the repo.
- `.gitignore` `*api_key*` rule was hiding the actual auth module at
  `app/core/api_key.py`; added explicit negation rules so legitimate
  source files for handling API keys stay tracked.
- `package.json`, `package-lock.json`, `tsconfig*.json` were caught by
  a broader `*.json` ignore rule; whitelisted under `honeyman-v2/**`.
- Domain rename: every active code/doc reference updated from
  `honeyman.io` (never registered) to `honeymanproject.com`.
- "V2" branding scrubbed from user-facing UI strings (the version
  number stays in the URL prefix `/api/v2/` and directory names).
- Stale archived directories (`archive/v1/`, `archive/v1-scripts/`,
  `archive/v2-removed-*`, `docs/historical/`) deleted — 27,466 lines
  removed; `git log` preserves the history.

### V2 Phase D — Location upgrades — 2026-05

- Agent `LocationService` rewritten: resolves location in the order **manual override → GPS via gpsd → WiFi positioning (Mozilla Location Service / Google) → IP**. Each method returns `{lat, lon, accuracy, source}`; results cached for 5 min.
- New config options: `location.manual_latitude` / `manual_longitude` / `manual_label` / `manual_accuracy`; `location.gps_enabled` / `gpsd_host` / `gpsd_port`; `location.wifi_positioning_api_key` / `wifi_interface` / `wifi_max_aps`
- Threat payload now carries `accuracy_meters` and `location_method` end-to-end: agent `BaseDetector` emits them, backend `Threat` model + `ThreatCreate`/`ThreatResponse` schemas accept them, Alembic migration creates the columns, frontend `Threat` type includes them
- `ThreatMap` dashboard component renders a colour-coded confidence circle under each threat marker (GPS green, WiFi sky, IP gray-dashed, manual violet). Circle radius equals reported accuracy, capped at 2km for readability. Legend updated. Popup shows `LOCATION_METHOD · ±N m`
- Unit tested: manual override skips all dynamic sources, invalid manual coords are ignored, `iw dev … scan` parser pulls BSSID+signal pairs, disabled service returns None

### Deploy-blocker fixes — 2026-05

- `app/core/api_key.py` — module added (was imported by `deps.py` and `onboarding.py` but missing on the public branch). `generate_api_key` / `hash_api_key` / `verify_api_key` / `extract_bearer_token`.
- `alembic/env.py` — removed `from app.models.user import User` (V2 has no users). Asyncpg DATABASE_URL now rewritten to psycopg2 inside `set_main_option` for alembic's sync engine
- `threats` hypertable: composite PK on `(id, timestamp)` in both Alembic migration (`PrimaryKeyConstraint('id', 'timestamp')`) and the SQLAlchemy model. TimescaleDB requires the partition column in any unique/PK index
- `CORS_ORIGINS` env parsing: `Annotated[List[str], NoDecode]` + `@field_validator("CORS_ORIGINS", mode="before")` accepts either JSON-array (`["a","b"]`) or CSV (`a,b`) — operators can use whichever is friendlier
- `phase_a_apply.sh` BACKEND_DIR default corrected to `/root/honeyman-Project/honeyman-v2/dashboard-v2/backend`

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
- `install.sh` rewritten for the self-register flow: calls `/api/v2/sensors/register`, captures one-time API key, drops config + systemd unit
- New `AddSensorPage` on the dashboard with a copy-able install command and non-interactive variant, wired into nav

**Phase C — Resilience + central rule sync**
- New `transport/offline_buffer.py`: SQLite-backed persistent FIFO at `/var/lib/honeyman/buffer.db`. Survives agent restarts; bounded at 10k rows
- `ProtocolHandler` now uses the SQLite buffer (with deque fallback). On reconnect it batches the drain (100 at a time) with ack-on-success and stops on first failure to avoid hammering a flaky backend
- New backend endpoint `GET /api/v2/rules`: returns `{version, count, generated_at, rules: [{path, category, sha256, content}]}`. Supports `?since_version=…` for short-circuit. Authenticated by sensor API key
- 37 default rules seeded into `honeyman-v2/dashboard-v2/backend/rules/` from the agent tree (single source of truth for what gets pushed)
- New agent service `core/rule_sync.py`: polls the backend every 5 min (disabled by default; opt-in via `rule_sync.enabled: true`). Writes new/changed YAML to `/etc/honeyman/rules/`. Path-traversal-protected. Preserves any rule with a `<rule>.yaml.local` marker file alongside it
- Wired into agent lifecycle (`HoneymanAgent.initialize` / `.start` / `.stop`)

### Removed
- V1 monolithic codebase and one-shot V1 helpers (previously under `archive/v1/` and `archive/v1-scripts/`) — `git log` preserves the history
- Pre-API-key auth code (JWT, User model, RBAC) and the duplicated standalone Flask `provisioning_api.py` (previously under `archive/v2-removed-*`)
- Stale phase-completion and migration-status docs (`*-COMPLETE.md`, `CURRENT-STATUS.md`, `V2-MIGRATION-STATUS.md`, `IMPLEMENTATION-ROADMAP.md`, `dashboard-v2/DEPLOYMENT.md`, `docs/historical/`) — superseded by `PROJECT-PLAN.md`

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
