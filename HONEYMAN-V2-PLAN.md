# Honeyman V2 — Canonical Plan

**Status:** This is the single source of truth for V2.
The older docs (`HONEYMAN-V2-STATUS.md`, `honeyman-v2/CURRENT-STATUS.md`, `honeyman-v2/V2-MIGRATION-STATUS.md`, `honeyman-v2/IMPLEMENTATION-ROADMAP.md`) are historical and contradict each other. Treat this file as authoritative.

Last updated: 2026-05-09

---

## 1. Vision

Honeyman V2 is a **mobile, multi-vector threat collection platform**. Pi-class portable sensors detect malicious activity across USB, WiFi, BLE, AirDrop, and (when networked) act as canary SSH/HTTP honeypots. Detections are pushed to a publicly accessible dashboard that visualizes threats on a map and offers filtering — no user accounts, no actions, just a viewing surface.

**Three guiding principles for V2:**

1. **Simple to deploy.** A single `curl | bash` puts a sensor on the air.
2. **Simple to operate.** No accounts, no roles, no admin UI. Public dashboard. Sensor-side YAML rules can be hand-edited or pulled from a central endpoint.
3. **Simple to extend.** New rules ship without touching code. New detectors plug into a stable agent contract.

---

## 2. Architecture (target state)

```
┌──────────────────────────────────────────────────────┐
│  Sensor (Pi Zero 2 W / Pi 4)                         │
│                                                      │
│  ┌──────────┬──────────┬──────────┬──────────┐       │
│  │   USB    │   WiFi   │   BLE    │ AirDrop  │       │
│  └──────────┴──────────┴──────────┴──────────┘       │
│                       │                              │
│  ┌──────────────────────────────────────┐            │
│  │  Rule Engine  (loads /etc/honeyman/  │            │
│  │                rules/*.yaml)         │            │
│  └──────────────────────────────────────┘            │
│                       │                              │
│  ┌──────────────────────────────────────┐            │
│  │  Location Service                    │            │
│  │  GPS → WiFi-positioning → IP         │            │
│  └──────────────────────────────────────┘            │
│                       │                              │
│  ┌──────────────────────────────────────┐            │
│  │  Transport Layer                     │            │
│  │  - HTTPS + API key (default)         │            │
│  │  - MQTT + creds (optional)           │            │
│  │  - SQLite offline buffer             │            │
│  └──────────────────────────────────────┘            │
│                       │                              │
│  ┌──────────────────────────────────────┐            │
│  │  Canary Network Stack (optional)     │            │
│  │  SSH/HTTP honeypot if connected      │            │
│  │  to a network. Reports as events.    │            │
│  └──────────────────────────────────────┘            │
└──────────────────────────────────────────────────────┘
                          │
                  HTTPS / MQTT (TLS)
                          │
                          ▼
┌──────────────────────────────────────────────────────┐
│  VPS                                                 │
│                                                      │
│  ┌──────────────────────────────────────┐            │
│  │  FastAPI Backend                     │            │
│  │  - POST /v2/sensors/register         │            │
│  │  - POST /v2/threats   (API-key auth) │            │
│  │  - POST /v2/heartbeat (API-key auth) │            │
│  │  - GET  /v2/rules     (sensor pull)  │            │
│  │  - GET  /v2/threats   (public read)  │            │
│  │  - GET  /v2/sensors   (public read)  │            │
│  │  - GET  /v2/analytics/* (public)     │            │
│  │  - WS   /v2/ws        (live feed)    │            │
│  └──────────────────────────────────────┘            │
│         │                                            │
│         ▼                                            │
│  ┌──────────────────────────────────────┐            │
│  │  Postgres + TimescaleDB              │            │
│  │  threats hypertable (90d retention)  │            │
│  │  sensors table                       │            │
│  │  api_keys table                      │            │
│  │  rules table (versioned YAML)        │            │
│  └──────────────────────────────────────┘            │
│         │                                            │
│         ▼                                            │
│  ┌──────────────────────────────────────┐            │
│  │  React Dashboard (public read-only)  │            │
│  │  - Leaflet map with threat overlay   │            │
│  │  - Filter by sensor / type / time    │            │
│  │  - Live feed via WebSocket           │            │
│  └──────────────────────────────────────┘            │
└──────────────────────────────────────────────────────┘
```

**What changed from the previously-documented architecture:**

- No JWT / no users / no RBAC. Dashboard is public; sensors authenticate with per-sensor API keys.
- HTTPS+API-key is the primary sensor transport. MQTT is optional.
- The "separated alert engine over Unix socket" idea is dropped. Detectors call the rule engine inline (already implemented this way).
- Rules live in YAML files on the sensor. Centralized rule distribution is a `GET /v2/rules` poll, not an MQTT push.
- Onboarding is one endpoint inside the FastAPI backend, not a separate Flask service.

---

## 3. Current state, honestly

The code is roughly **75–80% written but only ~25% deployed**. Reconciling the three contradictory status docs:

| Component | Code state | Operational state |
|---|---|---|
| Agent core (orchestrator, plugin manager, config) | ✅ Built | ⚠️ Not running on any sensor |
| 5 detectors (USB, WiFi, BLE, AirDrop, Network) | ✅ Built | ⚠️ Not exercised end-to-end |
| Rule engine + 35 YAML rules | ✅ Built | ✅ Loads correctly |
| Transport (MQTT + HTTP fallback) | ⚠️ MQTT path only; needs HTTPS+API-key default | ❌ Not connected |
| Location service | ⚠️ IP geolocation works; GPS + WiFi-positioning are TODO stubs | ❌ Not exercised |
| SQLite offline buffer | ❌ Not built | ❌ |
| Backend FastAPI app + 27 endpoints | ✅ Built | ⚠️ Code complete, not deployed |
| Auth (JWT, RBAC, User model) | ✅ Built | 🗑 **DELETE per V2 vision** |
| API key issuance + validation | ❌ Not built | ❌ |
| MQTT subscriber | ✅ Built | ⚠️ Won't run without broker |
| Postgres database | ✅ Schema defined | ✅ Created on VPS |
| TimescaleDB hypertable + retention | ❌ Migration uses date_trunc as workaround | ❌ Extension not enabled |
| Mosquitto broker | ⚠️ Configs written | ❌ Not deployed |
| Frontend (Leaflet map, charts, sensor list) | ✅ Built and deployed | ✅ Visible at http://72.60.25.24:3000 |
| Frontend auth UI | ❌ Not built | 🗑 **No longer needed** |
| Sensor edit/detail UI | ❌ Stubbed | Build later |
| Install script | ✅ Written | ⚠️ Untested on real Pi |

**Known integration bugs that will bite at first end-to-end test:**

1. **Topic-naming mismatch.** Agent sends to topic `'threats'`; backend MQTT subscriber expects `honeyman/sensors/{id}/threats`; onboarding architecture doc uses `honeypot/{id}/{type}`. Pick one.
2. **Location field-name mismatch.** Agent emits `geolocation.lat / geolocation.lon`; backend MQTT subscriber reads `payload.get('latitude') / payload.get('longitude')`. Threats will arrive but their map coordinates will be NULL until this is fixed.
3. **Two onboarding implementations.** Standalone Flask `provisioning_api.py` vs FastAPI `app/api/onboarding.py`. The standalone needs to die.
4. **Backend MQTT subscriber assumes broker exists** at startup. Until Mosquitto is up or the subscriber is made optional, the backend won't start cleanly.

---

## 4. Mobile sensor capabilities (target)

**Detection (always on):**

- **USB** — pyudev event loop, mass-storage auto-mount + recursive SHA256 against the 360+ malware DB, VID/PID fingerprinting (Rubber Ducky, Bash Bunny, OMG Cable, Flipper Zero), volume label patterns, autorun.inf inspection.
- **WiFi** — scapy in monitor mode (airmon-ng), iwlist fallback. Evil Twin (SSID with multiple BSSIDs), deauth flooding, beacon flooding, Pineapple/ESP8266 deauther/Flipper signatures, suspicious SSIDs, WPS attacks.
- **BLE** — bleak or bluetoothctl. Flipper Zero variants, BLE spam, Apple Continuity abuse, HID keyloggers, ESP32 attack tools, manufacturer-data spoofing.
- **AirDrop / mDNS** — avahi-browse. Suspicious service names, generic-device spoofing, rapid announcement floods, TXT-record abuse.

**Canary network stack (when sensor has IP):**

- **SSH honeypot** — accept connections, log username/password attempts, log keystroke commands, never authenticate.
- **HTTP honeypot** — fake "router admin" landing page, log credential submissions, log path-traversal probes.
- Both implemented as part of the existing `network_detector` module; OpenCanary already integrated.
- Toggleable in `config.yaml` — off by default for sensors deployed in environments where running listening services would be inappropriate (corporate networks, public WiFi).

**Location reporting (every threat):**

- Every threat carries `latitude`, `longitude`, `accuracy_meters`, `source` (`gps` | `wifi` | `ip` | `manual`).
- Operator can pin a sensor's location at registration time — overrides automatic methods.
- GPS via `gpsd` if a GPS HAT/USB module is attached (currently a TODO stub, prioritize).
- WiFi positioning via Mozilla Location Service (free) or Google Geolocation API (paid). Pick MLS for the public deployment to avoid API key management.
- IP geolocation via ipapi.co (works, fallback only — accuracy ~5km).
- Heartbeat carries the most recent location so an idle sensor still appears on the map.

---

## 5. Cleanup actions

These are the structural moves needed before further building. They're being executed in this conversation.

**Files moving to `archive/v1/`:**

```
src/                          → archive/v1/src/
dashboard/                    → archive/v1/dashboard/
scripts/                      → archive/v1/scripts/
deployment/                   → archive/v1/deployment/
config/                       → archive/v1/config/
web/                          → archive/v1/web/
logrotate.conf                → archive/v1/
logrotate.d/                  → archive/v1/
log_manager.py                → archive/v1/
simple_log_collector.py       → archive/v1/
system_monitor.py             → archive/v1/
resync_all_threats.py         → archive/v1/
resync_dashboard_data.py      → archive/v1/
opencanary.conf               → archive/v1/
docker-compose.yml            → archive/v1/
requirements.txt              → archive/v1/
honeyman.jpeg                 → archive/v1/  (old logo)
```

**Files staying at top level but keep:**

```
README.md                     → rewritten for V2 (public-facing)
LICENSE
CHANGELOG.md
ARCHITECTURE.mmd              → rewritten for V2
CAPABILITIES.md               → rewritten for V2
HONEYMAN-V2-PLAN.md           → this file (canonical)
data/                         → kept (malware DB used by V2)
honeyman-v2/                  → V2 source tree (will be promoted in step below)
migrate_v1_to_v2.py           → kept (one-time migration script)
.gitignore
```

**Files marked archival but not deleted:**

```
HONEYMAN-V2-STATUS.md         → header points to HONEYMAN-V2-PLAN.md
ARCHITECTURE-V2.md            → archived — superseded by ARCHITECTURE.mmd + this plan
V2-OVERVIEW.md                → archived
V2-IMPLEMENTATION-PLAN.md     → archived
V2-MIGRATION-STARTED.md       → archived
V2-MOBILE-SENSOR-DESIGN.md    → kept until merged into this plan
TESTING.md                    → reviewed and updated for V2
DEPLOYMENT-NOTES.md           → kept; merged into deployment guide
honeyman-v2/CURRENT-STATUS.md           → header points here
honeyman-v2/V2-MIGRATION-STATUS.md      → header points here
honeyman-v2/IMPLEMENTATION-ROADMAP.md   → header points here
honeyman-v2/PHASE-2-COMPLETE.md         → kept as historical record
honeyman-v2/dashboard-v2/PHASE-3-COMPLETE.md  → kept as historical record
honeyman-v2/dashboard-v2/PHASE-4-COMPLETE.md  → kept as historical record
```

**Files being deleted outright:**

```
honeyman-v2/readme/onboarding/provisioning_api.py
honeyman-v2/readme/onboarding/requirements.txt
                              → duplicate of FastAPI onboarding endpoint
"New folder/"                 → mystery directory (verify empty first)
```

**Code being deleted from the V2 backend:**

```
backend/app/api/auth.py                  → DELETE (no JWT login)
backend/app/models/user.py               → DELETE (no users)
backend/app/schemas/user.py              → DELETE (no users)
backend/app/core/security.py             → REWRITTEN as api_key.py
backend/app/api/deps.py                  → REWRITTEN: api_key dep only
backend/app/main.py                      → drop auth router import
backend/alembic/versions/001_initial_schema.py
                                         → drop users table; add api_keys table
```

**Code being deleted from the V2 frontend:**

```
frontend/src/services/api.ts             → drop JWT axios interceptor
                                         (no Authorization header on read endpoints)
                                         (any saved tokens removed)
```

**Promotion (deferred to a follow-up commit):**

The `honeyman-v2/` subdirectory should eventually be promoted to the repo root. For now we're keeping it nested to avoid disturbing every import path during cleanup. The promotion itself is mechanical (`git mv honeyman-v2/* .`) once nothing else under it references the prefix.

---

## 6. Build order

Phase ordering after cleanup. Each phase produces something demonstrable; don't move on without that demo.

### Phase A — Make a single sensor talk to the dashboard end-to-end (1–2 weeks)

Goal: a Pi sitting on a desk shows up on the public map, sends one synthetic USB threat, and the dot appears in the right city.

1. Implement HTTPS+API-key transport in the agent. Default to this. MQTT becomes opt-in.
2. Add API-key middleware to the backend's POST `/v2/threats`, `/v2/heartbeat`, `/v2/rules` endpoints. Read endpoints stay open.
3. Build the API-key issuance flow inside `POST /v2/sensors/register`. Returns `{sensor_id, api_key}`. Store the hash, not the key.
4. Fix the location field-name mismatch (`geolocation.lat` ↔ `latitude`).
5. Strip auth from frontend; remove the JWT axios interceptor.
6. Enable TimescaleDB extension on the VPS Postgres; convert `threats` to a hypertable; add 90-day retention policy.
7. Test on a real Pi 4. Send one threat. Verify it lands on the map.

### Phase B — Onboarding works for someone other than you (1 week)

Goal: a stranger runs `curl ... | bash` and their sensor is on the map within five minutes.

1. Test `install.sh` on a clean Pi 4 and a Pi Zero 2 W. Fix what breaks.
2. Wire the install script to call `/v2/sensors/register`, capture the returned API key, write it to `/etc/honeyman/credentials`.
3. Add a public "Add Sensor" page on the dashboard that displays the install command and a QR code.
4. Test onboarding from a fresh device with no Honeyman context.

### Phase C — Resilience and centralized rules (1 week)

Goal: a sensor on flaky WiFi doesn't lose data; you can change a rule without SSHing into every Pi.

1. Add SQLite offline buffer in the transport layer; flush on reconnect.
2. Implement `GET /v2/rules?since=<version>` returning a manifest of active rules.
3. Add a periodic poll in the agent (every 5 min default). On change, write to `/etc/honeyman/rules/`, signal the rule engine to reload.
4. Build a minimal rule-management UI on the backend (still no auth — but treat it as admin-only by leaving it un-linked from the public dashboard, accessible only via direct URL with a shared secret in a header). Or skip this entirely and edit rules in a Git repo that the backend syncs from.

### Phase D — Location upgrades (1 week)

Goal: every threat on the map is in the right place, indoors and out.

1. Implement GPS support via `gpsd` in `LocationService._get_gps_location()`.
2. Implement WiFi-positioning via Mozilla Location Service in `LocationService._get_wifi_location()` (no API key needed).
3. Add operator-pinned location override (set at registration, sent in heartbeat).
4. Add a confidence indicator on the map — circle radius = accuracy.

### Phase E — Canary network stack toggle (3–5 days)

Goal: when a sensor has a network interface, optionally expose SSH/HTTP honeypots and report attempts as events.

1. Verify OpenCanary integration in `network_detector` works end-to-end.
2. Add `canary_network: enabled: false` to default config; document the security implications of turning it on.
3. Add a frontend filter to view canary-only events.

### Phase F — Operability (ongoing)

1. Systemd unit files for backend, MQTT subscriber-as-separate-service, broker.
2. Let's Encrypt + nginx reverse proxy.
3. Basic Prometheus metrics or a `/health` JSON with broker, DB, ingestion rate.
4. Log rotation, error alerting (Slack webhook is enough).

**Total realistic effort to hit Phase A through Phase E end-to-end: 5–6 weeks of focused work.**

---

## 7. Rule management model

Rules live in YAML files in `/etc/honeyman/rules/<category>/<rule-name>.yaml` on the sensor. There are three ways a rule gets there:

1. **Shipped with the agent** — packaged in the install script. The 35 default rules.
2. **Hand-edited locally** — operator SSHes in, edits a YAML file, the rule engine reloads on file-change (inotify on Linux).
3. **Pulled from the dashboard backend** — `GET /v2/rules` returns the current rule manifest. The agent polls this every 5 minutes and writes any new/changed rules to disk. Hand-edited rules are never overwritten (tracked by a `local: true` marker file).

Rule editing on the backend is intentionally low-tech for V2: a `rules/` directory in the backend's filesystem, version-controlled in a Git repo (e.g., `github.com/SecurityWard/honeyman-rules`). The backend serves whatever's in that directory. To change a rule, you `git push` to the rules repo. No web UI required for V2; one can be added later.

This means rule changes propagate without code redeployment, just as required.

---

## 8. Public dashboard scope

**The dashboard is a viewing surface only.** No accounts, no actions.

What it shows:

- Live map (Leaflet) with threats overlaid as colored markers (red/orange/yellow/blue by severity)
- Marker click → small popup with sensor ID, threat type, time, severity
- Live event feed (last 20 events, slides in via WebSocket)
- Filters: time range (24h / 7d / 30d / 90d / custom), sensor, threat type, severity, detector category
- Stat cards: total threats, critical count, active sensors, threats/hr
- Sensor list: ID, location, last seen, threat count
- About page: what Honeyman is, how to deploy a sensor, link to the rules repo

What it does NOT do:

- No login. No user accounts. No saved preferences (other than `localStorage` filter state).
- No "acknowledge" / "delete" / "edit" actions on threats.
- No sensor management beyond a public list. Operators manage their own sensors via SSH.
- No alerting / paging / webhooks (those live on the sensor side as rule actions).

---

## 9. Open decisions

A few things I've made implicit choices on but you should confirm:

1. **Rules-from-Git vs rules-from-DB.** I'm assuming a `honeyman-rules` Git repo that the backend syncs from. Alternative: rules live in Postgres and are edited via a (rudimentary) web form. Git is simpler and gives free history; DB is better if you ever want non-developers to edit rules.

2. **WiFi positioning provider.** Mozilla Location Service is free and good but has been quietly deprecated/spun off; Google Geolocation costs money but is reliable. For now I'd default to MLS and let operators opt into Google with their own API key in `config.yaml`.

3. **Public dashboard hostname.** Right now it's `http://72.60.25.24:3000`. For a public deployment we want `https://dashboard.honeyman.io` or similar. Need a domain and Let's Encrypt cert.

4. **Sensor naming privacy.** Self-selected names with random suffixes (`defcon-hotel-7x9k`) — already designed. Operators may not want their physical location guessable. Consider letting operators flag a sensor as "hide exact location" — the map would show city-level only.

5. **Data retention default.** 90 days is in the schema; for a public dashboard, longer retention with aggressive aggregation (e.g., 7 days raw + 90 days aggregated) might be better. Decide before TimescaleDB compression policy is set.

---

## 10. Out of scope for V2

Explicit no-goes for this version, to prevent scope creep:

- Machine learning threat correlation
- SIEM integrations (Splunk, ELK, etc.)
- Multi-tenant support
- Mobile (Android/iOS) sensor app
- Incident response workflows
- User accounts in any form
- Paid subscriptions, billing, plans

---

## 11. Document map

After cleanup, this is the doc structure:

```
README.md                    Public-facing intro + quick-start
HONEYMAN-V2-PLAN.md          This file (canonical plan)
ARCHITECTURE.mmd             Mermaid diagram of V2 system
CAPABILITIES.md              What V2 detects, accuracy, limitations
CHANGELOG.md                 Release notes
LICENSE                      MIT
TESTING.md                   How to run tests + integration scenarios

honeyman-v2/
├── agent/                   Sensor-side Python package
│   ├── README.md            Agent install + dev guide
│   └── ...
├── dashboard-v2/
│   ├── backend/             FastAPI app
│   │   └── README.md        Backend dev + deploy
│   └── frontend/            React app
│       └── README.md        Frontend dev + deploy
└── deployment/              VPS deployment configs (compose, nginx, etc.)

archive/
└── v1/                      All V1 code, untouched, for reference
```
