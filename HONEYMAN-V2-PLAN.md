# Honeyman V2 — Canonical Plan

**Status:** This is the single source of truth for V2. Earlier design docs
have been removed; `git log` has them if you need them.

Last updated: 2026-06-23

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
| Agent core (orchestrator, plugin manager, config) | ✅ Built | ⚠️ Not yet running on a real sensor |
| 5 detectors (USB, WiFi, BLE, AirDrop, Network) | ✅ Built | ⚠️ Not exercised end-to-end |
| Rule engine + 35 YAML rules | ✅ Built | ✅ Loads correctly |
| Transport: HTTPS+API-key default, MQTT optional | ✅ Built (Phase A) | ❌ Not yet connected to backend |
| BaseDetector envelope aligned to backend schema | ✅ Built (Phase A) | — |
| Heartbeat envelope aligned to backend schema | ✅ Built (Phase A) | — |
| Location field-name fix (latitude/longitude top-level) | ✅ Built (Phase A) | — |
| Location service | ✅ **Built (Phase D)** — manual override + GPS via gpsd + WiFi positioning via MLS/Google + IP fallback. Threats + heartbeats now carry `accuracy_meters` and `location_method`. Unit tested. | — |
| Threat schema: `accuracy_meters` + `location_method` | ✅ Built (Phase D) — column on `threats`, fields on `ThreatCreate`/`ThreatResponse`, type on frontend `Threat` | — |
| Dashboard map accuracy circle | ✅ Built (Phase D) — `<Circle>` underneath each marker, colour-coded by method (GPS green / WiFi sky / IP gray-dashed / manual violet), legend in the corner | — |
| **SQLite offline buffer + persistent FIFO** | ✅ **Built (Phase C)** — `transport/offline_buffer.py`, wired into ProtocolHandler, unit tested | — |
| **Central rule sync (`GET /api/v2/rules` + agent poll)** | ✅ **Built (Phase C)** — `app/api/rules.py` + agent `core/rule_sync.py`, `.local` marker protection, unit tested | ❌ Not yet polling from a real sensor |
| Backend FastAPI app (no auth, public reads) | ✅ Built | ⚠️ Code complete, awaiting VPS deploy |
| Auth (JWT, RBAC, User model) | 🗑 **Removed** (git history preserves) | — |
| API key issuance + validation | ✅ Built (cleanup) — SHA256-hashed per-sensor key, `Authorization: Bearer` on writes | — |
| MQTT subscriber | ✅ Built | Only starts when `MQTT_OFFERED=true` |
| Postgres database | ✅ Schema rewritten (no `users`, adds `api_key_hash`) | ✅ Created on VPS |
| TimescaleDB hypertable + retention | ✅ Migration applies hypertable + 90d retention + 7d compression | ❌ Extension not yet enabled on VPS |
| Mosquitto broker | ⚠️ Configs written | ❌ Not deployed (HTTPS is primary now) |
| Frontend (Leaflet map, charts, sensor list) | ✅ Built and deployed | ✅ Visible at http://72.60.25.24:3000 |
| Frontend auth UI | 🗑 **Removed** | — |
| **Frontend "Add Sensor" page** | ✅ **Built (Phase B)** — `pages/AddSensorPage.tsx` with copy-able install command, wired into nav | ⚠️ Not yet rebuilt+deployed to VPS |
| Sensor edit/detail UI | ❌ Stubbed | Build later (Phase F or later) |
| Install script | ✅ **Rewritten for V2 self-register flow** (Phase B) | ⚠️ Untested on real Pi |
| `phase_a_apply.sh` operator script | ✅ **Built** — runs TimescaleDB install, schema reset, .env sync, smoke test on the VPS | ⚠️ Awaiting execution on VPS |

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

## 5. Build order

Phase ordering after cleanup. Each phase produces something demonstrable; don't move on without that demo.

### Phase A — Make a single sensor talk to the dashboard end-to-end (1–2 weeks) ✅ **code complete**

Goal: a Pi sitting on a desk shows up on the public map, sends one synthetic USB threat, and the dot appears in the right city.

1. ✅ Implement HTTPS+API-key transport in the agent. Default to this. MQTT becomes opt-in.
2. ✅ Add API-key middleware to the backend's POST `/v2/threats`, `/v2/heartbeat`, `/v2/rules` endpoints. Read endpoints stay open.
3. ✅ Build the API-key issuance flow inside `POST /v2/sensors/register`. Returns `{sensor_id, api_key}`. Stores the SHA256 hash, not the key.
4. ✅ Fix the location field-name mismatch (`geolocation.lat` → top-level `latitude`).
5. ✅ Strip auth from frontend; remove the JWT axios interceptor.
6. ⏳ **Operator step** — Enable TimescaleDB extension on the VPS Postgres; convert `threats` to a hypertable; add 90-day retention policy. Use `honeyman-v2/deployment/phase_a_apply.sh`.
7. ⏳ **Operator step** — Test on a real Pi 4. Send one threat. Verify it lands on the map.

### Phase B — Onboarding works for someone other than you (1 week) ✅ **code complete**

Goal: a stranger runs `curl ... | bash` and their sensor is on the map within five minutes.

1. ⏳ **Operator step** — Test `install.sh` on a clean Pi 4 and a Pi Zero 2 W. Fix what breaks.
2. ✅ Wire the install script to call `/v2/sensors/register`, capture the returned API key, write it to `/etc/honeyman/api_key` (mode 0600).
3. ✅ Add a public "Add Sensor" page on the dashboard — `AddSensorPage.tsx` shows the install command with a Copy button and wires into the nav.
4. ⏳ **Operator step** — Test onboarding from a fresh device with no Honeyman context.

### Phase C — Resilience and centralized rules (1 week) ✅ **code complete**

Goal: a sensor on flaky WiFi doesn't lose data; you can change a rule without SSHing into every Pi.

1. ✅ SQLite offline buffer (`transport/offline_buffer.py`) — persistent FIFO at `/var/lib/honeyman/buffer.db`, 10k row cap, ack semantics. Wired into `ProtocolHandler` so it drains on reconnect and survives agent restarts.
2. ✅ `GET /api/v2/rules?since_version=<hash>` — returns a manifest of all rule files with per-file SHA256 and a global version hash. Authenticated by sensor API key. Reads from `backend/rules/` (37 default rules seeded from the agent tree).
3. ✅ Agent rule-poll (`core/rule_sync.py`) — runs every 5 min by default (configurable, disabled by default). Diffs remote vs local, writes new/changed YAML, preserves any rule with a `.local` marker file. Rule engine's inotify watcher reloads automatically.
4. **Deferred for now** — admin rule-edit UI. Today's flow: edit YAML files in the backend's `rules/` dir (or a Git repo pointed at via `RULES_DIR` env), sensors pick up the change on next poll.

### Phase D — Location upgrades (1 week) ✅ **code complete**

Goal: every threat on the map is in the right place, indoors and out.

1. ✅ GPS support via `gpsd` — `LocationService._get_gps_location()` connects to `127.0.0.1:2947`, requests JSON TPV reports, returns `{lat, lon, accuracy, source: "gps"}` when mode ≥ 2. Honours a 5s timeout.
2. ✅ WiFi positioning — `_get_wifi_location()` scans nearby BSSIDs via `iw dev <iface> scan`, POSTs to Mozilla Location Service (free `?key=test`) by default; operators can set `wifi_positioning_api_key` to use Google's API instead.
3. ✅ Operator-pinned override — `location.manual_latitude` + `location.manual_longitude` in `config.yaml` skip all dynamic methods and report exact coordinates. Optional `manual_label` and `manual_accuracy` (default 10m).
4. ✅ Confidence indicator on the map — translucent `<Circle>` (radius = `accuracy_meters`, capped at 2km for display) under each marker, colour-coded by `location_method`. Legend updated.

Wire-level effect: every threat row now carries `accuracy_meters` + `location_method`, the backend migration creates those columns, the agent fills them via `BaseDetector.create_threat()`, and the dashboard renders the confidence circle.

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

## 6. Rule management model

Rules live in YAML files in `/etc/honeyman/rules/<category>/<rule-name>.yaml` on the sensor. There are three ways a rule gets there:

1. **Shipped with the agent** — packaged in the install script. The 35 default rules.
2. **Hand-edited locally** — operator SSHes in, edits a YAML file, the rule engine reloads on file-change (inotify on Linux).
3. **Pulled from the dashboard backend** — `GET /v2/rules` returns the current rule manifest. The agent polls this every 5 minutes and writes any new/changed rules to disk. Hand-edited rules are never overwritten (tracked by a `local: true` marker file).

Rule editing on the backend is intentionally low-tech for V2: a `rules/` directory in the backend's filesystem, version-controlled in a Git repo (e.g., `github.com/SecurityWard/honeyman-rules`). The backend serves whatever's in that directory. To change a rule, you `git push` to the rules repo. No web UI required for V2; one can be added later.

This means rule changes propagate without code redeployment, just as required.

---

## 7. Public dashboard scope

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

## 8. Open decisions

A few things I've made implicit choices on but you should confirm:

1. **Rules-from-Git vs rules-from-DB.** I'm assuming a `honeyman-rules` Git repo that the backend syncs from. Alternative: rules live in Postgres and are edited via a (rudimentary) web form. Git is simpler and gives free history; DB is better if you ever want non-developers to edit rules.

2. **WiFi positioning provider.** Mozilla Location Service is free and good but has been quietly deprecated/spun off; Google Geolocation costs money but is reliable. For now I'd default to MLS and let operators opt into Google with their own API key in `config.yaml`.

3. **Public dashboard hostname.** Right now it's `http://72.60.25.24:3000`. For a public deployment we want `https://dashboard.honeymanproject.com` or similar. Need a domain and Let's Encrypt cert.

4. **Sensor naming privacy.** Self-selected names with random suffixes (`defcon-hotel-7x9k`) — already designed. Operators may not want their physical location guessable. Consider letting operators flag a sensor as "hide exact location" — the map would show city-level only.

5. **Data retention default.** 90 days is in the schema; for a public dashboard, longer retention with aggressive aggregation (e.g., 7 days raw + 90 days aggregated) might be better. Decide before TimescaleDB compression policy is set.

---

## 9. Out of scope for V2

Explicit no-goes for this version, to prevent scope creep:

- Machine learning threat correlation
- SIEM integrations (Splunk, ELK, etc.)
- Multi-tenant support
- Mobile (Android/iOS) sensor app
- Incident response workflows
- User accounts in any form
- Paid subscriptions, billing, plans

---

## 10. Document map

```
README.md                    Public-facing intro + quick-start
HONEYMAN-V2-PLAN.md          This file (canonical plan)
ARCHITECTURE.mmd             Mermaid diagram of the system
CAPABILITIES.md              What Honeyman detects, accuracy, limitations
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
├── deployment/              VPS deployment configs (compose, nginx, etc.)
└── readme/onboarding/       install.sh, Mosquitto, Compose configs
```
