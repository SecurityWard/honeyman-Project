# Honeyman — Canonical Plan

**Status:** This is the single source of truth for the project. Earlier
design docs have been removed; `git log` has them if you need them.

Last updated: 2026-06-24

---

## 1. Vision

Honeyman is a **mobile, multi-vector threat collection platform**. Pi-class portable sensors detect malicious activity across USB, WiFi, BLE, AirDrop, and (when networked) act as canary SSH/HTTP honeypots. Detections are pushed to a publicly accessible dashboard that visualizes threats on a map and offers filtering — no user accounts, no actions, just a viewing surface.

**Three guiding principles:**

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

**Phases A through D are deployed and a real Pi Zero 2 W is reporting in.**
The remaining gaps are Phase E (canary toggle), Phase F (operability polish),
and rule-quality tuning. Numbers from production right now:

- 1 sensor (`honeyman0-1-e17b`, Pi Zero 2 W) on the public map
- USB + BLE + Network detectors all loading and producing threats
- Live WebSocket feed broadcasting via Redis from the HTTPS ingest path
- TimescaleDB 2.25 hypertable, 90-day retention, 7-day compression active
- Let's Encrypt TLS on `dashboard.honeymanproject.com` and
  `api.honeymanproject.com`
- `https://honeymanproject.com/install` serves the install script as
  `text/plain` so the curl-pipe-bash one-liner actually reaches a shell

| Component | Status |
|---|---|
| Agent core (orchestrator, plugin manager, config, heartbeat) | ✅ Deployed |
| Plugin manager class-name table | ✅ Deployed — explicit `(module, class)` map per detector key; aliases `bluetooth`→`ble` and rejects guessing |
| `UsbDetector` | ✅ Deployed — pyudev events, malware-hash DB loaded (360 sigs) |
| `BleDetector` | ✅ Deployed — bleak scanner, 5-second cadence |
| `NetworkDetector` | ✅ Deployed — OpenCanary webhook server on :8888 |
| `WifiDetector` | ⚠️ Built, off by default on single-adapter Pis (installer guards) |
| `AirDropDetector` | ⚠️ Built, off by default on single-adapter Pis (installer guards) |
| Rule engine + 37 YAML rules | ✅ Deployed and producing alerts |
| Per-(rule, target) cooldown in `BaseDetector` | ✅ Deployed — honours `tuning.cooldown_seconds` or derives from `tuning.max_alerts_per_hour` |
| Transport: HTTPS + per-sensor API key (default) | ✅ Deployed — Bearer auth on writes |
| MQTT transport (optional) | ✅ Built, `MQTT_OFFERED=false` in production |
| SQLite offline buffer | ✅ Deployed at `/var/lib/honeyman/buffer.db` |
| Location service (manual → GPS via gpsd → WiFi → IP) | ✅ Deployed — IP-fallback path in active use |
| Central rule sync (`GET /api/v2/rules`) | ✅ Deployed in backend; agent polling **disabled by default**, opt-in |
| Backend FastAPI app | ✅ Deployed at `api.honeymanproject.com`, systemd `honeyman-backend.service`, 4 workers |
| `POST /threats` publishes to Redis | ✅ Deployed — Phase-A regression fix for the empty live feed |
| Live sensor threat counts in `/sensors` list | ✅ Deployed — bulk GROUP BY at request time, no counter drift |
| API key issuance + validation | ✅ Deployed — SHA256-hashed per-sensor key, one-time return at register |
| Postgres + TimescaleDB | ✅ Deployed — hypertable + 90d retention + 7d compression policy active |
| Nginx + Let's Encrypt | ✅ Deployed — config snapshot in `honeyman-v2/deployment/nginx/honeyman.conf` |
| `/install` endpoint serving `install.sh` | ✅ Deployed (text/plain via nginx `location = /install`) |
| Frontend dashboard | ✅ Deployed at `dashboard.honeymanproject.com` |
| Frontend "Add Sensor" page | ✅ Deployed — includes a red **deliberate-risk** callout + amber single-adapter callout |
| Frontend "Sensors" page | ✅ Deployed — click a sensor row to filter `/dashboard?sensor_id=…` |
| Frontend "Real-time Threat Feed" | ✅ Deployed — expandable details for matched rule, hashes, MITRE, raw_event |
| Trends chart (`/analytics/trends`) | ✅ Deployed — fixed `date_trunc('hour'/'day'/'week')` (was raising on every call) |
| Sensor edit/detail UI | ❌ Not built — the click-filter dashboard view replaces the immediate need |
| Mosquitto broker on VPS | ⚠️ Configs in repo (`honeyman-v2/readme/onboarding/`), not deployed |

**No known integration bugs as of `dd87307`.** The four that were in this
section at the start of Phase A (MQTT topic mismatch, location field-name
mismatch, duplicate onboarding implementations, MQTT subscriber required
at startup) are all resolved.

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

### Phase A — Single sensor talks to the dashboard end-to-end ✅ **deployed**

Goal: a Pi shows up on the public map, sends a threat, the dot appears in
the right city.

All sub-steps complete. The Phase A operator script
(`honeyman-v2/deployment/phase_a_apply.sh`) ran successfully against the
production VPS; TimescaleDB is installed, the hypertable + retention +
compression policies are in place, and one Pi Zero 2 W has been
heartbeating since `dd87307` with 200+ real threat events.

### Phase B — Self-register onboarding ✅ **deployed**

Goal: a stranger runs `curl … | bash` and their sensor is on the map
within a few minutes.

All sub-steps complete plus several real-world fixes uncovered by the
first physical install:

- `install.sh` reattaches stdin to `/dev/tty` so prompts work under
  `curl | bash`
- single-WiFi-adapter detection — refuses to default WiFi/AirDrop on
  when there's only one wireless interface that's also the default route
- registration payload built via a quoted Python heredoc with env vars
  to handle bash booleans and special characters cleanly
- malware-hash DB now shipped to `/var/lib/honeyman/malware_hashes.db`
- `aiohttp` declared as a setup.py dependency (was silently missing)
- per-(rule, target) cooldown so the dashboard doesn't get flooded by
  the same rule firing repeatedly on the same nearby device
- Add Sensor page now leads with a red "you are deliberately inviting
  attacks" safety callout, then the amber single-adapter hardware note

### Phase C — Resilience + central rule sync ✅ **deployed**

SQLite offline buffer is in place. Rule sync endpoint is live; agent
poller is opt-in (disabled by default) and isn't being exercised on the
running Pi — that's expected: it should turn on once we have a rules Git
repo to point at.

### Phase D — Location chain ✅ **deployed**

Manual override + GPS via gpsd + WiFi positioning (MLS / Google) + IP
fallback. The Pi currently reports via the IP fallback path; the
dashboard renders the right confidence circle for it (gray, ~5 km).

### Phase E — Canary network stack toggle ✅ **mostly deployed**

`NetworkDetector` is loaded and its OpenCanary webhook server is bound
on port 8888 in production right now. The remaining bits:

1. ⏳ Add an explicit `canary_network.enabled: false` top-level switch
   to `config.yaml` so the OpenCanary server can be turned off without
   disabling the whole network detector (today, disable = no detector
   at all).
2. ⏳ Document the legal/operational implications of running honeypots
   on the network the sensor is on.
3. ⏳ Add a frontend filter / chip on the threat feed to view
   canary-derived events only.

### Phase F — Operability (ongoing)

| Item | Status |
|---|---|
| systemd unit for backend (`honeyman-backend.service`) | ✅ Deployed |
| systemd unit for agent (`honeyman-agent.service`) | ✅ Deployed by install.sh |
| Nginx + Let's Encrypt | ✅ Deployed — config snapshot in `honeyman-v2/deployment/nginx/honeyman.conf` |
| Mosquitto broker as separate service | ❌ Not deployed (HTTPS is primary) |
| `/health` JSON with broker, DB, ingestion rate | ⚠️ Basic `/health` exists; doesn't yet expose ingestion rate |
| Prometheus metrics | ❌ Not started |
| Log rotation | ❌ Not started — `/var/log/honeyman-backend.log` grows unbounded |
| Alerting (Slack webhook, email) | ❌ Not started |

### Phase G — Rule quality & tuning (new, ongoing)

Surfaced once we had a real sensor producing real data. The detectors
work; some rules are over-eager.

1. ⏳ Per-rule review — are the conditions specific enough that one
   firing carries useful signal? `mac_randomization` is the obvious
   example (matched every iPhone in BLE range until disabled).
2. ⏳ Add `tuning.cooldown_seconds` (or a meaningful
   `max_alerts_per_hour`) to every rule that's network/proximity-based.
   The per-(rule, target) cooldown enforces whatever value is declared;
   rules with neither field set are never throttled.
3. ⏳ Consider tiering rules into "high-signal" (default on) and
   "noisy" (default off, opt-in) sets.

### Phase H — Security review (new, scheduled)

See [`SECURITY.md`](SECURITY.md) for the full threat model and checklist.
The review covers two surfaces:

- **Dashboard / backend**: SQL injection (one `text(f"…")` usage with
  regex-validated input), XSS via raw_event JSON, WebSocket auth,
  sensor self-registration abuse, public read scope.
- **Onboarding / sensor**: `curl | bash` integrity (TLS only, no
  signature verification), system-wide pip install with
  `--break-system-packages`, the `ProtectSystem=strict` systemd
  hardening, malware-hash DB integrity.

---

## 6. Rule management model

Rules live in YAML files in `/etc/honeyman/rules/<category>/<rule-name>.yaml` on the sensor. There are three ways a rule gets there:

1. **Shipped with the agent** — packaged in the install script. The 35 default rules.
2. **Hand-edited locally** — operator SSHes in, edits a YAML file, the rule engine reloads on file-change (inotify on Linux).
3. **Pulled from the dashboard backend** — `GET /v2/rules` returns the current rule manifest. The agent polls this every 5 minutes and writes any new/changed rules to disk. Hand-edited rules are never overwritten (tracked by a `local: true` marker file).

Rule editing on the backend is intentionally low-tech: a `rules/` directory in the backend's filesystem, version-controlled in a Git repo (e.g., `github.com/SecurityWard/honeyman-rules`). The backend serves whatever's in that directory. To change a rule, you `git push` to the rules repo. No web UI required today; one can be added later.

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

3. ~~**Public dashboard hostname.** Right now it's `http://72.60.25.24:3000`. For a public deployment we want `https://dashboard.honeymanproject.com` or similar. Need a domain and Let's Encrypt cert.~~ **Resolved** — `dashboard.honeymanproject.com` and `api.honeymanproject.com` are live with Let's Encrypt certs; `honeymanproject.com` apex redirects to dashboard.

4. **Sensor naming privacy.** Self-selected names with random suffixes (`defcon-hotel-7x9k`) — already designed. Operators may not want their physical location guessable. Consider letting operators flag a sensor as "hide exact location" — the map would show city-level only.

5. **Data retention default.** 90 days is in the schema; for a public dashboard, longer retention with aggressive aggregation (e.g., 7 days raw + 90 days aggregated) might be better. Decide before TimescaleDB compression policy is set.

---

## 9. Out of scope

Explicit no-goes, to prevent scope creep:

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
PROJECT-PLAN.md              This file (canonical plan)
ARCHITECTURE.mmd             Mermaid diagram of the system
CAPABILITIES.md              What Honeyman detects, accuracy, limitations
CHANGELOG.md                 Release notes
LICENSE                      MIT
TESTING.md                   How to run tests + integration scenarios
RELEASE-CHECKLIST.md         Executable runbook for a release
SECURITY.md                  Threat model + per-PR review checklist

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
