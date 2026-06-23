# Honeyman

Mobile, multi-vector threat collection for physical events.

Honeyman puts a Raspberry Pi-class sensor in a backpack, on a hotel-room desk, or in a conference hall — and reports malicious USB, WiFi, BLE, and AirDrop activity in real time to a public map. When the sensor is on a network, it can also expose SSH and HTTP honeypots and report intrusion attempts as events.

V1 launched at DefCon. V2 (this branch) is a redesign: simpler to deploy, public read-only dashboard, no user accounts, central YAML rules that update without reflashing sensors.

> **For contributors:** the canonical plan, current state, and build order live in [`HONEYMAN-V2-PLAN.md`](HONEYMAN-V2-PLAN.md). The architecture diagram is in [`ARCHITECTURE.mmd`](ARCHITECTURE.mmd) (Mermaid; renders on GitHub).

---

## What it detects

| Vector | Examples |
|---|---|
| **USB** | BadUSB / Rubber Ducky / Bash Bunny / OMG Cable, malicious VID/PID, suspicious volume labels (`STARKILLER`, `PAYLOAD`), autorun.inf abuse, and 360+ malware hash signatures (Stuxnet, Conficker, WannaCry, Mimikatz, Hak5 payloads, …) on auto-mounted mass storage. |
| **WiFi** | Evil Twin APs, deauth flooding, beacon flooding, WiFi Pineapple / ESP8266 Deauther / Flipper Zero WiFi, suspicious SSIDs, WPS attacks. |
| **BLE** | Flipper Zero (incl. Unleashed/Xtreme firmware), BLE spam, Apple Continuity abuse, BLE HID keyloggers, ESP32 attack tools, manufacturer-data spoofing. |
| **AirDrop / mDNS** | Suspicious service names, generic device spoofing, rapid announcement floods, TXT-record abuse. |
| **Network honeypots** *(optional)* | SSH brute-force, HTTP credential harvesting, port scanning, service enumeration, web-attack probes. |

Every threat carries a location (GPS → WiFi-positioning → IP → operator-pinned), so events appear on the dashboard map at the right place, indoors or out.

For accuracy expectations and the explicit list of what Honeyman does *not* detect, see [`CAPABILITIES.md`](CAPABILITIES.md).

---

## Architecture (in one paragraph)

A sensor runs the `honeyman-agent` Python package, which loads YAML detection rules and executes detector modules in parallel. When a rule matches, the agent attaches a location and POSTs the event to the dashboard backend over HTTPS using a per-sensor API key issued at install time. The backend (FastAPI + Postgres+TimescaleDB) stores threats in a 1-day-chunked hypertable with 90-day retention and 7-day compression. The React dashboard is publicly viewable: anyone can see the map, filter threats, and watch the live WebSocket feed. There are no user accounts and no actions to perform — it's a viewing surface. MQTT is supported as an optional alternative transport for high-volume sensors.

```
Sensor (Pi)  ──HTTPS──▶  Backend (FastAPI + TimescaleDB)  ──REST/WS──▶  Public Dashboard (React + Leaflet)
                              ▲
                              └── optional: MQTT/TLS
```

See [`ARCHITECTURE.mmd`](ARCHITECTURE.mmd) for the detailed diagram.

---

## Deploy a sensor

> ⚠️ The endpoints below assume a hosted deployment. If you're running your own backend, replace `api.honeymanproject.com` with your URL.

On a fresh Raspberry Pi (Pi Zero 2 W, Pi 4, or Pi 5):

```bash
curl -sSL https://honeymanproject.com/install | bash
```

The installer will:

1. Detect available hardware (USB, WiFi adapter with monitor mode, Bluetooth)
2. Ask you for a sensor name and (optional) location label
3. Install Python deps + the `honeyman-agent` package
4. Call `POST /api/v2/sensors/register` to claim a sensor ID and receive a one-time API key
5. Write the API key to `/etc/honeyman/credentials` (mode 0600, owner root)
6. Drop a systemd unit at `/etc/systemd/system/honeyman.service` and start it

Within a minute or two, the sensor appears on the public dashboard.

For non-interactive installs (e.g. flashing many SD cards), pre-set the env vars:

```bash
curl -sSL https://honeymanproject.com/install | \
  SENSOR_NAME="defcon-hotel" \
  LOCATION="DefCon 32 — Caesars Palace" \
  bash
```

---

## View the dashboard

**Public URL:** http://72.60.25.24:3000  *(will move to `https://dashboard.honeymanproject.com` when DNS is set up)*

The dashboard shows:

- A world map with color-coded threat markers (red/orange/yellow/blue by severity)
- Filters for time range, sensor, threat type, severity, detector category
- A live WebSocket feed of the most recent threats
- Stat cards (totals, critical count, threats/hr, active sensors)
- A list of every registered sensor with last-seen and threat count

There is no login. There are no actions. It's a viewing surface.

---

## Custom rules

Detection rules are YAML files. Each sensor ships with the default rule set under `/etc/honeyman/rules/<category>/`. To add or modify rules:

**Locally on a sensor** — edit any YAML file in `/etc/honeyman/rules/`. The rule engine reloads on file change (inotify); no restart needed.

**Centrally** — open a PR against the public rules repo at [`github.com/SecurityWard/honeyman-rules`](https://github.com/SecurityWard/honeyman-rules) *(planned)*. Sensors poll `GET /api/v2/rules` every 5 minutes and write any new/changed rules to disk; locally-edited rules are never overwritten.

A rule looks like:

```yaml
rule_id: usb_rubber_ducky_001
name: "USB Rubber Ducky (Hak5)"
version: 2.0
enabled: true
severity: critical
threat_type: usb_rubber_ducky
category: usb

conditions:
  operator: AND
  clauses:
    - type: device
      field: vendor_id
      operator: equals
      value: "0x03eb"
    - type: device
      field: product_id
      operator: equals
      value: "0x2401"

actions:
  - type: alert_dashboard
    priority: critical
  - type: local_log
    severity: critical

metadata:
  mitre_attack: [T1200, T1052.001]
  tags: [hak5, hid_injection]
  description: "USB Rubber Ducky — HID-injection attack tool from Hak5"
  confidence: 0.98
```

The default 35 rules live under [`honeyman-v2/agent/rules/`](honeyman-v2/agent/rules/).

---

## Repository layout

```
README.md                    ← this file
HONEYMAN-V2-PLAN.md          canonical V2 plan & status
ARCHITECTURE.mmd             V2 architecture diagram (Mermaid)
CAPABILITIES.md              what V2 detects, accuracy, limitations
CHANGELOG.md                 release notes
TESTING.md                   how to run the test suites
LICENSE                      MIT

data/                        malware hash database (used by agent)
honeyman-v2/
  agent/                     sensor-side Python package + 35 default rules
  dashboard-v2/
    backend/                 FastAPI app
    frontend/                React + TypeScript dashboard
  deployment/                DEPLOY.md, phase_a_apply.sh, ops scripts
  readme/onboarding/         install.sh + Mosquitto + Compose configs
```

The V1 codebase, removed-auth/onboarding chunks, and earlier V2 design docs
have been deleted; `git log` preserves them if you ever need to fish one
out.

---

## Status

V2 is **under active development.** Phases A–D are code-complete; Phases E (canary network toggle) and F (operability — systemd, TLS, metrics) are not started.

| Phase | What | Code | Deployed |
|---|---|---|---|
| Cleanup | Archive V1, strip JWT/users, single canonical plan | ✅ done | ⏳ partial |
| A | Sensor ↔ backend end-to-end (HTTPS + per-sensor API key, schema alignment) | ✅ done | ⏳ awaiting `phase_a_apply.sh` |
| B | Self-register onboarding (`install.sh` + dashboard's Add Sensor page) | ✅ done | ⏳ awaiting deploy + real-Pi test |
| C | Resilience + central rule sync (SQLite offline buffer, `GET /api/v2/rules`, agent poller) | ✅ done, unit tested | ❌ awaiting deploy |
| D | Location chain — manual override → GPS via gpsd → WiFi positioning (MLS / Google) → IP. Every threat carries `accuracy_meters` + `location_method`, dashboard map renders a confidence circle | ✅ done, unit tested | ❌ awaiting deploy |
| E | Optional SSH/HTTP canary toggle + frontend filter | — | — |
| F | Operability — systemd units, TLS, Prometheus, alerting | — | — |

Real-Pi smoke test (`curl ... | bash` on a Pi 4, watch it appear on the map) is the next milestone. The full plan and per-phase notes live in [`HONEYMAN-V2-PLAN.md`](HONEYMAN-V2-PLAN.md); release notes are in [`CHANGELOG.md`](CHANGELOG.md); deployment runbook is at [`honeyman-v2/deployment/DEPLOY.md`](honeyman-v2/deployment/DEPLOY.md).

---

## Contributing

- **Rules:** open PRs to the rules repo (link above). New detection signatures, MITRE ATT&CK mappings, false-positive tuning all welcome.
- **Code:** open PRs to this repo. Please match the V2 design constraints in `HONEYMAN-V2-PLAN.md` — in particular: no user accounts, public read-only dashboard, sensors authenticate with API keys, rules are YAML-driven.
- **Bug reports:** GitHub Issues. Include sensor model, agent version (`honeyman-agent --version`), and the relevant chunk of `/var/log/honeyman/agent.log`.

---

## License

MIT — see [`LICENSE`](LICENSE).

---

## Disclaimer

Honeyman is a defensive monitoring tool. Deploy it only where you have the legal authority to do so. Capturing wireless traffic, running honeypots, and observing nearby Bluetooth devices may be regulated in your jurisdiction. The authors are not responsible for misuse.
