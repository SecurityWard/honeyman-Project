# Honeyman

Mobile, multi-vector threat collection for physical events.

Honeyman puts a Raspberry Pi-class sensor in a backpack, on a hotel-room desk, or in a conference hall — and reports malicious USB, WiFi, BLE, and AirDrop activity in real time to a public map. When the sensor is on a network, it can also expose SSH and HTTP honeypots and report intrusion attempts as events.

The design is deliberately small: a single `curl | bash` install,
a public read-only dashboard with no user accounts, and YAML detection
rules that update without reflashing sensors.

> **For contributors:** the canonical plan, current state, and build order live in [`docs/PROJECT-PLAN.md`](docs/PROJECT-PLAN.md). The architecture diagram is in [`docs/ARCHITECTURE.mmd`](docs/ARCHITECTURE.mmd) (Mermaid; renders on GitHub).

---

## What it detects

| Vector | Examples |
|---|---|
| **USB** | BadUSB / Rubber Ducky / Bash Bunny / OMG Cable, malicious VID/PID, suspicious volume labels (`STARKILLER`, `PAYLOAD`), autorun.inf abuse, and 600+ real malware hash signatures from abuse.ch MalwareBazaar (Mirai, AgentTesla, Formbook, RemcosRAT, Vidar, WannaCry, …) + EICAR, on self-mounted mass storage. |
| **WiFi** | Evil Twin APs, deauth flooding, beacon flooding, WiFi Pineapple / ESP8266 Deauther / Flipper Zero WiFi, suspicious SSIDs, WPS attacks. |
| **BLE** | Flipper Zero (incl. Unleashed/Xtreme firmware), BLE spam, Apple Continuity abuse, BLE HID keyloggers, ESP32 attack tools, manufacturer-data spoofing. |
| **AirDrop / mDNS** | Suspicious service names, generic device spoofing, rapid announcement floods, TXT-record abuse. |
| **Network honeypots** *(optional)* | SSH brute-force, HTTP credential harvesting, port scanning, service enumeration, web-attack probes. |

Every threat carries a location (GPS → WiFi-positioning → IP → operator-pinned), so events appear on the dashboard map at the right place, indoors or out.

For accuracy expectations and the explicit list of what Honeyman does *not* detect, see [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md).

---

## Architecture (in one paragraph)

A sensor runs the `honeyman-agent` Python package, which loads YAML detection rules and executes detector modules in parallel. When a rule matches, the agent attaches a location and POSTs the event to the dashboard backend over HTTPS using a per-sensor API key issued at install time. The backend (FastAPI + Postgres+TimescaleDB) stores threats in a 1-day-chunked hypertable with 90-day retention and 7-day compression. The React dashboard is publicly viewable: anyone can see the map, filter threats, and watch the live WebSocket feed. There are no user accounts and no actions to perform — it's a viewing surface. MQTT is supported as an optional alternative transport for high-volume sensors.

```
Sensor (Pi)  ──HTTPS──▶  Backend (FastAPI + TimescaleDB)  ──REST/WS──▶  Public Dashboard (React + Leaflet)
                              ▲
                              └── optional: MQTT/TLS
```

See [`docs/ARCHITECTURE.mmd`](docs/ARCHITECTURE.mmd) for the detailed diagram.

---

## Deploy a sensor

> ⚠️ The endpoints below assume a hosted deployment. If you're running your own backend, replace `api.honeymanproject.com` with your URL.

On a fresh Raspberry Pi (Pi Zero 2 W, Pi 4, or Pi 5):

```bash
curl -sSL https://honeymanproject.com/install | sudo bash
```

(The installer needs root — it writes to `/etc/honeyman`, `/var/lib/honeyman`, and installs a systemd unit.)

The installer will:

1. Detect available hardware (USB, WiFi adapter with monitor mode, Bluetooth)
2. Refuse to default WiFi/AirDrop on if the device has only one wireless adapter (would disconnect the installer from itself mid-run)
3. Ask you for a sensor name and (optional) location label
4. Install Python deps + the `honeyman-agent` package
5. Ship the malware-hash DB (600+ real MalwareBazaar signatures + EICAR) to `/var/lib/honeyman/malware_hashes.db` so the USB detector can scan files on plugged drives (it self-mounts read-only — no `usbmount` package needed)
6. Call `POST /api/v2/sensors/register` to claim a sensor ID and receive a one-time API key
7. Write the API key to `/etc/honeyman/api_key` (mode 0600, owner root)
8. Drop a systemd unit at `/etc/systemd/system/honeyman-agent.service` and start it

Within a minute or two, the sensor appears on the public dashboard.

For non-interactive installs (e.g. flashing many SD cards), pre-set the env vars:

```bash
curl -sSL https://honeymanproject.com/install | sudo \
  SENSOR_NAME="defcon-hotel" \
  LOCATION="DefCon 32 — Caesars Palace" \
  bash
```

---

## View the dashboard

**Public URL:** <https://dashboard.honeymanproject.com>

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

**Pull the latest defaults** — on any installed sensor, run `sudo honeyman-update`. It fetches the newest source, syncs the default rules into `/etc/honeyman/rules/` and refreshes the malware-hash DB, then restarts the agent. Rules you've customised locally are preserved (see the `.local` marker below).

**Locally on a sensor** — drop a YAML file into `/etc/honeyman/rules/<category>/` or edit an existing one, then `sudo systemctl restart honeyman-agent`. The agent loads everything under that tree at startup. To keep your edit from being overwritten by `honeyman-update` or central sync, drop an empty marker next to it: `touch /etc/honeyman/rules/<category>/<rule>.yaml.local`.

**Centrally** — open a PR against this repo's `agent/rules/` directory. CI validates every rule can actually fire (`agent/tests/validate_rules.py`). Sensors then pick it up via `sudo honeyman-update` (or `rule_sync.enabled: true`, which polls `GET /api/v2/rules`).

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

The default 35 rules live under [`agent/rules/`](agent/rules/).

---

## Repository layout

```
README.md                ← this file
CHANGELOG.md             release notes
SECURITY.md              threat model + per-PR review checklist
LICENSE                  MIT

agent/                   sensor-side Python package + 35 default rules
backend/                 FastAPI app (Pydantic 2, SQLAlchemy async)
frontend/                React + TypeScript dashboard
deployment/              nginx config, install.sh, ops timers, DEPLOY.md
docs/                    PROJECT-PLAN, CAPABILITIES, TESTING,
                         RELEASE-CHECKLIST, ARCHITECTURE.mmd
data/                    malware hash database (used by agent)
```

There is exactly one rule manifest tracked, under `agent/rules/`. The
backend serves it to sensors via `GET /api/v2/rules`; on the VPS, set
`RULES_DIR` in `backend/.env` if you need to point at something else.

---

## Status

**Live:** Pi sensors running against the production backend; the
dashboard, API, WebSocket feed, per-sensor click-through views, central
rule sync (opt-in poll), and the location chain (manual / GPS / WiFi /
IP with accuracy circles on the map) are all deployed. Nightly
Postgres backups, log rotation, and a 5-minute uptime probe are
running as systemd timers on the VPS.

**Open:** rule-quality tuning against real-world traffic, multi-sensor
deployments (one Pi in production today), end-to-end testing of the
WiFi and AirDrop detectors on a Pi 4 with a USB WiFi dongle, and
per-detector supervision so one crashing detector doesn't take the
agent down.

The canonical plan lives in [`docs/PROJECT-PLAN.md`](docs/PROJECT-PLAN.md);
release notes in [`CHANGELOG.md`](CHANGELOG.md); the test plan in
[`docs/TESTING.md`](docs/TESTING.md); the release-time runbook in
[`docs/RELEASE-CHECKLIST.md`](docs/RELEASE-CHECKLIST.md); the threat
model + per-PR checklist in [`SECURITY.md`](SECURITY.md); deployment
in [`deployment/DEPLOY.md`](deployment/DEPLOY.md).

---

## Contributing

- **Rules:** open PRs to the rules repo (link above). New detection signatures, MITRE ATT&CK mappings, false-positive tuning all welcome.
- **Code:** open PRs to this repo. Please match the design constraints in [`docs/PROJECT-PLAN.md`](docs/PROJECT-PLAN.md) — in particular: no user accounts, public read-only dashboard, sensors authenticate with API keys, rules are YAML-driven.
- **Bug reports:** GitHub Issues. Include sensor model, agent version (`honeyman-agent --version`), and the relevant chunk of `/var/log/honeyman/agent.log`.

---

## License

MIT — see [`LICENSE`](LICENSE).

---

## Disclaimer

Honeyman is a defensive monitoring tool. Deploy it only where you have the legal authority to do so. Capturing wireless traffic, running honeypots, and observing nearby Bluetooth devices may be regulated in your jurisdiction. The authors are not responsible for misuse.
