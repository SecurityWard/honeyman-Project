# Honeyman test plan

Pragmatic test plan covering what's worth automating, what stays manual,
and what to re-check before every release. Organised by where the test
runs (sensor / backend / dashboard) and what flavour it is (unit /
integration / manual / regression).

Three guiding principles:

1. **Real network, real Pi, at least once per change** that touches the
   sensor or the install path. Mocked detectors miss too many failure
   modes (udev queueing, bluetooth `User=root` capability issues,
   single-adapter monitor-mode disconnects).
2. **Regression tests for every production bug** that bit us. The
   commits in CHANGELOG `Post-deploy fixes` are all candidates — they
   each shipped past the existing test suite and we should make sure
   they can't again.
3. **Run the manual smoke flow before pushing anything that touches the
   API surface.** It takes five minutes and catches schema drift that
   the unit tests don't.

---

## 1. Sensor side — agent + detectors

### 1.1 Unit tests (existing)

```bash
cd agent
pip install -e ".[dev]"
pytest tests/
```

Existing files under `agent/tests/`:

| File | What it covers |
|---|---|
| `test_usb_detector.py` | USB event parsing, malware-hash DB lookups, autorun.inf inspection |
| `test_wifi_detector.py` | scapy parsing, evil-twin detection logic |
| `test_ble_detector.py` (in the agent root) | BLE device tracking, manufacturer-data spoofing |
| `test_airdrop_detector.py` (in the agent root) | avahi-browse parsing, service-name patterns |
| `test_network_detector.py` (in the agent root) | OpenCanary log parsing |

### 1.2 Unit tests we still need

Bugs that shipped past the existing suite — each one becomes a test that
would have caught the regression:

- **Plugin manager class-name lookup.** Test that each name in the
  `detectors` table actually resolves to an importable class. Would
  have caught the `BluetoothDetector` / `AirdropDetector` typo regressions.
- **Detector constructor signature.** Parametric test that asserts every
  detector accepts `(rule_engine, transport, config, location_service)`
  as kwargs and forwards them to `BaseDetector` in the right order.
- **Per-(rule, target) cooldown.**
  - Same rule, same identity, second event within `cooldown_seconds` →
    filtered.
  - Same rule, same identity, second event after `cooldown_seconds` →
    passes.
  - Same rule, *different* identity → both pass.
  - Rule with no `tuning` → never filtered.
  - `tuning.cooldown_seconds: 60` wins over `max_alerts_per_hour: 100`.
- **`_event_identity` precedence.** Each key in the priority chain
  (`device_mac` → `src_host` → `service_name` → `device_id` → `ssid`
  → `bssid` → `file_hash` → `vendor:product:serial` → `anon`) wins
  when present.
- **`HoneymanAgent.start` does not call `/sensors/register`.**
  Regression for the spurious self-registration loop. Mock the
  transport; assert no calls whose topic is `'registration'`.
- **Install script registration payload shape.** Run the heredoc'd
  Python block with representative inputs and confirm
  `requested_name`/`capabilities`/`enabled_detectors` are present and
  bash booleans become Python booleans correctly.

### 1.3 Manual smoke — on a real Pi (Pi Zero 2 W or better)

Run these on any sensor that just installed. They cover the failure
modes the onboarding flow has historically hit.

| # | What | How | Pass criteria |
|---|---|---|---|
| S1 | Fresh install completes | `curl -sSL https://honeymanproject.com/install \| sudo HONEYMAN_API='https://api.honeymanproject.com' bash` | Last line says `Honeyman sensor installed`, exit code 0 |
| S2 | systemd unit enabled | `systemctl is-enabled honeyman-agent` | `enabled` |
| S3 | Service active | `systemctl is-active honeyman-agent` | `active` |
| S4 | All three detectors loaded | `journalctl -u honeyman-agent -n 50 \| grep "Loaded detector"` | Three lines: `usb`, `ble`, `network`. No `Failed to load detector` |
| S5 | Sensor shows on dashboard | open https://dashboard.honeymanproject.com/sensors | Sensor row appears, badge becomes `ONLINE` within 60s |
| S6 | Click-through to dashboard works | click the sensor row | Lands on `/dashboard?sensor_id=…`, banner visible, map centered on sensor |
| S7 | Reboot persistence | `sudo reboot`; wait 90s; recheck S2/S3/S5 | Same results after reboot |
| S8 | Detector toggle reflects in heartbeat | edit `/etc/honeyman/config.yaml` to disable `ble`; `systemctl restart honeyman-agent`; wait 90s | Sensor row `enabled_detectors` shows `["usb", "network"]` |

---

## 2. Detection accuracy — manual

Numbered by `T<vector><n>`. Each test produces a known stimulus and
expects a known threat to land within a target time. Pass criteria are
visible end-to-end (dashboard map + feed).

### USB

| # | Stimulus | Expected threat | Latency |
|---|---|---|---|
| TU1 | USB stick formatted `mkfs.vfat -F 32 -n STARKILLER` | `suspicious_volume` (medium) | ≤ 10s |
| TU2 | USB stick with `autorun.inf` at root | `autorun_abuse` (high) | ≤ 10s |
| TU3 | USB stick with a file whose SHA-256 is in `data/malware_hashes.db` (e.g. EICAR after manually adding the hash) | `malware_hash` (critical) | ≤ 30s |
| TU4 | Plug in a Hak5 Rubber Ducky (VID `0x03eb` PID `0x2401`) | `usb_rubber_ducky` (critical) | ≤ 2s |
| TU5 | Same Rubber Ducky plugged in twice within the cooldown | one threat, not two | per `tuning.cooldown_seconds` |

### BLE

| # | Stimulus | Expected | Notes |
|---|---|---|---|
| TB1 | Flipper Zero advertising | `flipper_zero_ble` (critical) | requires Flipper |
| TB2 | Plain neighbour iPhone in range | **no threat** (after the `mac_randomization` rule was disabled) | regression for the noise problem |
| TB3 | Same BLE device firing repeatedly | rate-limited per `cooldown_seconds` | watch agent log for `Throttled rule` debug lines |

### Network honeypot

| # | Stimulus | Expected | Notes |
|---|---|---|---|
| TN1 | `ssh root@<sensor-ip> -o PasswordAuthentication=yes` (any pw) | `ssh_brute_force` after 3 attempts | OpenCanary webhook |
| TN2 | `curl http://<sensor-ip>:8888/admin` with form data | `http_credential_harvesting` | |
| TN3 | nmap port scan | `port_scan` | one event, not one per port |

### WiFi *(only on Pis with a second WiFi adapter)*

| # | Stimulus | Expected |
|---|---|---|
| TW1 | `hostapd` raised with a known SSID also on a real AP | `evil_twin` |
| TW2 | `mdk4 wlan0mon b -s 200` (beacon flood) | `beacon_flooding` |

### AirDrop / mDNS

| # | Stimulus | Expected |
|---|---|---|
| TA1 | `avahi-publish-service "PWNED" _airdrop._tcp 80` | `airdrop_suspicious_name` |

---

## 3. Backend — FastAPI

### 3.1 Integration tests (run against a local Postgres + Redis)

```bash
cd backend
pip install -e ".[dev]"
pytest tests/
```

(Tests directory hasn't been spun up yet — this is the highest-priority
gap in the suite. The smoke flow below covers most of what the tests
should assert.)

### 3.2 Smoke flow

Run from any laptop with `curl` + `python3`. Reusable as a CI step.

```bash
BASE=https://api.honeymanproject.com

# 1. register
REG=$(curl -s -X POST $BASE/api/v2/sensors/register -H 'Content-Type: application/json' -d '{
  "requested_name":"test","capabilities":{"usb":true},"enabled_detectors":["usb"],
  "platform":"linux","agent_version":"2.0.0",
  "initial_location":{"latitude":37.77,"longitude":-122.42,"method":"manual","accuracy":100}
}')
SID=$(jq -r .sensor_id <<<"$REG"); KEY=$(jq -r .api_key <<<"$REG")

# 2. heartbeat
curl -s -X POST "$BASE/api/v2/sensors/$SID/heartbeat" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' -d "{
  \"sensor_id\":\"$SID\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S)\",\"is_online\":true,
  \"enabled_detectors\":[\"usb\"],\"system_info\":{\"cpu_percent\":1,\"memory_percent\":10,
  \"disk_percent\":10,\"uptime_seconds\":1},
  \"location\":{\"latitude\":37.77,\"longitude\":-122.42,\"method\":\"manual\",\"accuracy\":100}}" \
  | jq .

# 3. push a threat
curl -s -X POST $BASE/api/v2/threats -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' -d "{
  \"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S)\",\"sensor_id\":\"$SID\",
  \"threat_type\":\"usb_rubber_ducky\",\"detector_type\":\"usb\",\"severity\":\"critical\",
  \"threat_score\":0.95,\"confidence\":0.98,
  \"matched_rules\":[{\"rule_id\":\"usb_rubber_ducky_001\",\"name\":\"USB Rubber Ducky\",\"severity\":\"critical\",\"confidence\":0.98}],
  \"raw_event\":{\"vendor_id\":\"0x03eb\"},\"latitude\":37.77,\"longitude\":-122.42,
  \"accuracy_meters\":100,\"location_method\":\"manual\"}" | jq .

# 4. listing
curl -s "$BASE/api/v2/sensors" | jq '.sensors[] | {sensor_id, is_online, total_threats_detected, threats_last_24h}'
curl -s "$BASE/api/v2/threats?sensor_id=$SID" | jq '.items | length'

# 5. cleanup (run against the VPS, not over the API — no public delete)
ssh root@72.60.25.24 "sudo -u postgres psql -d honeyman_v2 -c \"DELETE FROM threats WHERE sensor_id='$SID'; DELETE FROM sensors WHERE sensor_id='$SID';\""
```

Pass criteria:

- step 1 returns 201 with `sensor_id` and `api_key`
- step 2 returns 200 with `{"message":"Heartbeat received"}`
- step 3 returns 201 with the persisted row including the UUID
- step 4 reports `total_threats_detected=1`, `threats_last_24h=1`, threat
  listing length 1
- The same threat appears on `https://dashboard.honeymanproject.com`
  within ~2 seconds of step 3, with the matched rule, raw_event, and
  MITRE tags rendered in the expandable feed row

### 3.3 Auth regression tests

```bash
# wrong key — expect 401
curl -i -X POST $BASE/api/v2/threats -H "Authorization: Bearer hms_garbage" \
  -H 'Content-Type: application/json' -d '{"timestamp":"…","sensor_id":"…","threat_type":"x","detector_type":"usb","severity":"low"}'

# right key, wrong sensor_id in body — expect 403
curl -i -X POST $BASE/api/v2/threats -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' -d '{"timestamp":"…","sensor_id":"someone-else","threat_type":"x","detector_type":"usb","severity":"low"}'

# no auth header — expect 401
curl -i -X POST $BASE/api/v2/threats -H 'Content-Type: application/json' -d '{…}'
```

### 3.4 WebSocket regression

```bash
# in one terminal
wscat -c wss://api.honeymanproject.com/api/v2/ws

# in another, fire the smoke flow from 3.2
# the wscat session should print {"type":"threat","data":{…full ThreatResponse…},…}
```

Without this test the empty-live-feed regression we just fixed could
have shipped silently.

### 3.5 Analytics regression

`/analytics/trends` was returning 500 with
`InvalidParameterValueError: unit 'hourly' not recognized`. Add a test
for each `period` value:

```bash
for p in hourly daily weekly; do
  echo -n "$p: "
  curl -s -o /dev/null -w "%{http_code}\n" "$BASE/api/v2/analytics/trends?period=$p"
done
# expect 200 200 200
```

---

## 4. Dashboard (frontend)

### 4.1 Build sanity

```bash
cd frontend
npm install
npm run build
```

Build should complete in ≤ 30s with no TypeScript errors.

### 4.2 Manual UI smoke

After every frontend deploy:

| # | Page | What to check |
|---|---|---|
| F1 | `/dashboard` | Map loads, marker visible for the running sensor, no console errors |
| F2 | `/dashboard` | Threat feed populated (REST seed) within ~2s of load |
| F3 | `/dashboard` | Push a threat via the smoke flow → new row appears in feed within ~2s (WS path) |
| F4 | `/dashboard` | Click a feed row → expands to show matched rule, hashes, MITRE, raw_event |
| F5 | `/dashboard` | Click a map marker → popup shows the same rich detail, no `NaN` anywhere |
| F6 | `/sensors` | At least one sensor row, total_threats_detected and threats_last_24h match the smoke-flow numbers |
| F7 | `/sensors` | Hover row → shows "→ view threats" hint. Click → navigates to `/dashboard?sensor_id=…` |
| F8 | `/dashboard?sensor_id=…` | Blue filter banner visible with sensor name + clear-filter button + back-link |
| F9 | `/dashboard?sensor_id=…` | "Clear filter" returns to `/dashboard`, banner gone, broadcasts unfiltered again |
| F10 | `/add-sensor` | Red "deliberately inviting attacks" callout appears first, then the amber single-adapter caveat. Both readable (no white text on tan) |
| F11 | `/add-sensor` | Copy button copies the right URL (`honeymanproject.com/install`, not `honeyman.io`) |
| F12 | `/about` | All text renders dark (no white-on-light regression from the index.css `:root` dark default) |

### 4.3 Stale-field regression

The frontend `Threat` and `Sensor` types were drifted from the backend
schemas. Bake into CI: for every API endpoint the dashboard consumes,
fetch one real response and compare keys against the TypeScript
interface. Any key in the response that's not in the interface (or
vice-versa) fails.

---

## 5. End-to-end (E2E)

The shortest meaningful E2E is the manual smoke flow run against the
deployed stack with a real Pi powering up cold. Replace any individual
sub-flow above with the deployed equivalent — it covers the same paths
with real wire-level behaviour.

For a release E2E:

1. Wipe the running Pi: stop the agent, `rm -rf /etc/honeyman
   /var/lib/honeyman /var/log/honeyman /opt/honeyman`, remove the
   systemd unit.
2. Wipe the DB: `DELETE FROM threats; DELETE FROM sensors;` on the VPS.
3. From the Pi: `curl -sSL https://honeymanproject.com/install | sudo
   HONEYMAN_API='https://api.honeymanproject.com' bash`. Answer the
   prompts.
4. Run S1–S8 from §1.3.
5. Run TU1, TU2, TB3, TN1 from §2.
6. Run F1–F12 from §4.2.

If all 23 checks pass on a fresh Pi against the live VPS, the release
is good to tag.

---

## 6. Performance & scale (not yet measured)

Not measured in production yet. When we have a second sensor:

- **Threat ingest rate.** How many `POST /threats` per second can the
  backend sustain before the Redis publish becomes a bottleneck? The
  protocol handler batches drains of the offline buffer at 100 at a
  time, so floor is ~100/min/sensor.
- **WebSocket fanout.** How many simultaneous WS subscribers before
  `broadcast()`'s `for connection in self.active_connections` becomes
  expensive? Cheap measurement: open N tabs and `console.log` the
  inter-frame delta on each.
- **Postgres + TimescaleDB.** Already in a hypertable; the long-term
  question is whether the GROUP BYs in `/sensors` and
  `/analytics/trends` stay sub-100ms past ~10⁷ rows. Watch
  `pg_stat_statements`.

---

## 7. CI suggestions (not yet wired up)

Cheap wins to add to whatever CI gets stood up:

- `pytest agent/tests/` on push
- `cd frontend && npm run build` on push
- `python -m py_compile $(git ls-files 'backend/**/*.py')`
- `bash -n deployment/install.sh`
- The auth-regression curls from §3.3 against a throw-away backend
- The analytics regression from §3.5

---

## 8. What we still aren't testing

Honest list — these matter and aren't covered yet:

- **Real WiFi monitor mode** (no second WiFi-capable test Pi)
- **GPS** path of `LocationService` (no test box with a GPS HAT)
- **OpenCanary integration** with all its built-in honeypots (only the
  webhook receiver was exercised on the running sensor)
- **Rule sync via `/api/v2/rules`** end-to-end (opt-in poller never
  enabled in production)
- **Mosquitto / MQTT transport** end-to-end (not deployed)
- **Backwards-compatibility of the rule schema** as we add fields
- **Log rotation** on the backend (`/var/log/honeyman-backend.log`
  grows unbounded today)

Address these as the relevant phase gets deployed.
