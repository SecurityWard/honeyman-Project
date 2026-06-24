# Release checklist — verify all capabilities front-to-back

Run this whenever something significant ships, before tagging a release,
and after any deploy that touched the agent or the backend. It's the
operational counterpart to [`TESTING.md`](TESTING.md) (which is the
*planning* doc); this is the *execution* doc.

Pass criteria are explicit; tick a `[x]` only when the criterion is
met. Each block is independent — you can run them out of order if a
hardware piece isn't available right now (BLE without a Flipper, WiFi
without a second adapter, etc.).

Tag legend:

- `MUST` — production-blocking. If any of these fails, don't tag.
- `SHOULD` — important; document the failure and decide whether to ship.
- `NICE` — extra coverage; failure is informational.

Substitute these placeholders where you see them:

| Placeholder | Meaning |
|---|---|
| `$API` | `https://api.honeymanproject.com` (or your backend) |
| `$DASH` | `https://dashboard.honeymanproject.com` (or your dashboard) |
| `$SID` | sensor_id from the smoke flow (e.g. `honeyman0-1-XXXX`) |
| `$KEY` | API key from `POST /sensors/register` |
| `$VPS` | the operator's SSH target (e.g. `root@72.60.25.24`) |
| `$PI`  | the sensor's hostname / IP |

---

## A. Sensor onboarding (MUST)

### A1 — Fresh install on a clean Pi completes without error

```bash
# On the Pi
sudo systemctl stop honeyman-agent 2>/dev/null || true
sudo systemctl disable honeyman-agent 2>/dev/null || true
sudo rm -rf /etc/honeyman /var/lib/honeyman /var/log/honeyman /opt/honeyman
sudo rm -f /etc/systemd/system/honeyman-agent.service
sudo systemctl daemon-reload

curl -sSL https://honeymanproject.com/install \
  | sudo HONEYMAN_API="$API" bash 2>&1 | tee /tmp/install.log
```

- [ ] Last line of output: `Honeyman sensor installed`
- [ ] Exit code 0 (`echo $?` immediately after)
- [ ] `Registered as: honeyman0-1-XXXX` appears in the log
- [ ] `[OK] Default rules installed (37 files)` or higher count
- [ ] `[OK] Malware hash DB installed (188416 bytes)` (or similar size)

### A2 — systemd unit is enabled and active

```bash
sudo systemctl is-active honeyman-agent
sudo systemctl is-enabled honeyman-agent
```

- [ ] Both return `active` and `enabled`

### A3 — Agent log shows clean startup

```bash
sudo tail -n 100 /var/log/honeyman/agent.log | grep -E "Loaded detector|Loaded malware|subsystems|Heartbeat service|Failed|Error"
```

- [ ] `Loaded detector: usb`, `Loaded detector: ble`, `Loaded detector: network` all present
- [ ] `Loaded malware hash database: 360 signatures` (or higher)
- [ ] `USB detector initialized (subsystems: usb, block)`
- [ ] `Heartbeat service started (interval=60s)`
- [ ] **No** `Failed to load detector`
- [ ] **No** `Error` / `ERROR` lines

### A4 — Sensor appears online on the dashboard

```bash
sleep 60                # let the first heartbeat through
curl -s "$API/api/v2/sensors" | python3 -c "
import sys, json
for s in json.load(sys.stdin)['sensors']:
    print(s['sensor_id'], 'online=' + str(s['is_online']),
          'detectors=' + ','.join(s['enabled_detectors']))
"
```

- [ ] The new sensor's row prints `online=True`
- [ ] `enabled_detectors` contains `usb`, `ble`, and `network`

### A5 — Reboot persistence

```bash
sudo reboot
# wait ~90s, SSH back in
sudo systemctl is-active honeyman-agent
```

- [ ] `active` after reboot, no manual intervention required

### A6 — Single-adapter Pi guard fires (only on single-WiFi devices)

In `/tmp/install.log` from A1:

- [ ] On a Pi Zero W / Zero 2 W: `[!] only one WiFi adapter, and it is the default route — WiFi detection will be off by default`
- [ ] On the same: `enabled_detectors` from A4 contains `usb`, `ble`, `network` but **not** `wifi` or `airdrop`

---

## B. USB detection (MUST for production)

Setup: open one terminal on the Pi with `sudo tail -f /var/log/honeyman/agent.log` and another with `watch -n 5 'curl -s "$API/api/v2/threats?page_size=10" | python3 -m json.tool | grep -E "threat_type|severity"'`.

### B1 — `STARKILLER` volume label fires `suspicious_volume`

```bash
# format any throwaway USB stick (DOUBLE-CHECK THE DEVICE)
sudo mkfs.vfat -F 32 -n "STARKILLER" /dev/sdX1
```

Plug the stick into the Pi.

- [ ] Agent log: `USB partition: dev=/dev/sdX1 label='STARKILLER' vid_pid=...`
- [ ] Agent log: `UsbDetector reported threat: suspicious_volume (severity=medium, ...)`
- [ ] Dashboard map: yellow marker appears at the sensor location within ~5s
- [ ] Threat feed expandable row shows rule `usb_volume_label_001`

### B2 — Canonical Rubber Ducky (Hak5 03eb:2401) fires `rubber_ducky`

Plug in a stock Hak5 Rubber Ducky.

- [ ] Agent log: `Analyzing USB device: ... [03eb:2401]`
- [ ] Agent log: `UsbDetector reported threat: rubber_ducky (severity=critical, ...)`
- [ ] Dashboard map: red marker appears
- [ ] Threat feed expandable row shows rule `usb_rubber_ducky_001`

### B3 — VID/PID-spoofed Ducky (Apple-VID variant) fires `rubber_ducky`

Plug in a Ducky variant that reports `vid=05ac pid=0220` with `Product: HID Keyboard and MSC`.

- [ ] Agent log: `Analyzing USB device: HID_Keyboard_and_MSC [05ac:0220]`
- [ ] Agent log: `UsbDetector reported threat: rubber_ducky` (same rule, v2.1 catches it via product-name or behavioural HID+MSC clause)
- [ ] Dashboard map: red marker

### B4 — Malware-hash USB fires `malware_hash`

Plug in a USB drive containing a file whose SHA-256 is in
`/var/lib/honeyman/malware_hashes.db`. (Use one of the documented test
hashes or add an EICAR hash to the DB for a controlled test.)

- [ ] Agent log: `USB partition: ...` then `Mounted /dev/sdX1 at /run/honeyman/usb/...` then `UsbDetector reported threat: malware_hash`
- [ ] Dashboard: red marker, raw_event in the expanded feed row shows the file path + hash

### B5 — Cooldown silences repeated plug-ins of the same device

Unplug the Rubber Ducky from B2/B3, wait 30 seconds, plug back in.

- [ ] Agent log debug line: `Throttled rule usb_rubber_ducky_001 for ...`
- [ ] **No** second `rubber_ducky` threat sent to backend (verify via `/api/v2/threats?sensor_id=$SID&threat_type=rubber_ducky` — count unchanged)

---

## C. BLE detection (SHOULD)

### C1 — BLE detector scanning loop is alive

```bash
sudo tail -f /var/log/honeyman/agent.log | grep -i ble
```

- [ ] At least one `Starting BLE detection` line in the last minute

### C2 — Suspicious-name BLE device fires (needs a Flipper Zero or a phone advertising a device with a spoofed name like `Pwn3d`)

- [ ] Agent log: `BleDetector reported threat: suspicious_device_name` (or `flipper_zero` if it's an actual Flipper)
- [ ] Dashboard map: marker appears

### C3 — `mac_randomization` rule stays disabled (regression guard)

```bash
curl -s "$API/api/v2/threats?threat_type=mac_randomization&page_size=1" | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])"
```

- [ ] Returns 0 — the disabled rule is not firing. (If non-zero, someone re-enabled the noisy rule without thinking.)

---

## D. Network honeypot (SHOULD)

### D1 — OpenCanary webhook port is bound

```bash
ssh $PI 'ss -tlnp | grep :8888'
```

- [ ] One line showing the agent (`python3`) listening on `0.0.0.0:8888`

### D2 — SSH brute-force lands in the feed

```bash
# from any laptop on the same network as the Pi
for i in 1 2 3 4; do
  ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password \
      -o NumberOfPasswordPrompts=1 nobody@$PI 2>/dev/null
done
```

- [ ] Agent log: `NetworkDetector reported threat: ssh_brute_force` after the threshold (default 3 attempts)
- [ ] Dashboard: feed row shows `ssh_brute_force`, raw_event includes the source IP

### D3 — HTTP honeypot logs a probe

```bash
curl -s -m 3 http://$PI:8888/admin -d 'username=admin&password=admin' -o /dev/null -w '%{http_code}\n'
```

- [ ] HTTP response code returned (the response body is irrelevant)
- [ ] Agent log: `NetworkDetector reported threat: http_credential_harvesting`

---

## E. Backend ingest path (MUST)

### E1 — Smoke flow (register → heartbeat → threat → read) succeeds

```bash
BASE=$API
REG=$(curl -s -X POST $BASE/api/v2/sensors/register -H 'Content-Type: application/json' -d '{
  "requested_name":"checklist-smoke","capabilities":{"usb":true},"enabled_detectors":["usb"],
  "platform":"linux","agent_version":"2.0.0",
  "initial_location":{"latitude":37.77,"longitude":-122.42,"method":"manual","accuracy":100}
}')
SID=$(jq -r .sensor_id <<<"$REG"); KEY=$(jq -r .api_key <<<"$REG")

# heartbeat
curl -s -o /dev/null -w "HB %{http_code}\n" -X POST "$BASE/api/v2/sensors/$SID/heartbeat" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d "{
  \"sensor_id\":\"$SID\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S)\",\"is_online\":true,
  \"enabled_detectors\":[\"usb\"],\"system_info\":{\"cpu_percent\":1,\"memory_percent\":10,
  \"disk_percent\":10,\"uptime_seconds\":1},
  \"location\":{\"latitude\":37.77,\"longitude\":-122.42,\"method\":\"manual\",\"accuracy\":100}}"

# threat
curl -s -o /dev/null -w "T %{http_code}\n" -X POST $BASE/api/v2/threats -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' -d "{
  \"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S)\",\"sensor_id\":\"$SID\",
  \"threat_type\":\"usb_rubber_ducky\",\"detector_type\":\"usb\",\"severity\":\"critical\",
  \"threat_score\":0.95,\"confidence\":0.98,
  \"matched_rules\":[{\"rule_id\":\"usb_rubber_ducky_001\",\"name\":\"Rubber Ducky\",\"severity\":\"critical\",\"confidence\":0.98}],
  \"raw_event\":{\"vendor_id\":\"0x05ac\"},\"latitude\":37.77,\"longitude\":-122.42,
  \"accuracy_meters\":100,\"location_method\":\"manual\"}"

# list
curl -s "$BASE/api/v2/threats?sensor_id=$SID" | python3 -c "import sys, json; d=json.load(sys.stdin); print('count', len(d.get('items', [])))"

# cleanup (against the VPS, not the API)
ssh $VPS "sudo -u postgres psql -d honeyman_v2 -c \"DELETE FROM threats WHERE sensor_id='$SID'; DELETE FROM sensors WHERE sensor_id='$SID';\""
```

- [ ] Register: `HTTP 201` with `sensor_id` + `api_key` in body
- [ ] Heartbeat: `HB 200`
- [ ] Threat: `T 201`
- [ ] List: `count 1`

### E2 — Auth — wrong key returns 401

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST $API/api/v2/threats \
  -H "Authorization: Bearer hms_garbage" -H 'Content-Type: application/json' \
  -d '{"timestamp":"2026-01-01T00:00:00","sensor_id":"x","threat_type":"x","detector_type":"usb","severity":"low"}'
```

- [ ] Returns `401`

### E3 — Auth — valid key but wrong sensor_id in body returns 403

```bash
# Use the $KEY from E1 (before cleanup) and a different sensor_id in the body
curl -s -o /dev/null -w "%{http_code}\n" -X POST $API/api/v2/threats \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"timestamp":"2026-01-01T00:00:00","sensor_id":"someone-else","threat_type":"x","detector_type":"usb","severity":"low"}'
```

- [ ] Returns `403`

### E4 — Rate limit kicks in after 10 quick registers

```bash
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
  curl -s -o /dev/null -w "$i %{http_code}\n" -X POST $API/api/v2/sensors/register \
    -H 'Content-Type: application/json' -d "{
    \"requested_name\":\"rl-checklist-$i\",\"capabilities\":{\"usb\":true},
    \"enabled_detectors\":[\"usb\"],\"platform\":\"linux\",\"agent_version\":\"x\"
  }"
done
ssh $VPS "sudo -u postgres psql -d honeyman_v2 -c \"DELETE FROM sensors WHERE name LIKE 'rl-checklist-%';\""
```

- [ ] Requests 1–10 return 201
- [ ] Requests 11 and 12 return 429

### E5 — Body-size limit rejects oversize POST

```bash
yes "x" | head -c 300000 > /tmp/big.bin
curl -s -o /dev/null -w "%{http_code}\n" -X POST $API/api/v2/threats \
  -H "Authorization: Bearer hms_garbage" -H 'Content-Type: application/json' \
  --data-binary @/tmp/big.bin
rm -f /tmp/big.bin
```

- [ ] Returns `413` (before auth gets a look, nginx caught it)

---

## F. Dashboard UI (MUST)

Open `$DASH` in a browser. For each: pass = visible without console errors.

- [ ] **F1** — `/dashboard` loads. Map renders, marker for at least one sensor visible, no red errors in the browser console.
- [ ] **F2** — Threat feed has rows within ~2s of page load (REST seed).
- [ ] **F3** — Push a synthetic threat via the E1 snippet — new row appears in the feed within ~2s (WS path).
- [ ] **F4** — Click a feed row — it expands and shows: matched rule name + rule_id, confidence/score, MITRE tags as clickable links to attack.mitre.org, raw_event as pretty-printed JSON.
- [ ] **F5** — Click a map marker — popup shows the same rich detail. **No `NaN%`** anywhere.
- [ ] **F6** — `/sensors` shows the running sensor with correct counts and `→ view threats` on hover.
- [ ] **F7** — Click the sensor row — navigates to `/dashboard?sensor_id=…`, blue filter banner with sensor name + clear button visible.
- [ ] **F8** — Click "clear filter" — returns to `/dashboard`, banner gone.
- [ ] **F9** — `/add-sensor` — red "deliberately inviting attacks" callout appears first, then amber single-adapter caveat, both readable (no white text on tan).
- [ ] **F10** — `/about` — all paragraphs render dark, no inherited `rgba(255,255,255,…)` text on white.
- [ ] **F11** — Browser dev tools → Network → reload `/dashboard`. The WebSocket request to `wss://api.honeymanproject.com/api/v2/ws` returns status `101 Switching Protocols`.
- [ ] **F12** — Charts (`Threat Trends`, `Top Threats`, `Top Sensors`) populate with bars or lines, not empty.

---

## G. Persistence and recovery (SHOULD)

### G1 — Agent restart preserves sensor identity

```bash
ssh $PI 'sudo systemctl restart honeyman-agent && sleep 5 && sudo tail -n 20 /var/log/honeyman/agent.log | grep -E "sensor_id|Heartbeat"'
```

- [ ] No new registration POST in the backend log
- [ ] Sensor stays online with the same `sensor_id` after restart

### G2 — Offline buffer survives network drop

```bash
# On the Pi, block egress to the backend briefly
sudo iptables -A OUTPUT -d $(getent hosts api.honeymanproject.com | awk '{print $1}') -j DROP
sleep 120
sudo iptables -D OUTPUT -d $(getent hosts api.honeymanproject.com | awk '{print $1}') -j DROP
```

- [ ] During the block, agent log shows `Queued message after send failure (depth=…)`
- [ ] After the block: `Flushing N queued messages`
- [ ] `/api/v2/sensors/$SID` reports `is_online=True` again within ~2 minutes

---

## H. Operability (SHOULD)

### H1 — Backend log file perms tightened (Audit OPS-1)

```bash
ssh $VPS 'ls -la /var/log/honeyman-backend.log'
```

- [ ] Mode is `-rw-r-----` (0640) or stricter

### H2 — Rate limiter active log line on backend startup

```bash
ssh $VPS 'sudo systemctl restart honeyman-backend && sleep 3 && tail -n 30 /var/log/honeyman-backend.log | grep -i "rate limit"'
```

- [ ] `Rate limiting active` appears in fresh startup output

### H3 — WebSocket connection cap log fires when overshooting

```bash
# From any laptop; needs node's `wscat` or similar
for i in $(seq 1 510); do (wscat -c wss://api.honeymanproject.com/api/v2/ws --no-color > /dev/null 2>&1 &) ; done
sleep 5
ssh $VPS 'tail -n 100 /var/log/honeyman-backend.log | grep -i "Refusing WebSocket"' | head -3
pkill wscat 2>/dev/null
```

- [ ] At least one `Refusing WebSocket connect: at cap (500/500)` in the backend log
- [ ] Browser dashboard still works after the test (cap doesn't break legit clients)

### H4 — Backend health endpoint responds in < 100 ms

```bash
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{time_total}\n" $API/health; done
```

- [ ] All five times < 0.1s

---

## I. Detector tuning regressions (NICE)

### I1 — No detector fires more than 100 threats/hour on an idle sensor

```bash
curl -s "$API/api/v2/threats?sensor_id=$SID&page_size=1" | python3 -c "
import sys, json, urllib.request
d = json.load(sys.stdin)
print('total all-time:', d.get('total'))
"
# Wait an hour idle, then re-run
```

- [ ] After an idle hour: increment ≤ 100 threats from the running sensor (sanity check that cooldowns are working across the rule set)

### I2 — Disabled rules stay disabled across an agent restart

```bash
ssh $PI 'grep "enabled:" /etc/honeyman/rules/ble/mac_randomization.yaml'
```

- [ ] Returns `enabled: false`

---

## Sign-off

| Block | Tester | Date | Result |
|---|---|---|---|
| A — Onboarding | | | |
| B — USB detection | | | |
| C — BLE detection | | | |
| D — Network honeypot | | | |
| E — Backend ingest | | | |
| F — Dashboard UI | | | |
| G — Persistence | | | |
| H — Operability | | | |
| I — Detector tuning | | | |

Tag a release only when every `MUST` block is fully green and any `SHOULD`
gaps are documented in the release notes.
