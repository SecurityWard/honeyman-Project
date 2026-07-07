# Honeyman — Roadmap / Action Items

Living checklist. Roughly prioritized within each section. Check items
off as they land.

Status shorthand: `[x]` done · `[ ]` not started.

---

## 1. Detection validation (prove every vector locally)

Build a repeatable test matrix; confirm each fires the right
`threat_type` / severity / MITRE tags and reaches the dashboard.

- [x] **USB** — Rubber Ducky proven on the Pi5
- [ ] **USB** — Bash Bunny, OMG Cable, spoofed VID/PID, suspicious volume
      labels (`STARKILLER`, `PAYLOAD`), `autorun.inf`
- [x] **BLE** — Flipper Zero proven on the Pi5
- [ ] **BLE** — BLE spam, Apple Continuity abuse, HID keylogger, ESP32
      tools, manufacturer spoofing
- [ ] **WiFi** — Evil Twin, deauth flood, beacon flood, Pineapple,
      ESP8266 Deauther, Flipper WiFi, WPS (monitor mode now works)
- [ ] **AirDrop/mDNS** — suspicious service names, device spoofing, rapid
      announcement floods, TXT-record abuse
- [ ] **Network honeypot** — SSH brute-force, HTTP cred harvest, port
      scan, SMB/Telnet/VNC/web probes
- [ ] Fold confirmations into `docs/RELEASE-CHECKLIST.md` as the living
      test matrix

## 2. Malware-hash scanning

- [ ] **EICAR end-to-end** — drop an `eicar.com` file on a USB, confirm
      `known_malware` critical fires and reaches the dashboard (the safe,
      deterministic proof)
- [ ] Confirm the agent self-mounts USB read-only and hashes partition files
- [ ] Confirm a real MalwareBazaar-listed hash matches (EICAR is the safe proxy)
- [ ] Decide hash-DB refresh cadence — schedule `data/build_malware_db.py`
      (e.g. weekly) so signatures stay current

## 3. WiFi adapter stability across devices

- [ ] **Reboot persistence** — monitor mode re-establishes after reboot;
      NetworkManager-unmanaged rule survives
- [ ] **Chipset coverage** — works on mt76x0u; test rtl8812au / rtl8188 /
      other common USB dongles
- [ ] **Auto-detect** — agent picks the right external interface without
      explicit `wifi.interface` config
- [ ] **Single-adapter safety** — re-confirm a one-radio Pi Zero refuses
      monitor mode and never clobbers its network
- [ ] Consider baking the NetworkManager-unmanaged step into `install.sh`
      when a second adapter is detected
- [ ] Document a supported-adapter list

## 4. Dashboard usability & filtering

- [ ] **Sensor-filter bug** — the sensor filter only scopes the live feed.
      The map, stat cards, and charts stay global. Fix = thread `sensor_id`
      through the analytics endpoints (`/overview`, `/map`, `/top-threats`,
      `/trends`) and their frontend hooks so the whole dashboard scopes to
      the selected sensor.
- [ ] **Filter by severity** (critical / high / medium / low)
- [ ] **Filter by attack class** (detector type: usb / ble / wifi / airdrop
      / network) and/or `threat_type`
- [ ] Ensure filters **compose** (sensor + severity + class together).
      `/threats` already accepts `severity` + `detector_type`; mostly
      frontend UI + wiring the analytics endpoints.

## 5. Rule tuning / false positives

- [ ] **`suspicious_ssid` FP storm** — hundreds of false positives over a
      few hours. The rule matches `Guest`, `DIRECT-`, `Free/Open/Public
      WiFi`, `Complimentary`, `Setup/Config/Admin` — which hit nearly every
      printer (WiFi Direct `DIRECT-`), smart TV, hotel/airport hotspot, and
      phone hotspot in range. Fix options: drop the lure/setup patterns and
      keep only genuinely attack-indicative ones (FBI/NSA/Pwn/Hack/Exploit/
      tool names), require corroboration (suspicious SSID + evil-twin
      behavior), or drop to `info` + opt-in. Note: `max_alerts_per_hour`
      does NOT cap the aggregate (each unique SSID is a separate cooldown
      target), and `false_positive_prone` / `whitelist_check` metadata may
      not be enforced by the engine — verify.
- [ ] **`flipper_zero_unleashed` FP storm** — fires on ordinary BLE devices;
      tighten conditions
- [ ] Broader FP sweep — run a sensor in a busy environment for a day, rank
      rules by fire count, calm the noisy ones (tighter matches / cooldowns)
- [ ] Revisit `mac_randomization` (currently off by default) — salvageable?
- [ ] Audit whether the rule engine actually honors `tuning.max_alerts_per_hour`
      in aggregate vs per-target, and `whitelist_check` — several rules
      assume enforcement that may not exist

## 6. Stability & soak

- [ ] Let the Pi5 soak for days — watch for memory growth, restarts,
      detector give-ups
- [ ] **Detector supervision in practice** — kill a detector, confirm it
      restarts and the others + heartbeat keep running
- [ ] **Offline buffer** — pull the network, fire a threat, restore, confirm
      the queue drains
- [ ] **Multi-sensor** — run Pi Zero + Pi5 simultaneously; confirm
      map/filter/list scale

## 7. Infrastructure / audit backlog

- [ ] **nginx `sites-enabled` is a copy, not a symlink, and drifted** from
      `sites-available` — reconcile (edits to available silently don't
      apply; this bit us on `/wifi-check`)
- [ ] **Move web root + `install.sh` off `/root`** (audit #6) — won't
      survive a rebuild on a normal host where nginx can't traverse `/root`
- [ ] **Drop the dead `threat_stats_hourly` aggregate** (audit #4) —
      background compute nothing reads
- [ ] **Framework deprecations** — `@app.on_event` → lifespan; Pydantic v1
      `.from_orm/.dict/.json` → v2 (breaks on next major bump, not today)
- [ ] Purge aged sensor rows if any linger past the 72h auto-hide

## 8. Documentation

- [ ] Keep `CAPABILITIES.md` honest as detectors get validated (proven vs coded)
- [ ] Document the dual-adapter WiFi setup (internal internet + external
      monitor) as the supported pattern
- [ ] Adapter compatibility notes

---

## Recently shipped (context)

- WiFi rework: dedicated adapter, per-interface monitor mode, no
  `airmon-ng check kill` (no more network self-clobber)
- `scapy.sniff()` moved off the event loop (was freezing the whole agent)
- Per-detector supervision (one crash can't take the agent down)
- Sensor lifecycle: online derived from heartbeat age; sensors >72h silent
  drop off the list (threats retained)
- Map plots threats at their own location, not the sensor's current spot
- Real malware-hash DB (EICAR + MalwareBazaar) replacing synthetic hashes;
  fixed the `malware_family` lookup bug
- Per-sensor ingest rate limit; CORS/tz-aware/cleanup hardening batch
