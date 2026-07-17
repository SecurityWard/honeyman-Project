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

- [x] **EICAR end-to-end** — proven: an `eicar.com` (exact 68 bytes) on a
      USB fires `known_malware` critical (`EICAR-Test-File`) to the
      dashboard. Confirms mount + walk + hash + DB lookup + rule + delivery.
- [x] Agent self-mounts the USB and hashes partition files (proven by the
      EICAR test — the hash-match path works)
- [ ] Confirm a real MalwareBazaar-listed sample matches in the field
      (EICAR proved the mechanism; a live sample is the last mile)
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

- [x] **Sensor-filter bug** — fixed. Clicking a sensor now scopes the map,
      stat cards, trends, and top-threats to that sensor (not just the feed).
      `sensor_id` threaded through `/analytics/{map,overview,top-threats,trends}`
      and the frontend hooks.
- [ ] **Filter by severity** (critical / high / medium / low)
- [ ] **Filter by attack class** (detector type: usb / ble / wifi / airdrop
      / network) and/or `threat_type`
- [ ] Ensure filters **compose** (sensor + severity + class together).
      `/threats` already accepts `severity` + `detector_type`; mostly
      frontend UI + wiring the analytics endpoints.

## 5. Rule tuning / false positives

- [x] **`suspicious_ssid` FP storm** — fixed (v2.1). Dropped the lure/setup
      patterns (`Guest`/`DIRECT-`/`Free WiFi`/`Setup`…); now matches only
      prank/intimidation names and named attack tools (Pineapple/Hak5/MANA/
      Evil-Twin/…). Validated: fires on 7/7 attack names, 0 FPs on 8 legit
      networks. Purged 3361 old FP rows. Per-SSID 1h cooldown.
- [ ] **`flipper_zero_unleashed` FP storm** — fires on ordinary BLE devices;
      tighten conditions
- [ ] Broader FP sweep — run a sensor in a busy environment for a day, rank
      rules by fire count, calm the noisy ones (tighter matches / cooldowns)
- [ ] Revisit `mac_randomization` (currently off by default) — salvageable?
- [ ] Audit whether the rule engine actually honors `tuning.max_alerts_per_hour`
      in aggregate vs per-target, and `whitelist_check` — several rules
      assume enforcement that may not exist

## 6. Location accuracy

- [ ] **Stationary sensor coordinates jumped ~30 miles in a day.**
      Observed on `rpi5test-fad9` (stationary). It has no GPS and no manual
      pin, so the location chain falls through to **IP geolocation**
      (confirmed: `location_method: ip`, accuracy 5000m). IP geo routinely
      drifts tens of miles when the ISP's IP→location mapping changes or
      `ipapi.co` returns a different city centroid — the 5km accuracy circle
      understates the real jump. Fix options:
      - **Manual pin** for stationary sensors — set `location.manual_latitude`
        / `manual_longitude` in config; eliminates drift entirely and is the
        intended pattern for a fixed deployment. (Cheapest fix; make it the
        documented default for non-mobile sensors.)
      - **Jump damping / hysteresis** — don't rewrite the reported location
        on every heartbeat; keep the first fix and only move if a new reading
        differs by more than the accuracy radius (and, ideally, is corroborated).
      - **Prefer WiFi positioning over IP** — it's far more accurate (tens of
        meters). Investigate why it's falling through to IP: no API key? MLS
        deprecated? Can't scan APs because the spare adapter is in monitor
        mode and the internal one isn't being used for a positioning scan?
      - Make the map's accuracy circle honest about how coarse IP really is.

## 7. Stability & soak

- [ ] Let the Pi5 soak for days — watch for memory growth, restarts,
      detector give-ups
- [ ] **Detector supervision in practice** — kill a detector, confirm it
      restarts and the others + heartbeat keep running
- [ ] **Offline buffer** — pull the network, fire a threat, restore, confirm
      the queue drains
- [ ] **Multi-sensor** — run Pi Zero + Pi5 simultaneously; confirm
      map/filter/list scale

## 8. Infrastructure / audit backlog

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

## 9. Documentation

- [ ] Keep `CAPABILITIES.md` honest as detectors get validated (proven vs coded)
- [ ] Document the dual-adapter WiFi setup (internal internet + external
      monitor) as the supported pattern
- [ ] Adapter compatibility notes

---

## Recently shipped (context)

- Malware-hash scan **proven** end-to-end (EICAR → known_malware critical)
- `suspicious_ssid` rule retuned; FP storm eliminated (3361 rows purged)
- Dashboard sensor filter now scopes the map + stats + charts, not just feed
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
