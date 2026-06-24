# Security model & review

Honeyman's job is to deliberately attract malicious activity and store
what it sees. That makes its security posture different from a normal
application — the sensor *is* the bait, and the dashboard is publicly
viewable. This document is the threat model the project assumes, and the
checklist for reviewing each surface before a release that touches it.

If you're trying to *use* Honeyman safely, the right starting point is
the red "Read this first" callout on the [Add Sensor
page](https://dashboard.honeymanproject.com/add-sensor) and the
[CAPABILITIES.md](CAPABILITIES.md) document. This file is the
*operator/maintainer* view.

---

## 1. Assets to protect

| Asset | Where it lives | Why it matters |
|---|---|---|
| Per-sensor API keys (plaintext) | One-time response from `POST /sensors/register`; written to `/etc/honeyman/api_key` mode 0600 on the sensor | A leaked key lets an attacker push fake threats as that sensor. The hash on the backend is SHA-256-only, no salting — a leaked DB plus a key list could be correlated. |
| Sensor metadata (location, capabilities, last seen) | `sensors` table on the backend, public via `GET /sensors` | Maps to the *operator's* approximate physical location. We accept this as the cost of a public viewing surface; operators are told to use coarse manual locations if they care. |
| Threat events (raw_event, MAC addresses, hashes, MITRE tags) | `threats` hypertable on the backend, public via `GET /threats` | Includes BLE MAC addresses of devices observed nearby (people's phones, watches). Currently no PII filter; we accept this for V2 because the raw_event is the whole point of the dashboard. **Document this in the safety callout** and revisit if it becomes a complaint. |
| Backend admin credentials | Postgres password in `.env`, root SSH to the VPS | Direct DB access bypasses every public-read protection. Treat the VPS like any other production box. |
| TLS private keys | Let's Encrypt managed | Standard rotation. Renew is automatic via certbot. |
| The malware-hash database | `/var/lib/honeyman/malware_hashes.db` on each sensor, shipped from `data/malware_hashes.db` | Integrity matters: if an attacker tampers with this on a sensor they can blind the file-hash branch of the USB detector. |

There are no user accounts, no JWTs, no session tokens, and no
moderation/admin UI by design — those are not assets because they don't
exist.

---

## 2. Trust boundaries

```
+---------------------+      +-----------------------+      +-------------------+
|   Public internet   | ---> |   Nginx + TLS         | ---> |   FastAPI         |
|   (anyone reading   |  GET |   (Let's Encrypt)     |      |   - public read   |
|   the dashboard)    | <--- |                       | <--- |   - API-key write |
+---------------------+      +-----------------------+      +-------------------+
        ^                              |                            |
        | WebSocket (anon)             v                            v
        |                       +-------------+              +-------------+
        |                       |   React SPA |              |   Postgres  |
        +-----------------------|   read-only |              |   Redis     |
                                +-------------+              +-------------+

                                 (trust boundary: the VPS)

+---------------------+      +-----------------------+      +-------------------+
|   Operator at home  | ---> |   curl | sudo bash    | ---> |   sensor (Pi)     |
|   (running install) |      |   (TLS only)          |      |   - root agent    |
+---------------------+      +-----------------------+      |   - pip --break   |
                                                            |     -system-pkgs  |
                                                            +-------------------+
                                                                     |
                                                                     v
                                                     HTTPS + Bearer API-key
                                                                     |
                                                                     v
                                                            (back to FastAPI)
```

Key boundaries:

- **Internet → Nginx**: TLS terminates here. Anything not HTTPS gets a
  301 redirect.
- **Anyone → public read endpoints**: zero auth. We are deliberately
  serving the entire `threats` table publicly.
- **Sensor → write endpoints**: per-sensor API key on `Authorization:
  Bearer`. The key must match the `sensor_id` in the request body;
  cross-sensor writes are 403.
- **Curl-pipe-bash → sensor root**: we trust TLS to the
  honeymanproject.com endpoints. There is no signature verification on
  the install script. An attacker with TLS-MITM capability could ship a
  malicious script. (See §4 for what we'd do about it.)
- **Sensor agent → host OS**: the agent runs as `User=root` in
  systemd, with `ProtectHome=true`, `ProtectSystem=strict`,
  `ReadWritePaths=<logs/data/config>`, `PrivateTmp=true`. So root, but
  scoped.

---

## 3. Threats we accept (and document)

Treat these as conscious decisions, not unmitigated risk:

1. **Public threat visibility.** All `GET /threats` and `GET /sensors`
   responses are public. Anyone can scrape the whole table. The
   dashboard is the product; making it auth'd would defeat the point.
2. **Sensor location reveal.** A sensor's last reported `latitude` and
   `longitude` are in the public list. Operators who don't want their
   physical location guessable should set `location.manual_latitude`
   to a coarse pin (e.g. city-centre) in `config.yaml`.
3. **MAC addresses in public threat data.** BLE/WiFi MACs of nearby
   devices land in `raw_event` and are publicly readable. iOS/Android
   already randomize these for privacy, but not all devices do.
   Documented on the Add Sensor page.
4. **The sensor itself is bait.** We tell operators explicitly: use
   throwaway hardware, segment the network, reimage. There is no host
   integrity service running on the sensor and we don't claim one.
5. **`curl | bash` install.** The install script's only integrity
   property today is TLS to nginx on the VPS. We accept this for a
   small operator base; revisit if we ever publish a release tag or
   want supply-chain claims.
6. **No rate limiting on `POST /sensors/register`.** A bad actor can
   register sensors and push junk threats. Mitigations live downstream
   (rule tuning, operator triage), not upstream.

---

## 4. Threats we don't accept (and what mitigates them)

| Threat | Mitigation today | Gap |
|---|---|---|
| **Cross-sensor write.** Sensor A's key writing as sensor B. | `authenticated_sensor` dep verifies the key's hash matches the row whose `sensor_id` is in the path / body; mismatch → 403. | None currently. |
| **API-key replay if the DB leaks.** | Keys are SHA-256-hashed on the backend; plaintext is returned exactly once and never persisted. | No salt — SHA-256 of a key is the key's identity. If you suspect a leak, regenerate every key (currently a manual psql `UPDATE`). |
| **SQL injection.** | All queries go through SQLAlchemy parameter binding **except** `/analytics/trends` which builds the `date_trunc` unit with f-string interpolation. | The `period` parameter is regex-validated to `^(hourly|daily|weekly)$` before interpolation and mapped through a lookup table, so this is safe. **Re-audit on every analytics change.** |
| **XSS via `raw_event`.** | React escapes string children by default; we render `raw_event` via `JSON.stringify(...)` inside a `<pre>`, which is safe. We don't `dangerouslySetInnerHTML` anywhere. | If you ever add markdown / HTML rendering, sanitize. |
| **WebSocket abuse.** | The WS endpoint accepts anonymous connections (it's public). Each client only receives broadcasts; there's no client-to-server channel except keepalive. | Cap on `len(active_connections)` is not enforced — DoS by opening many connections is plausible. |
| **Backend resource exhaustion via heartbeats.** | The heartbeat endpoint just `UPDATE`s the sensor row; cheap. | No per-sensor rate limit — a compromised key could send heartbeats in a tight loop. |
| **Sensor compromise via the malware-hash scan.** | The agent reads files to hash them, doesn't execute. | Reading executables can still trigger antivirus-style hooks on some kernels. Documented on Add Sensor page. |
| **TLS-MITM during install.** | Let's Encrypt + nginx default ciphers + HSTS from certbot. | No signature on the served `install.sh` body. A compromised CA or compromised nginx ships an arbitrary script. Mitigation if we ever want it: sign the script and have the README publish the public key. |
| **Pip dependency confusion / supply chain.** | The agent's `setup.py` declares a small, well-known dep set. Nothing pulls a private/internal package. | We do `pip install --break-system-packages`. A compromised wheel cache on the sensor at install time lands as root. |

---

## 5. Review checklist

Run this checklist on every PR (or release tag) that touches one of the
columns. The point isn't perfection — it's making the trade-offs
explicit so they don't drift.

### 5.1 Every change

- [ ] No new auth surface (login, JWT, session) introduced — V2 stays
      account-less by design.
- [ ] No write endpoint reachable without `authenticated_sensor`.
- [ ] No write endpoint accepts data for a `sensor_id` other than the
      authenticated one.
- [ ] No `dangerouslySetInnerHTML` in the frontend.
- [ ] No raw user/sensor input concatenated into SQL via f-strings or
      `text(...)` without a regex-validated allowlist.

### 5.2 If you touched `/api/v2/sensors/register` or `install.sh`

- [ ] Plaintext API key returned once, never stored.
- [ ] Hash on the row uses a constant-time comparison for verify
      (`hmac.compare_digest`).
- [ ] No PII required in the registration payload.
- [ ] If you accept a `manual_location`, it stays opt-in.
- [ ] `install.sh` written to `/etc/honeyman/api_key` is mode 0600
      owned by root.
- [ ] `install.sh` doesn't `curl` anything other than the registration
      endpoint and the agent source over HTTPS.

### 5.3 If you touched the agent

- [ ] No new write to `/etc/` or `/var/` outside the declared
      `ReadWritePaths=` in the systemd unit.
- [ ] No `subprocess` call with shell=True on attacker-controlled
      input.
- [ ] New detector imports tolerate missing hardware (no agent crash
      because BlueZ wasn't running).
- [ ] If you added a hash-DB lookup, the DB path comes from config
      with a safe default.

### 5.4 If you touched the dashboard / frontend

- [ ] Built bundle has no `console.log` of sensor or threat objects.
- [ ] No environment variable referenced from `import.meta.env` that
      contains a secret (env vars in Vite are bundled into the public
      JS).
- [ ] Filter banners and click-throughs only ever produce URLs the SPA
      knows how to handle — no open redirect.

### 5.5 If you touched `nginx/honeyman.conf`

- [ ] Server names are exhaustive (`dashboard`, `api`, apex, `www`);
      no other vhost falls through to the dashboard root.
- [ ] No alias / try_files exposes a path outside the
      `dashboard-v2/frontend/dist` directory except the deliberate
      `location = /install`.
- [ ] HSTS / TLS settings unchanged from certbot defaults (or
      explicitly stricter).
- [ ] No backup `.conf` files left in `sites-enabled/` (loaded by
      default — they conflict with the live config and silently win).

### 5.6 Before a release tag

- [ ] Smoke flow in [`TESTING.md`](TESTING.md) §3.2 passes against
      staging.
- [ ] Auth regression tests in §3.3 pass.
- [ ] WS broadcast test in §3.4 sees the event for a freshly POSTed
      threat.
- [ ] At least one real Pi has been onboarded against the new build in
      the last week.

---

## 6. Reporting a vulnerability

Email `contact@honeymanproject.com` with details and a reproducer.
We'll acknowledge within 72 hours. There's no bug bounty; we'll credit
reporters in CHANGELOG unless they ask not to be.

If the issue is exploitable as-is — credential leakage, RCE through the
install path, account takeover (n/a but listed for completeness) —
include "URGENT" in the subject.

---

## 7. Known unfixed items

Live list, kept honest:

- Backend `/var/log/honeyman-backend.log` grows unbounded — no
  logrotate. Practical impact: disk fills eventually, but not soon at
  current ingest rate.
- API-key hashing has no salt. Migrating to argon2 + per-key salt is
  reasonable; not yet scheduled.
- WebSocket has no connection cap. Open issue.
- `install.sh` has no signature. Open issue.
- `data/malware_hashes.db` is shipped unsigned. We trust git for
  integrity at the source; the install copy is a verbatim cp from the
  cloned tree.
