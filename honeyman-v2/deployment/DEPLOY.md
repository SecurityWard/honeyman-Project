# Honeyman V2 — Deployment Guide

This is the step-by-step deployment guide for Honeyman V2. It covers:

1. [VPS first-time setup](#1-vps-first-time-setup) — bring up backend + dashboard from scratch
2. [Deploying updates](#2-deploying-updates) — applying new code to an already-running VPS
3. [Onboarding a Pi sensor](#3-onboarding-a-pi-sensor) — `curl | bash` and verify it appears
4. [Verification checklist](#4-verification-checklist) — what to look at after each step
5. [Troubleshooting](#5-troubleshooting) — what to do when things break
6. [Rolling back](#6-rolling-back) — undoing a bad update

Throughout this guide, anything in `monospace` is something you copy/paste. Lines starting with `$` are run as a normal user, lines starting with `#` are run as root. The example VPS in this guide is at `72.60.25.24`.

---

## 1. VPS first-time setup

### Prerequisites

A Linux VPS with:

- Ubuntu 22.04 or Debian 12 (other distros work but commands differ)
- Root access (or sudo)
- 2 vCPUs, 2 GB RAM, 20 GB disk minimum
- A public IP and (recommended) a domain pointing at it
- Ports 80, 443, and 8000 reachable from sensors. Port 3000 reachable from your dashboard viewers.

You'll need a basic LAMP-ish stack already running:

- **PostgreSQL 15+** with a database `honeyman_v2` and a user `honeyman` who owns it
- **Redis 7+** listening on `localhost:6379`
- **nginx** (or equivalent) to put TLS in front of the FastAPI backend
- **Python 3.11+** with `pip` available

If you don't have these yet, the appendix at the bottom of this doc walks through installing them.

### Step 1.1 — Get the code onto the VPS

```bash
# As root, or a user with write access to /root
cd /root
git clone https://github.com/SecurityWard/honeyman-Project.git
cd honeyman-Project
```

After cloning you should have `/root/honeyman-Project/honeyman-v2/dashboard-v2/backend/` and the matching `frontend/` directory.

### Step 1.2 — Create the Postgres database

```bash
sudo -u postgres psql <<'SQL'
CREATE USER honeyman WITH PASSWORD 'CHANGE-ME-strong-random';
CREATE DATABASE honeyman_v2 OWNER honeyman;
GRANT ALL PRIVILEGES ON DATABASE honeyman_v2 TO honeyman;
SQL
```

Replace `CHANGE-ME-strong-random` with something from `openssl rand -hex 24`. Write the password down; you'll need it twice more in this guide.

### Step 1.3 — Backend venv + dependencies

```bash
cd /root/honeyman-Project/honeyman-v2/dashboard-v2/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

This pulls in FastAPI, SQLAlchemy, asyncpg, paho-mqtt, etc. Takes about a minute.

### Step 1.4 — Backend `.env`

```bash
cp .env.example .env
$EDITOR .env
```

Fill in at minimum:

```
DATABASE_URL=postgresql+asyncpg://honeyman:CHANGE-ME-strong-random@localhost:5432/honeyman_v2
REDIS_URL=redis://localhost:6379/0
PUBLIC_API_BASE_URL=https://api.your-domain.tld     # or http://72.60.25.24:8000 for now
CORS_ORIGINS=http://72.60.25.24:3000,https://dashboard.your-domain.tld
MQTT_OFFERED=false
```

V2 has **no `SECRET_KEY` and no JWT settings**. If you see those in `.env.example`, ignore them — they're from a previous version.

### Step 1.5 — Apply the schema

V2 ships a single Phase A operator script that does this idempotently:

```bash
cd /root/honeyman-Project/honeyman-v2/deployment
bash phase_a_apply.sh 2>&1 | tee /root/phase_a_apply.log
```

This script does all of:

- Installs the TimescaleDB apt package matching your Postgres major version
- Runs `timescaledb-tune` and restarts Postgres
- `CREATE EXTENSION timescaledb` on the `honeyman_v2` DB
- `pg_dump` of the current DB to `/root/honeyman_v2_pre_phase_a_<timestamp>.sql.gz` as a safety net
- Drops any pre-existing schema (the V2 `users` table, old `threats`/`sensors` definitions)
- Runs `alembic upgrade head` — creates `sensors` (with `api_key_hash`), `threats` (as a TimescaleDB hypertable with compression after 7 days, retention after 90 days), and the `threat_stats_hourly` continuous aggregate
- Syncs your `.env` to V2 settings (removes JWT-era keys, ensures `MQTT_OFFERED` and `PUBLIC_API_BASE_URL` exist)
- Restarts the backend systemd service if it can find it
- Runs an end-to-end smoke test: register a fake sensor, POST a threat, verify it appears, clean up

If the script ends with `Phase A apply complete`, you're done. If a step said `[FAIL]`, scroll back to that step in the log — every failure is paired with the underlying error.

If you don't yet have the backend systemd unit installed, see [Appendix A](#appendix-a-systemd-units).

### Step 1.6 — Frontend build + deploy

```bash
cd /root/honeyman-Project/honeyman-v2/dashboard-v2/frontend

# Tell the frontend where the backend lives
cat > .env.production <<EOF
VITE_API_BASE_URL=https://api.your-domain.tld/api/v2
VITE_WS_URL=wss://api.your-domain.tld/api/v2/ws
EOF
# (use http://72.60.25.24:8000/api/v2 and ws://...:8000/... if you haven't set up TLS yet)

npm install
npm run build
```

The build lands in `dist/`. Serve it via nginx:

```nginx
# /etc/nginx/sites-available/honeyman
server {
    listen 80;
    server_name dashboard.your-domain.tld;
    root /root/honeyman-Project/honeyman-v2/dashboard-v2/frontend/dist;
    index index.html;
    location / {
        try_files $uri $uri/ /index.html;   # SPA fallback
    }
}

server {
    listen 80;
    server_name api.your-domain.tld;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;       # required for WebSocket
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}
```

```bash
ln -s /etc/nginx/sites-available/honeyman /etc/nginx/sites-enabled/honeyman
nginx -t && systemctl reload nginx
```

For TLS, run `certbot --nginx -d dashboard.your-domain.tld -d api.your-domain.tld`. Skip TLS for the local smoke test if you don't have DNS pointed yet — just use `http://72.60.25.24:3000` and `http://72.60.25.24:8000` directly.

### Step 1.7 — Confirm the dashboard loads

Open `https://dashboard.your-domain.tld` (or `http://72.60.25.24:3000`) in a browser. You should see:

- An empty map
- "0 sensors" / "0 threats" in the stat cards
- The header navigation: Dashboard · Sensors · Add Sensor · About

If anything 404s, jump to [Troubleshooting](#5-troubleshooting).

---

## 2. Deploying updates

When new code lands in the repo:

```bash
cd /root/honeyman-Project
git pull --ff-only

# Backend
cd honeyman-v2/dashboard-v2/backend
source venv/bin/activate
pip install -r requirements.txt        # in case dependencies changed
alembic upgrade head                   # in case a new migration shipped
systemctl restart honeyman-backend

# Frontend
cd ../frontend
npm install
npm run build
# nginx serves from dist/ — no reload needed
```

For risky updates (schema changes, large refactors) take a snapshot first:

```bash
sudo -u postgres pg_dump honeyman_v2 | gzip > /root/honeyman_v2_$(date +%F).sql.gz
```

If the update goes sideways, see [Rolling back](#6-rolling-back).

---

## 3. Onboarding a Pi sensor

The agent self-registers — no admin step needed.

On a clean Raspberry Pi (Pi Zero 2 W, Pi 4, or Pi 5) running Raspberry Pi OS / Ubuntu:

```bash
curl -sSL https://your-domain.tld/install | sudo HONEYMAN_API=https://api.your-domain.tld bash
```

What this does, step by step:

1. Asks for a sensor name (lowercase letters/hyphens) and an optional location label
2. Detects available hardware (USB always, plus Bluetooth and WiFi monitor mode if the chipset supports it)
3. Installs system deps (`bluez`, `wireless-tools`, `iw`, `aircrack-ng`, `avahi-utils`)
4. Calls `POST /api/v2/sensors/register` and stores the returned API key at `/etc/honeyman/api_key` (mode `0600`)
5. `git clone`s the repo and `pip install -e`s the agent package
6. Copies the default 37 detection rules to `/etc/honeyman/rules/`
7. Writes `/etc/honeyman/config.yaml`
8. Installs and starts `honeyman-agent.service` under systemd

For batch flashing or cloud-init, set the values non-interactively:

```bash
curl -sSL https://your-domain.tld/install | sudo \
  SENSOR_NAME='defcon-hotel' \
  LOCATION='DefCon 32 hotel lobby' \
  NON_INTERACTIVE=1 \
  HONEYMAN_API='https://api.your-domain.tld' \
  bash
```

Within about 60 seconds the new sensor appears under **Sensors** on the dashboard and a marker shows up on the map.

---

## 4. Verification checklist

Run these after the first-time setup, after each update, and after every Pi onboard.

| Check | Command | Expected |
|---|---|---|
| Backend reachable | `curl http://127.0.0.1:8000/health` | `{"status":"ok",…}` |
| Backend behind nginx | `curl https://api.your-domain.tld/health` | same |
| Sensors API public | `curl https://api.your-domain.tld/api/v2/sensors` | JSON, possibly empty list |
| Threats API public | `curl https://api.your-domain.tld/api/v2/threats` | JSON, possibly empty list |
| Analytics public | `curl https://api.your-domain.tld/api/v2/analytics/overview` | JSON with zeroed counts |
| Rules endpoint authed | `curl https://api.your-domain.tld/api/v2/rules` | `401` (no API key) — confirms auth wired |
| TimescaleDB enabled | `sudo -u postgres psql -d honeyman_v2 -c "SELECT extversion FROM pg_extension WHERE extname='timescaledb'"` | non-empty version string |
| `threats` is a hypertable | `sudo -u postgres psql -d honeyman_v2 -c "SELECT * FROM timescaledb_information.hypertables"` | one row, `threats` |
| `sensors.api_key_hash` exists | `sudo -u postgres psql -d honeyman_v2 -c "\d sensors" | grep api_key_hash` | non-empty |
| Backend service running | `systemctl is-active honeyman-backend` | `active` |
| Backend startup log clean | `journalctl -u honeyman-backend -n 30` | "started successfully", "MQTT_OFFERED=False - skipping" |
| Dashboard loads | open `https://dashboard.your-domain.tld` in a browser | empty map, nav present |
| Smoke threat round-trip | follow steps 5a-5c of `PHASE-A-OPS.md` | threat appears on map |
| Pi agent running | on the Pi: `systemctl is-active honeyman-agent` | `active` |
| Pi appears on dashboard | refresh dashboard | sensor in list, marker on map within ~60s |

---

## 5. Troubleshooting

### Backend won't start

```bash
journalctl -u honeyman-backend -n 100
```

| Symptom | Likely cause | Fix |
|---|---|---|
| `time_bucket does not exist` | TimescaleDB extension not enabled in `honeyman_v2` DB | `sudo -u postgres psql -d honeyman_v2 -c "CREATE EXTENSION timescaledb"` |
| `password authentication failed for user "honeyman"` | `.env` `DATABASE_URL` password mismatches what Postgres knows | Reset: `sudo -u postgres psql -c "ALTER USER honeyman WITH PASSWORD '…'"` then update `.env` |
| `pydantic.ValidationError: SECRET_KEY field required` | Stale `.env` from a pre-V2 deployment | Remove `SECRET_KEY`, `ALGORITHM`, `ACCESS_TOKEN_*`, `REFRESH_TOKEN_*` lines — V2 doesn't use them |
| `ConnectionRefusedError: [Errno 111]` to `mqtt.honeymanproject.com` | `MQTT_OFFERED=true` but no broker reachable | Set `MQTT_OFFERED=false` in `.env` |
| `(psycopg2.OperationalError) FATAL: database "honeyman_v2" does not exist` | DB not created yet | Step 1.2 |

### Dashboard loads but is empty / shows network errors in DevTools

Open browser DevTools → Network tab → reload the page.

| Failed request | Cause | Fix |
|---|---|---|
| `GET /api/v2/...` → 404 | nginx not proxying `/api/` to port 8000 | Verify the `api.your-domain.tld` server block in nginx config, `nginx -t && systemctl reload nginx` |
| `GET /api/v2/...` → CORS error | Frontend origin not in `CORS_ORIGINS` | Add the frontend's exact origin (with scheme + port) to `.env`'s `CORS_ORIGINS`, restart backend |
| `WebSocket connection failed` | nginx not forwarding the `Upgrade` header | Confirm `proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";` are in the `api.` server block |
| Frontend uses `http://localhost:8000` | Build-time env var wasn't set | Re-run step 1.6 with `VITE_API_BASE_URL` exported, then `npm run build`, then refresh browser (Ctrl-Shift-R to bust cache) |

### Pi agent registers but no heartbeats appear

On the Pi:

```bash
journalctl -u honeyman-agent -f
```

| Log line | Cause | Fix |
|---|---|---|
| `No API key configured` | `/etc/honeyman/api_key` is missing or empty | Re-run the install script, or copy the key from registration response manually |
| `401 Unauthorized` | Backend doesn't have this sensor's hash (sensor deleted on server) | Delete `/etc/honeyman/api_key` and re-run install.sh |
| `403 Forbidden` | The `sensor_id` in `config.yaml` doesn't match the API key's owner | Edit `/etc/honeyman/config.yaml` so `sensor_id:` matches the registration response |
| `Network is unreachable` | Pi can't reach the backend | Check firewall, DNS, `curl https://api.your-domain.tld/health` from the Pi |
| `SSL: CERTIFICATE_VERIFY_FAILED` | Self-signed or expired cert | Either fix the cert (`certbot renew`) or set `transport.https.verify_ssl: false` in config (testing only) |

### Threat lands in DB but no map marker

The threat made it through but doesn't have coordinates. From the VPS:

```bash
sudo -u postgres psql -d honeyman_v2 -c "SELECT id, threat_type, latitude, longitude, country FROM threats ORDER BY timestamp DESC LIMIT 5"
```

If `latitude` and `longitude` are `null`:

- Sensor has no GPS, no WiFi positioning API key, and `ipapi.co` returned nothing (or rate-limited)
- Fix: pin the location at install time with `LOCATION="<city>"` — or once Phase D ships, set `location.manual_latitude` and `location.manual_longitude` in `/etc/honeyman/config.yaml`

---

## 6. Rolling back

Each update of any complexity should start by saving a snapshot:

```bash
sudo -u postgres pg_dump honeyman_v2 | gzip > /root/honeyman_v2_$(date +%F).sql.gz
git -C /root/honeyman-Project rev-parse HEAD > /root/honeyman_commit_$(date +%F).txt
```

To roll back code:

```bash
cd /root/honeyman-Project
git log --oneline -10                # find the commit you want
git checkout <last-good-commit>
cd honeyman-v2/dashboard-v2/backend
source venv/bin/activate
pip install -r requirements.txt
alembic downgrade -1                 # only if a migration shipped in the bad update
systemctl restart honeyman-backend
```

To roll back data:

```bash
sudo -u postgres dropdb honeyman_v2
sudo -u postgres createdb honeyman_v2 -O honeyman
gunzip -c /root/honeyman_v2_<date>.sql.gz | sudo -u postgres psql honeyman_v2
```

The `phase_a_apply.sh` script also writes a `pg_dump` at the start of every run — look for `/root/honeyman_v2_pre_phase_a_*.sql.gz`.

---

## Appendix A — Systemd units

If you don't have one yet, drop this at `/etc/systemd/system/honeyman-backend.service`:

```ini
[Unit]
Description=Honeyman V2 dashboard backend (FastAPI)
After=network-online.target postgresql.service redis-server.service
Wants=network-online.target postgresql.service redis-server.service

[Service]
Type=simple
User=root
WorkingDirectory=/root/honeyman-Project/honeyman-v2/dashboard-v2/backend
ExecStart=/root/honeyman-Project/honeyman-v2/dashboard-v2/backend/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
EnvironmentFile=/root/honeyman-Project/honeyman-v2/dashboard-v2/backend/.env
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/honeyman-backend.log
StandardError=append:/var/log/honeyman-backend.log

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable honeyman-backend
systemctl start honeyman-backend
```

The Pi-side systemd unit (`honeyman-agent.service`) is installed automatically by `install.sh` — no action needed on the VPS.

---

## Appendix B — Installing the prerequisites from scratch

On a fresh Ubuntu 22.04 VPS:

```bash
apt update
apt install -y \
    postgresql postgresql-contrib \
    redis-server \
    nginx \
    python3 python3-pip python3-venv \
    git curl jq \
    certbot python3-certbot-nginx

systemctl enable --now postgresql redis-server nginx

# Frontend toolchain
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs
```

Postgres ships with default `peer` auth on Unix sockets and `scram-sha-256` over TCP. If you hit auth errors during step 1.4 of the main guide, edit `/etc/postgresql/<ver>/main/pg_hba.conf` to ensure local TCP connections use `scram-sha-256`, then `systemctl reload postgresql`.

---

## Appendix C — Removing Honeyman

Server side:

```bash
systemctl stop honeyman-backend
systemctl disable honeyman-backend
rm /etc/systemd/system/honeyman-backend.service
systemctl daemon-reload
sudo -u postgres dropdb honeyman_v2
sudo -u postgres dropuser honeyman
rm -rf /root/honeyman-Project /root/honeyman_v2_*.sql.gz
rm /etc/nginx/sites-enabled/honeyman /etc/nginx/sites-available/honeyman
systemctl reload nginx
```

Pi side:

```bash
systemctl stop honeyman-agent
systemctl disable honeyman-agent
rm /etc/systemd/system/honeyman-agent.service
systemctl daemon-reload
rm -rf /etc/honeyman /var/lib/honeyman /var/log/honeyman /opt/honeyman
pip uninstall -y honeyman-agent
```

If you want the sensor to disappear from the dashboard, the backend doesn't expose a public delete endpoint by design (no actions in V2). For now, drop it manually:

```bash
sudo -u postgres psql -d honeyman_v2 -c "DELETE FROM sensors WHERE sensor_id='<the-id>'"
```

---

*Last reviewed: 2026-05-09 against the V2 cleanup + Phase A/B/C code drop.*
