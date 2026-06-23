# Phase A — VPS ops + smoke test

This is the operator's checklist for getting Phase A working end-to-end on
the VPS at `72.60.25.24` (or wherever you're hosting). Pair with the agent
code that just shipped (HTTPS+API-key transport, schema-aligned envelope).

Time estimate: ~60 minutes if nothing goes wrong.

---

## 1. Install TimescaleDB on the VPS

The new Alembic migration assumes TimescaleDB is available. Install the
extension at the OS level first.

### Debian/Ubuntu

```bash
sudo apt install -y gnupg postgresql-common apt-transport-https lsb-release wget
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh

# Add TimescaleDB repo
echo "deb https://packagecloud.io/timescale/timescaledb/$(lsb_release -is | tr '[:upper:]' '[:lower:]')/ $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/timescaledb.list
wget --quiet -O - https://packagecloud.io/timescale/timescaledb/gpgkey \
  | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/timescaledb.gpg

sudo apt update
sudo apt install -y timescaledb-2-postgresql-15   # match your PG version

# Tune Postgres for TimescaleDB
sudo timescaledb-tune --quiet --yes

sudo systemctl restart postgresql
```

### Verify

```bash
sudo -u postgres psql -d honeyman_v2 -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"
sudo -u postgres psql -d honeyman_v2 -c "\dx timescaledb"
```

You should see a row with `timescaledb` and a version number.

---

## 2. Reset the database to the new V2 schema

The cleanup PR rewrote the Alembic migration to drop the `users` table and
add `api_key_hash` to `sensors`. Since there's no production sensor data
yet, the cleanest path is to nuke and re-init.

```bash
# On the VPS, in the backend venv
cd /root/honeyman-v2/backend
source venv/bin/activate

# Drop everything (will refuse if there are connections; close pgAdmin etc first)
psql "$DATABASE_URL" <<'SQL'
DROP MATERIALIZED VIEW IF EXISTS threat_stats_hourly CASCADE;
DROP TABLE IF EXISTS threats CASCADE;
DROP TABLE IF EXISTS sensors CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TYPE IF EXISTS userrole;
SQL

# Apply the V2 migration (creates sensors + api_key_hash, threats hypertable,
# compression after 7d, retention after 90d, continuous aggregate)
alembic upgrade head
```

Verify:

```bash
psql "$DATABASE_URL" -c "\dt"
# Expect: sensors, threats, alembic_version (no 'users')

psql "$DATABASE_URL" -c "SELECT * FROM timescaledb_information.hypertables;"
# Expect: 1 row for 'threats'

psql "$DATABASE_URL" -c "\d sensors" | grep api_key_hash
# Expect: api_key_hash | character varying(64) | not null
```

---

## 3. Update backend .env

The cleanup added a few new settings and removed JWT-era ones. Sync your
`.env` with the new template:

```bash
diff -u /root/honeyman-v2/backend/.env /root/honeyman-v2/backend/.env.example
```

Make sure these are present and correct:

```bash
PUBLIC_API_BASE_URL=https://api.honeymanproject.com   # or http://72.60.25.24:8000 for now
MQTT_OFFERED=false                             # true only if you want MQTT alongside HTTPS
DATABASE_URL=postgresql+asyncpg://honeyman:...@localhost:5432/honeyman_v2
REDIS_URL=redis://localhost:6379/0
CORS_ORIGINS=http://72.60.25.24:3000,https://dashboard.honeymanproject.com
```

These can be removed if still present:

```bash
SECRET_KEY=...
ACCESS_TOKEN_EXPIRE_MINUTES=...
REFRESH_TOKEN_EXPIRE_DAYS=...
ALGORITHM=...
```

---

## 4. Restart the backend

```bash
sudo systemctl restart honeyman-backend   # or whatever your service file is called
sudo journalctl -u honeyman-backend -f
```

You should see:

```
INFO  Honeyman Dashboard API v2.0.0
INFO  Redis connected
INFO  MQTT_OFFERED=False — skipping MQTT subscriber. Sensors push via HTTPS.
INFO  Honeyman Dashboard API started successfully
```

The "skipping MQTT subscriber" line confirms the new optional-MQTT logic.

Sanity-check from your laptop:

```bash
curl http://72.60.25.24:8000/health
# {"status":"ok","service":"Honeyman Dashboard API","version":"2.0.0"}

curl http://72.60.25.24:8000/api/v2/sensors
# {"sensors":[],"total":0,"page":1,"page_size":50}

curl http://72.60.25.24:8000/api/v2/analytics/overview
# Should return zeroed-out overview (no threats yet)
```

---

## 5. Smoke test the full pipeline

Goal: register a fake sensor with curl, push one threat, see it on the dashboard.

### a. Register

```bash
curl -X POST http://72.60.25.24:8000/api/v2/sensors/register \
  -H 'Content-Type: application/json' \
  -d '{
    "requested_name": "smoke-test",
    "location_label": "Local laptop test",
    "capabilities": {"usb": true, "wifi": false, "ble": false},
    "enabled_detectors": ["usb"],
    "platform": "linux",
    "agent_version": "2.0.0",
    "initial_location": {
      "latitude": 37.7749,
      "longitude": -122.4194,
      "method": "manual",
      "accuracy": 100
    }
  }'
```

Save the `sensor_id` and `api_key` from the response. The api_key starts with `hms_`.

### b. Send a heartbeat

```bash
SENSOR_ID="smoke-test-XXXX"   # from step a
API_KEY="hms_..."              # from step a

curl -X POST "http://72.60.25.24:8000/api/v2/sensors/$SENSOR_ID/heartbeat" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{
    \"sensor_id\": \"$SENSOR_ID\",
    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%S)\",
    \"is_online\": true,
    \"enabled_detectors\": [\"usb\"],
    \"system_info\": {\"cpu_percent\": 5.2, \"memory_percent\": 41.0, \"disk_percent\": 28.0, \"uptime_seconds\": 12345},
    \"location\": {\"latitude\": 37.7749, \"longitude\": -122.4194, \"method\": \"manual\", \"accuracy\": 100}
  }"
# Expected: {"message": "Heartbeat received"}
```

### c. Push a threat

```bash
curl -X POST http://72.60.25.24:8000/api/v2/threats \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{
    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%S)\",
    \"sensor_id\": \"$SENSOR_ID\",
    \"threat_type\": \"usb_rubber_ducky\",
    \"detector_type\": \"usb\",
    \"severity\": \"critical\",
    \"threat_score\": 0.95,
    \"confidence\": 0.98,
    \"matched_rules\": [{\"rule_id\": \"usb_rubber_ducky_001\", \"name\": \"USB Rubber Ducky\", \"severity\": \"critical\", \"confidence\": 0.98}],
    \"raw_event\": {\"vendor_id\": \"0x03eb\", \"product_id\": \"0x2401\"},
    \"latitude\": 37.7749,
    \"longitude\": -122.4194,
    \"city\": \"San Francisco\",
    \"country\": \"US\",
    \"device_name\": \"USB Rubber Ducky\",
    \"mitre_tactics\": [\"TA0008\"],
    \"mitre_techniques\": [\"T1200\"]
  }"
# Expected: 201 with the full threat row including a UUID
```

### d. Verify

- `curl http://72.60.25.24:8000/api/v2/threats` — should include the new threat
- Open `http://72.60.25.24:3000` — a critical-red dot should appear over San Francisco; the live event feed should show it
- Open the WebSocket if you want: `wscat -c ws://72.60.25.24:8000/api/v2/ws` — should receive a `threat` message

If all four happen, **Phase A is live**.

### Negative tests (should fail)

```bash
# Wrong API key — expect 401
curl -X POST http://72.60.25.24:8000/api/v2/threats \
  -H "Authorization: Bearer hms_garbage" \
  -H 'Content-Type: application/json' \
  -d '{"timestamp":"2026-05-09T22:00:00","sensor_id":"smoke-test-XXXX","threat_type":"x","detector_type":"usb","severity":"low"}'

# Right API key, wrong sensor_id in body — expect 403
curl -X POST http://72.60.25.24:8000/api/v2/threats \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"timestamp":"2026-05-09T22:00:00","sensor_id":"someone-else","threat_type":"x","detector_type":"usb","severity":"low"}'

# No auth header — expect 401
curl -X POST http://72.60.25.24:8000/api/v2/threats \
  -H 'Content-Type: application/json' \
  -d '{"timestamp":"2026-05-09T22:00:00","sensor_id":"smoke-test-XXXX","threat_type":"x","detector_type":"usb","severity":"low"}'
```

---

## 6. Smoke test from a real Pi (when ready)

On a Pi 4 or Pi Zero 2 W:

```bash
# Install agent (manually for now until install.sh is updated for V2)
git clone https://github.com/SecurityWard/honeyman-Project.git /opt/honeyman-src
cd /opt/honeyman-src/honeyman-v2/agent
sudo pip install -e .

# Register
curl -X POST http://72.60.25.24:8000/api/v2/sensors/register \
  -H 'Content-Type: application/json' \
  -d '{"requested_name": "pi-test", "capabilities": {"usb": true}, "enabled_detectors": ["usb"], "platform": "rpi4"}'

# Save the api_key
sudo mkdir -p /etc/honeyman
echo 'hms_...' | sudo tee /etc/honeyman/api_key > /dev/null
sudo chmod 600 /etc/honeyman/api_key

# Drop the example config
sudo cp /opt/honeyman-src/honeyman-v2/agent/example_config.yaml /etc/honeyman/config.yaml
sudo $EDITOR /etc/honeyman/config.yaml   # set sensor_id and base_url

# Copy rules into place
sudo mkdir -p /etc/honeyman/rules
sudo cp -r /opt/honeyman-src/honeyman-v2/agent/rules/* /etc/honeyman/rules/

# Run in the foreground first
sudo honeyman-agent --config /etc/honeyman/config.yaml --verbose
```

Within ~60 seconds the heartbeat should hit the dashboard. Plug in a USB
device matching one of the rules (or use a Rubber Ducky) to fire a threat.

---

## What to watch for

- **`No API key configured` warning at agent start** — the credentials file is missing or empty. Re-run the registration step.
- **401 from POST /threats in agent logs** — API key didn't match the hash on the sensor row. Likely the sensor was deleted on the backend; re-register.
- **403 from POST /threats** — the `sensor_id` in the threat payload doesn't match the API key's owner. Check `sensor_id` in `/etc/honeyman/config.yaml`.
- **Threat lands in DB but no map dot** — verify `latitude`/`longitude` are populated on the `threats` row. Check `LocationService` logs (only IP-based geolocation works today; GPS and WiFi positioning are TODOs).
- **Backend won't start, complaining about `time_bucket`** — TimescaleDB extension wasn't loaded into this database. Run `CREATE EXTENSION timescaledb;` in `psql` against the `honeyman_v2` DB.
