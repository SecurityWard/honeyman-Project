# Honeyman Dashboard Backend

FastAPI-based REST API for the Honeyman threat detection platform.

## Features

- **FastAPI** — async Python web framework
- **PostgreSQL + TimescaleDB** — time-series threat storage with 90-day retention and 7-day compression
- **Per-sensor API keys** — sensors authenticate writes with `Authorization: Bearer <key>`. The dashboard read endpoints are **public** (no login).
- **Self-register onboarding** — `POST /sensors/register` returns a one-time API key the sensor stores and uses thereafter
- **MQTT integration (optional)** — receive sensor data via MQTT broker when `MQTT_OFFERED=true`. Default transport is HTTPS.
- **WebSocket** — public real-time threat feed for the dashboard

## Installation

### Prerequisites

- Python 3.11+
- PostgreSQL 15+ with TimescaleDB 2.13+
- Redis 7+
- Mosquitto (only if you opt into MQTT transport)

### Setup

```bash
cd honeyman-v2/dashboard-v2/backend

python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
$EDITOR .env

alembic upgrade head
```

There is no admin-user step — the system has no users by design.

## Running

### Development

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# Swagger UI: http://localhost:8000/api/v2/docs
```

### Production

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
# or via gunicorn
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

## API Endpoints

**Public (no auth):**
- `GET  /api/v2/sensors` — list sensors
- `GET  /api/v2/sensors/{sensor_id}` — sensor details
- `GET  /api/v2/sensors/{sensor_id}/stats` — sensor statistics
- `GET  /api/v2/threats` — query threats with filters
- `GET  /api/v2/threats/{threat_id}` — threat details
- `GET  /api/v2/analytics/overview` — dashboard overview
- `GET  /api/v2/analytics/trends` — time-series trends
- `GET  /api/v2/analytics/top-threats` — top threat types
- `GET  /api/v2/analytics/top-sensors` — most active sensors
- `GET  /api/v2/analytics/map` — geographic threat distribution
- `GET  /api/v2/analytics/velocity` — threat rate metrics
- `WS   /api/v2/ws` — live threat feed

**Sensor-authenticated (Authorization: Bearer <api_key>):**
- `POST /api/v2/sensors/register` — self-register, returns one-time API key (anyone can call this; it's how a sensor gets its key)
- `POST /api/v2/sensors/{sensor_id}/heartbeat` — health/location ping (key must match {sensor_id})
- `POST /api/v2/threats` — push a detected threat (key must match `sensor_id` in payload)

There are no acknowledge/delete/update endpoints. The dashboard is a viewing surface; sensors are managed via SSH.

## Database Migrations

```bash
alembic revision --autogenerate -m "description"
alembic upgrade head
alembic downgrade -1
alembic current
```

## Testing

```bash
pytest
pytest --cov=app tests/
```

## Source layout

```
app/
├── main.py                  FastAPI app + startup/shutdown
├── core/
│   ├── config.py            Pydantic settings (env-driven)
│   └── api_key.py           API key generate / hash / verify
├── api/
│   ├── deps.py              authenticated_sensor dependency
│   ├── sensors.py           sensor list/get/stats + heartbeat
│   ├── threats.py           threat list/get + ingest
│   ├── analytics.py         analytics endpoints (public)
│   ├── onboarding.py        self-register flow
│   └── websocket.py         live feed (public)
├── models/
│   ├── sensor.py            Sensor SQLAlchemy model (incl. api_key_hash)
│   └── threat.py            Threat hypertable model
├── schemas/                 Pydantic request/response schemas
├── db/base.py               Async session factory
├── mqtt/subscriber.py       MQTT subscriber (only started if MQTT_OFFERED=true)
└── services/
    ├── redis_client.py      Redis pub/sub + cache
    └── websocket.py         WebSocket connection manager
```

## TimescaleDB Features

- **Hypertable**: `threats` is partitioned by `timestamp` into 1-day chunks
- **Compression**: chunks older than 7 days are compressed (10–20x reduction)
- **Retention**: chunks older than 90 days are dropped automatically
- **Continuous aggregate**: `threat_stats_hourly` materialized view for fast dashboard queries

```sql
-- Query using time_bucket
SELECT time_bucket('1 hour', timestamp) AS bucket, COUNT(*) AS n
FROM threats
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY bucket;

-- Or use the continuous aggregate
SELECT * FROM threat_stats_hourly
WHERE bucket > NOW() - INTERVAL '7 days';
```

## Security model

- **Read endpoints** are public. The dashboard is intentionally an open viewing surface.
- **Write endpoints** require a per-sensor API key issued at registration. Only the SHA256 hash is stored on the sensor row; plaintext is returned exactly once.
- **CORS** is whitelisted via `CORS_ORIGINS` in env
- **Rate limiting** is enabled by default (60 req/min)
- **HTTPS** is required in production — terminate TLS at nginx in front of the FastAPI app

## Environment Variables

See [`.env.example`](.env.example) for all available options.

## License

MIT — see the repository root [`LICENSE`](../../../LICENSE).
