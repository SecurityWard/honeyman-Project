# Honeyman V2 Dashboard Backend

FastAPI-based REST API for Honeyman threat detection platform.

## Features

- **FastAPI** - Modern async Python web framework
- **PostgreSQL + TimescaleDB** - Time-series threat data storage
- **JWT Authentication** - Secure API access with role-based permissions
- **RESTful API** - Complete CRUD operations for sensors and threats
- **Real-time Analytics** - Threat trends, velocity, and geographic distribution
- **MQTT Integration** - Receive sensor data via MQTT broker
- **WebSocket** - Real-time threat feed for dashboard
- **Onboarding Flow** - One-time tokens for sensor registration

## Installation

### Prerequisites

- Python 3.11+
- PostgreSQL 15+ with TimescaleDB 2.13+
- Redis 7+
- MQTT Broker (Mosquitto recommended)

### Setup

```bash
# Clone repository
cd honeyman-v2/dashboard-v2/backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Setup environment
cp .env.example .env
vim .env  # Edit configuration

# Run database migrations
alembic upgrade head

# Create initial admin user (Python shell)
python3
>>> from app.db.base import AsyncSessionLocal
>>> from app.models.user import User, UserRole
>>> from app.core.security import get_password_hash
>>> import asyncio
>>>
>>> async def create_admin():
...     async with AsyncSessionLocal() as db:
...         admin = User(
...             username="admin",
...             email="admin@honeyman.io",
...             password_hash=get_password_hash("your-secure-password"),
...             full_name="Admin User",
...             role=UserRole.ADMIN,
...             is_active=True,
...             is_verified=True
...         )
...         db.add(admin)
...         await db.commit()
...         print("Admin user created")
>>>
>>> asyncio.run(create_admin())
```

## Running

### Development

```bash
# Start development server with auto-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# API documentation
open http://localhost:8000/api/v2/docs
```

### Production

```bash
# Using uvicorn with multiple workers
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4

# Or using gunicorn
gunicorn app.main:app \
    -w 4 \
    -k uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000 \
    --access-logfile - \
    --error-logfile -
```

## API Endpoints

### Authentication
- `POST /api/v2/auth/login` - User login
- `POST /api/v2/auth/refresh` - Refresh access token
- `POST /api/v2/auth/logout` - Logout
- `GET /api/v2/auth/me` - Get current user

### Sensors
- `GET /api/v2/sensors` - List sensors
- `GET /api/v2/sensors/{sensor_id}` - Get sensor
- `PUT /api/v2/sensors/{sensor_id}` - Update sensor
- `DELETE /api/v2/sensors/{sensor_id}` - Delete sensor
- `GET /api/v2/sensors/{sensor_id}/stats` - Sensor statistics
- `POST /api/v2/sensors/{sensor_id}/heartbeat` - Receive heartbeat

### Threats
- `GET /api/v2/threats` - Query threats
- `GET /api/v2/threats/{threat_id}` - Get threat
- `POST /api/v2/threats` - Create threat
- `PUT /api/v2/threats/{threat_id}/acknowledge` - Acknowledge threat
- `DELETE /api/v2/threats/{threat_id}` - Delete threat

### Analytics
- `GET /api/v2/analytics/overview` - Dashboard overview
- `GET /api/v2/analytics/trends` - Threat trends
- `GET /api/v2/analytics/top-threats` - Top threat types
- `GET /api/v2/analytics/top-sensors` - Top sensors
- `GET /api/v2/analytics/map` - Geographic distribution
- `GET /api/v2/analytics/velocity` - Threat velocity

### Onboarding
- `POST /api/v2/onboarding/tokens` - Generate onboarding token
- `POST /api/v2/onboarding/register` - Register sensor
- `GET /api/v2/onboarding/qrcode/{token}` - Get QR code

## Database Migrations

```bash
# Create a new migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback one migration
alembic downgrade -1

# Show current version
alembic current
```

## Testing

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=app tests/

# Run specific test file
pytest tests/test_api_sensors.py
```

## Architecture

```
app/
├── main.py                  # FastAPI application
├── core/
│   ├── config.py           # Settings management
│   └── security.py         # JWT & password hashing
├── api/
│   ├── deps.py             # API dependencies (auth, db)
│   ├── auth.py             # Authentication endpoints
│   ├── sensors.py          # Sensor endpoints
│   ├── threats.py          # Threat endpoints
│   ├── analytics.py        # Analytics endpoints
│   └── onboarding.py       # Onboarding endpoints
├── models/
│   ├── sensor.py           # Sensor database model
│   ├── threat.py           # Threat database model
│   └── user.py             # User database model
├── schemas/
│   ├── sensor.py           # Sensor Pydantic schemas
│   ├── threat.py           # Threat Pydantic schemas
│   ├── user.py             # User Pydantic schemas
│   ├── analytics.py        # Analytics Pydantic schemas
│   └── onboarding.py       # Onboarding Pydantic schemas
├── db/
│   └── base.py             # Database session
├── mqtt/
│   └── subscriber.py       # MQTT subscriber service
└── services/
    └── websocket.py        # WebSocket service
```

## TimescaleDB Features

### Hypertable
Threats table is converted to a TimescaleDB hypertable for optimized time-series storage:
- 1-day chunks
- Automatic compression after 7 days (10-20x compression)
- Automatic retention (90-day cleanup)

### Continuous Aggregates
Pre-computed hourly statistics for fast queries:
- Threat counts by sensor/detector/severity
- Average threat scores
- Auto-refresh every hour

### Querying
```sql
-- Query using time_bucket
SELECT
    time_bucket('1 hour', timestamp) AS bucket,
    COUNT(*) as count
FROM threats
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY bucket;

-- Use continuous aggregate
SELECT * FROM threat_stats_hourly
WHERE bucket > NOW() - INTERVAL '7 days';
```

## Security

### Authentication
- JWT tokens with configurable expiration
- Refresh token rotation
- Role-based access control (Admin, Analyst, Viewer)

### RBAC Permissions
- **Admin**: Full access to all endpoints
- **Analyst**: Read/write threats, read sensors
- **Viewer**: Read-only access

### API Security
- HTTPS required in production
- CORS configuration
- Rate limiting
- Input validation with Pydantic

## Environment Variables

See [.env.example](.env.example) for all available configuration options.

## License

Proprietary - Secured Foundations LLC

## Support

For issues and questions:
- GitHub: https://github.com/yourusername/honeyman
- Email: support@honeyman.io
