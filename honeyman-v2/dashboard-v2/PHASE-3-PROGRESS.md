# Phase 3: Dashboard Backend - In Progress

**Status**: 🔄 In Progress (70% Complete)
**Date Started**: 2025-11-30
**Target**: Phase 3 Complete in 4 weeks

---

## Progress Summary

### ✅ Completed (70%)

1. **Backend Project Structure**
   - FastAPI application skeleton
   - Directory structure created
   - Dependencies defined

2. **Core Configuration**
   - Settings management (Pydantic)
   - Environment variable loading
   - Security utilities (JWT, password hashing)

3. **Database Models**
   - Sensor model (full CRUD ready)
   - Threat model (TimescaleDB hypertable)
   - User model (authentication)

4. **Database Migrations**
   - Alembic setup complete
   - Initial schema migration (001)
   - TimescaleDB hypertable configuration
   - Compression & retention policies
   - Materialized views for analytics

5. **FastAPI Application Core**
   - Main application setup
   - CORS middleware
   - Request timing middleware
   - Exception handlers
   - Health check endpoint

6. **Pydantic Schemas** ✅
   - Sensor schemas (create, update, response, stats)
   - Threat schemas (create, response, query, map)
   - User schemas (create, update, login, token)
   - Analytics schemas (overview, trends, velocity)
   - Onboarding schemas (tokens, registration)

7. **API Endpoints - Authentication** ✅
   - POST /auth/login - User login with JWT
   - POST /auth/refresh - Refresh access token
   - POST /auth/logout - User logout
   - GET /auth/me - Get current user

8. **API Endpoints - Sensors** ✅
   - GET /sensors - List sensors with pagination
   - GET /sensors/{id} - Get sensor details
   - PUT /sensors/{id} - Update sensor
   - DELETE /sensors/{id} - Delete sensor
   - GET /sensors/{id}/stats - Sensor statistics
   - POST /sensors/{id}/heartbeat - Receive heartbeat

9. **API Endpoints - Threats** ✅
   - GET /threats - Query threats with filters
   - GET /threats/{id} - Get threat details
   - POST /threats - Create threat
   - PUT /threats/{id}/acknowledge - Acknowledge threat
   - DELETE /threats/{id} - Delete threat

10. **API Endpoints - Analytics** ✅
    - GET /analytics/overview - Dashboard overview
    - GET /analytics/trends - Threat trends over time
    - GET /analytics/top-threats - Top threat types
    - GET /analytics/top-sensors - Top sensors
    - GET /analytics/map - Geographic distribution
    - GET /analytics/velocity - Threat velocity metrics

11. **API Endpoints - Onboarding** ✅
    - POST /onboarding/tokens - Generate onboarding token
    - POST /onboarding/register - Register new sensor
    - GET /onboarding/qrcode/{token} - Get QR code

12. **Security & Dependencies** ✅
    - JWT authentication middleware
    - Role-based access control (RBAC)
    - API dependencies for auth checks
    - Password hashing utilities

13. **Documentation** ✅
    - README.md with setup instructions
    - .env.example with all variables
    - API documentation via FastAPI

---

## Files Created (30 files)

### Configuration & Core
```
backend/
├── requirements.txt                      ✅ Dependencies
├── alembic.ini                          ✅ Alembic config
├── app/
│   ├── main.py                          ✅ FastAPI app
│   ├── core/
│   │   ├── config.py                    ✅ Settings
│   │   └── security.py                  ✅ JWT & passwords
│   ├── db/
│   │   └── base.py                      ✅ Database session
│   ├── models/
│   │   ├── sensor.py                    ✅ Sensor model
│   │   ├── threat.py                    ✅ Threat model (hypertable)
│   │   └── user.py                      ✅ User model
│   └── alembic/
│       ├── env.py                       ✅ Migration env
│       ├── script.py.mako               ✅ Migration template
│       └── versions/
│           └── 001_initial_schema.py    ✅ Initial migration
```

---

## Database Schema

### Tables

#### 1. sensors
```sql
CREATE TABLE sensors (
    id UUID PRIMARY KEY,
    sensor_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description VARCHAR(500),
    is_active BOOLEAN DEFAULT TRUE,
    is_online BOOLEAN DEFAULT FALSE,
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    latitude FLOAT,
    longitude FLOAT,
    location_method VARCHAR(20),
    location_accuracy FLOAT,
    city VARCHAR(100),
    country VARCHAR(100),
    enabled_detectors JSON DEFAULT '[]',
    transport_protocol VARCHAR(20) DEFAULT 'mqtt',
    capabilities JSON DEFAULT '{}',
    platform VARCHAR(50),
    architecture VARCHAR(20),
    agent_version VARCHAR(20),
    python_version VARCHAR(20),
    total_threats_detected INTEGER DEFAULT 0,
    threats_last_24h INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    mqtt_username VARCHAR(255),
    mqtt_password_hash VARCHAR(255)
);
```

#### 2. threats (TimescaleDB Hypertable)
```sql
CREATE TABLE threats (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,  -- Time dimension
    sensor_id VARCHAR(100) REFERENCES sensors(sensor_id),
    threat_type VARCHAR(100) NOT NULL,
    detector_type VARCHAR(20) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    device_name VARCHAR(255),
    device_mac VARCHAR(50),
    device_ip VARCHAR(50),
    src_host VARCHAR(100),
    src_port INTEGER,
    dst_host VARCHAR(100),
    dst_port INTEGER,
    latitude FLOAT,
    longitude FLOAT,
    city VARCHAR(100),
    country VARCHAR(100),
    matched_rules JSON DEFAULT '[]',
    confidence FLOAT,
    threat_score FLOAT,
    raw_event JSON,
    mitre_tactics JSON DEFAULT '[]',
    mitre_techniques JSON DEFAULT '[]',
    is_acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    acknowledged_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Convert to hypertable
SELECT create_hypertable('threats', 'timestamp',
    chunk_time_interval => INTERVAL '1 day'
);

-- Compression (7 days)
ALTER TABLE threats SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'sensor_id,detector_type'
);
SELECT add_compression_policy('threats', INTERVAL '7 days');

-- Retention (90 days)
SELECT add_retention_policy('threats', INTERVAL '90 days');
```

#### 3. users
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role ENUM('admin', 'analyst', 'viewer') DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    last_login TIMESTAMP WITH TIME ZONE
);
```

### Materialized Views

#### threat_stats_hourly (Continuous Aggregate)
```sql
CREATE MATERIALIZED VIEW threat_stats_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', timestamp) AS bucket,
    sensor_id,
    detector_type,
    severity,
    COUNT(*) as threat_count,
    AVG(threat_score) as avg_threat_score
FROM threats
GROUP BY bucket, sensor_id, detector_type, severity;

-- Auto-refresh hourly
SELECT add_continuous_aggregate_policy('threat_stats_hourly',
    start_offset => INTERVAL '3 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour'
);
```

---

## Next Steps (60% Remaining)

### Week 1 (Current)
- [ ] Create Pydantic schemas for API requests/responses
- [ ] Implement authentication API endpoints
- [ ] Implement sensor CRUD endpoints
- [ ] Implement threat query endpoints
- [ ] Create analytics aggregation endpoints

### Week 2
- [ ] Implement MQTT subscriber service
- [ ] Build real-time threat ingestion pipeline
- [ ] Add heartbeat processing
- [ ] Implement geolocation enrichment service

### Week 3
- [ ] Implement WebSocket real-time service
- [ ] Build Redis pub/sub integration
- [ ] Create onboarding API endpoints
- [ ] Implement sensor provisioning flow

### Week 4
- [ ] API testing & documentation
- [ ] Performance optimization
- [ ] Error handling improvements
- [ ] Deployment preparation

---

## API Endpoints (Planned)

### Authentication
- `POST /api/v2/auth/login` - User login
- `POST /api/v2/auth/refresh` - Refresh token
- `POST /api/v2/auth/logout` - User logout
- `GET /api/v2/auth/me` - Get current user

### Sensors
- `GET /api/v2/sensors` - List all sensors
- `GET /api/v2/sensors/{sensor_id}` - Get sensor details
- `PUT /api/v2/sensors/{sensor_id}` - Update sensor
- `DELETE /api/v2/sensors/{sensor_id}` - Delete sensor
- `GET /api/v2/sensors/{sensor_id}/threats` - Get sensor threats
- `GET /api/v2/sensors/{sensor_id}/stats` - Get sensor statistics

### Threats
- `GET /api/v2/threats` - Query threats (with filters)
- `GET /api/v2/threats/{threat_id}` - Get threat details
- `PUT /api/v2/threats/{threat_id}/acknowledge` - Acknowledge threat
- `GET /api/v2/threats/export` - Export threats (CSV/JSON)

### Analytics
- `GET /api/v2/analytics/overview` - Dashboard overview
- `GET /api/v2/analytics/trends` - Threat trends
- `GET /api/v2/analytics/map` - Geospatial threat data
- `GET /api/v2/analytics/velocity` - Threat velocity metrics
- `GET /api/v2/analytics/mitre` - MITRE ATT&CK coverage

### Onboarding
- `POST /api/v2/onboarding/tokens` - Generate onboarding token
- `POST /api/v2/onboarding/register` - Register new sensor
- `GET /api/v2/onboarding/qrcode/{token}` - Get QR code

### WebSocket
- `WS /api/v2/ws` - Real-time threat feed

---

## Technology Stack

### Backend Framework
- **FastAPI** 0.104.1 - Modern async Python API framework
- **Uvicorn** - ASGI server
- **Pydantic** 2.5.0 - Data validation

### Database
- **PostgreSQL** 15+ - Primary database
- **TimescaleDB** 2.13+ - Time-series extension
- **SQLAlchemy** 2.0 - Async ORM
- **Alembic** - Database migrations

### Caching & Real-time
- **Redis** 7+ - Caching and pub/sub
- **WebSockets** - Real-time communications

### Security
- **python-jose** - JWT tokens
- **passlib[bcrypt]** - Password hashing
- **python-multipart** - Form data

### MQTT
- **paho-mqtt** 1.6.1 - MQTT client

---

## Configuration

### Environment Variables Required

```bash
# Application
SECRET_KEY=<random-secret-key>
DEBUG=false

# Database
DATABASE_URL=postgresql+asyncpg://honeyman:password@localhost/honeyman_v2

# Redis
REDIS_URL=redis://localhost:6379/0

# MQTT Broker
MQTT_BROKER_HOST=mqtt.honeyman.io
MQTT_BROKER_PORT=8883
MQTT_BROKER_USERNAME=dashboard
MQTT_BROKER_PASSWORD=<mqtt-password>
MQTT_USE_TLS=true

# Geolocation (optional)
GOOGLE_GEOLOCATION_API_KEY=<api-key>
IP_GEOLOCATION_API_KEY=<api-key>
```

---

## Running the Backend

### Development

```bash
# Install dependencies
cd honeyman-v2/dashboard-v2/backend
pip install -r requirements.txt

# Setup environment
cp .env.example .env
vim .env  # Edit configuration

# Run database migrations
alembic upgrade head

# Start development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Production

```bash
# Use multiple workers
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4

# Or use gunicorn
gunicorn app.main:app \
    -w 4 \
    -k uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000
```

---

## Database Setup

### PostgreSQL + TimescaleDB Installation

```bash
# Ubuntu/Debian
sudo apt-get install -y postgresql-15 postgresql-15-timescaledb

# Enable TimescaleDB
sudo -u postgres psql -c "CREATE EXTENSION timescaledb CASCADE;"

# Create database and user
sudo -u postgres psql <<EOF
CREATE DATABASE honeyman_v2;
CREATE USER honeyman WITH PASSWORD 'password';
GRANT ALL PRIVILEGES ON DATABASE honeyman_v2 TO honeyman;
EOF

# Enable TimescaleDB in database
sudo -u postgres psql -d honeyman_v2 -c "CREATE EXTENSION timescaledb CASCADE;"
```

### Run Migrations

```bash
# From backend directory
alembic upgrade head
```

---

## Performance Optimizations

### TimescaleDB Compression
- **Automatic compression** after 7 days
- **Segment by** sensor_id and detector_type
- **Compression ratio**: 10-20x typical

### Data Retention
- **Automatic deletion** after 90 days
- **Chunk-based deletion** (fast, no table bloat)
- **Configurable** via `DATA_RETENTION_DAYS`

### Continuous Aggregates
- **Pre-computed statistics** refreshed hourly
- **Fast dashboard queries** (sub-second)
- **Materialized views** with automatic refresh

---

## Phase 3 Timeline

**Week 1** (Current): Database & Core API ✅ 40%
**Week 2**: MQTT Integration & Data Ingestion
**Week 3**: WebSocket & Real-time Services
**Week 4**: Testing & Optimization

**Target Completion**: 4 weeks from start

---

*Last Updated: 2025-11-30*
*Status: 40% Complete - On Track*
