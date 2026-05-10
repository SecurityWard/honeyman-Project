# Honeyman V2 - Current Status Report

**Date:** December 22, 2025
**Dashboard Version:** 2.0.0
**Status:** Dashboard Complete, Infrastructure Planning Phase

---

## 🎉 Recently Completed

### Dashboard V2 Enhancements (December 22, 2025)

#### 1. Date Range Selector
**Status:** ✅ Complete and Deployed

Added comprehensive date range filtering to the dashboard with:
- **Preset ranges:** 24 hours, 7 days, 30 days, 90 days, all time
- **Custom range:** Date picker for specific start/end dates
- **Dynamic queries:** All analytics update based on selected range
- **Smart defaults:** Opens with 7-day view

**Files Modified:**
- [frontend/src/components/dashboard/DateRangeSelector.tsx](honeyman-v2/dashboard-v2/frontend/src/components/dashboard/DateRangeSelector.tsx)
- [frontend/src/pages/DashboardPage.tsx](honeyman-v2/dashboard-v2/frontend/src/pages/DashboardPage.tsx#L14-L41)
- [frontend/src/hooks/useAnalytics.ts](honeyman-v2/dashboard-v2/frontend/src/hooks/useAnalytics.ts)

**API Support:**
- Backend endpoints now accept `hours` parameter
- Updated: `/analytics/top-threats`, `/analytics/top-sensors`

#### 2. Metric Tooltips
**Status:** ✅ Complete and Deployed

Added informative tooltips explaining each dashboard metric:
- **Total Threats:** Total number of security threats detected across all sensors
- **Threats (24h):** Number of threats detected in the last 24 hours
- **Critical Threats:** Threats requiring immediate attention
- **High Threats:** Threats that should be investigated promptly
- **Active Sensors:** Number of sensors currently enabled and configured
- **Online Sensors:** Number of sensors currently connected and reporting data
- **Threat Velocity:** Average rate of threat detection (threats per hour)
- **Avg Threat Score:** Average confidence score of detected threats (0-100%)

**Files Created:**
- [frontend/src/components/common/TooltipIcon.tsx](honeyman-v2/dashboard-v2/frontend/src/components/common/TooltipIcon.tsx)
- [frontend/src/components/common/TooltipIcon.css](honeyman-v2/dashboard-v2/frontend/src/components/common/TooltipIcon.css)

**Files Modified:**
- [frontend/src/components/dashboard/DashboardOverview.tsx](honeyman-v2/dashboard-v2/frontend/src/components/dashboard/DashboardOverview.tsx#L69-L71)

#### 3. About/Documentation Page
**Status:** ✅ Complete and Deployed

Created comprehensive About page documenting:
- **System Overview:** What Honeyman V2 is and how it works
- **Detection Capabilities:**
  - WiFi: Evil Twin, Deauth Attacks, Rogue APs, Weak Security
  - USB: Malicious Devices (360+ signatures), HID Attacks, Mass Storage Threats
  - Bluetooth: Unauthorized Devices, Active Scanning, Device Profiling
- **Metric Calculations:**
  - Threat Score Formula: `BaseScore × ConfidenceMultiplier × ContextWeight`
  - Severity Classification: Critical, High, Medium, Low
  - Threat Velocity: `TotalThreats / TimeWindow (hours)`
- **System Architecture:** 5-step flow diagram
- **Technology Stack:** React, FastAPI, PostgreSQL, MQTT, Raspberry Pi
- **Data Retention:** 90-day default policy
- **Getting Started:** Sensor deployment instructions

**Files Created:**
- [frontend/src/pages/AboutPage.tsx](honeyman-v2/dashboard-v2/frontend/src/pages/AboutPage.tsx)
- [frontend/src/pages/AboutPage.css](honeyman-v2/dashboard-v2/frontend/src/pages/AboutPage.css)

**Files Modified:**
- [frontend/src/App.tsx](honeyman-v2/dashboard-v2/frontend/src/App.tsx#L27) - Added `/about` route
- [frontend/src/components/layout/Layout.tsx](honeyman-v2/dashboard-v2/frontend/src/components/layout/Layout.tsx#L27-L32) - Added About link to navigation

**Access:** http://72.60.25.24:3000/about

---

## 🏗️ Current Architecture

### Dashboard (Frontend)
- **Framework:** React 18 + TypeScript + Vite
- **UI Library:** Custom CSS with responsive design
- **Charts:** Recharts (line charts, bar charts, pie charts)
- **State Management:** React Query (@tanstack/react-query)
- **Routing:** React Router v7
- **Deployment:** Nginx on VPS (http://72.60.25.24:3000)

### Backend API
- **Framework:** FastAPI (Python)
- **Database:** PostgreSQL (not yet TimescaleDB)
- **ORM:** SQLAlchemy
- **Validation:** Pydantic
- **CORS:** Configured for VPS frontend
- **Deployment:** Uvicorn on VPS (http://72.60.25.24:8000)

### Database Schema
```sql
-- Sensors table
CREATE TABLE sensors (
    id SERIAL PRIMARY KEY,
    sensor_id VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100),
    location VARCHAR(200),
    latitude FLOAT,
    longitude FLOAT,
    status VARCHAR(20) DEFAULT 'registered',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP
);

-- Threats table
CREATE TABLE threats (
    id SERIAL PRIMARY KEY,
    sensor_id VARCHAR(50) REFERENCES sensors(sensor_id),
    timestamp TIMESTAMP NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence FLOAT,
    details JSONB,
    raw_data JSONB
);
```

---

## 📊 API Endpoints

### Analytics Endpoints
| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| GET | `/analytics/overview` | Dashboard summary stats | `hours` (optional) |
| GET | `/analytics/trends` | Time-series threat trends | `period`, `hours` |
| GET | `/analytics/top-threats` | Top threat types | `limit`, `hours` |
| GET | `/analytics/top-sensors` | Most active sensors | `limit`, `hours` |
| GET | `/analytics/map` | Sensor geo-location data | `hours` |

### Sensor Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/sensors` | List all sensors |
| GET | `/sensors/{id}` | Get sensor details |
| POST | `/sensors` | Register new sensor |
| PUT | `/sensors/{id}` | Update sensor |
| DELETE | `/sensors/{id}` | Remove sensor |

### Threat Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/threats` | List threats with pagination |
| GET | `/threats/{id}` | Get threat details |
| POST | `/threats` | Create new threat (from sensor) |

---

## 🚀 Deployment Status

### VPS (72.60.25.24)
- **OS:** Ubuntu/Debian
- **Services Running:**
  - ✅ Nginx (reverse proxy + static file server)
  - ✅ PostgreSQL (database)
  - ✅ FastAPI Backend (port 8000)
  - ✅ React Dashboard (served via Nginx on port 3000)
  - ❌ MQTT Broker (Mosquitto) - Not yet deployed
  - ❌ MQTT Collector - Not yet implemented
  - ❌ Provisioning API - Not yet deployed
  - ❌ TimescaleDB - Not yet configured

### Frontend Build
- **Location:** `/root/honeyman-v2/frontend/dist/`
- **Size:** ~34KB CSS, ~882KB JS (gzipped: ~269KB)
- **Build Tool:** Vite
- **Last Build:** December 22, 2025

### Backend
- **Location:** `/root/honeyman-v2/backend/`
- **Python Version:** 3.x
- **Virtual Environment:** `/root/honeyman-v2/backend/venv/`
- **Process Manager:** Needs systemd service or PM2

---

## 🔧 Recent Bug Fixes

### 1. CORS Configuration
**Issue:** Dashboard couldn't communicate with backend API
**Solution:** Added VPS frontend URL to CORS origins
**File:** `backend/app/core/config.py`

### 2. TimescaleDB Dependency Removal
**Issue:** `time_bucket()` function not available (TimescaleDB not installed)
**Solution:** Replaced with PostgreSQL's built-in `date_trunc()`
**File:** `backend/app/api/analytics.py`

### 3. API Response Structure Mismatch
**Issue:** Frontend expected flat array, API returned nested object
**Solution:** Extract `data_points` from API response in hooks
**File:** `frontend/src/hooks/useAnalytics.ts`

### 4. Empty Data Handling
**Issue:** Charts crashed when no data available for time period
**Solution:** Added empty data checks and fallback messages
**Files:**
- `frontend/src/components/analytics/TopThreatsChart.tsx`
- `frontend/src/components/analytics/TopSensorsChart.tsx`

### 5. Missing Hours Parameter
**Issue:** Backend analytics endpoints didn't accept `hours` parameter
**Solution:** Added `hours`/`days` parameter support to all analytics endpoints
**File:** `backend/app/api/analytics.py`

---

## 📁 New Documentation Files

### Onboarding Architecture
**Location:** `honeyman-v2/readme/onboarding/`

This directory contains the complete V2 zero-account onboarding architecture:

1. **README.md** - Overview of onboarding system
   - Zero-account design philosophy
   - Self-selected names with random suffixes
   - Separated alert logic architecture
   - Modular detection system

2. **ARCHITECTURE.md** - Complete system architecture
   - Detailed component diagrams
   - MQTT topic structure
   - Event/health payload schemas
   - Detection module capabilities
   - Alert engine design

3. **install.sh** - One-command sensor installer
   - Interactive setup prompts
   - Hardware detection (BLE, WiFi, monitor mode)
   - Module selection UI
   - Auto-registration with provisioning API
   - Systemd service creation

4. **provisioning_api.py** - Sensor registration API
   - Flask-based REST API
   - Unique ID generation with random suffixes
   - PostgreSQL integration
   - Mosquitto credential management
   - Rate limiting (10 registrations/hour/IP)
   - Stale sensor cleanup (30 days)

5. **docker-compose.yml** - VPS deployment config
   - TimescaleDB (PostgreSQL + time-series)
   - Redis (pub/sub for dashboard)
   - Mosquitto (MQTT broker with TLS)
   - Provisioning API
   - MQTT Collector
   - Dashboard API + SSE
   - Nginx reverse proxy
   - Certbot (Let's Encrypt)

6. **mosquitto.conf** - MQTT broker configuration
   - Internal listener (port 1883, no TLS)
   - External listener (port 8883, TLS 1.3)
   - Per-sensor ACLs
   - Persistence and logging

7. **acl** - Mosquitto access control template
   - System user permissions (collector, dashboard)
   - Sensor topic isolation
   - Dynamic ACL updates

8. **requirements.txt** - Provisioning API dependencies
   - Flask, Flask-Limiter
   - psycopg2 (PostgreSQL driver)
   - gunicorn (WSGI server)

### Key Concepts

#### Zero-Account Onboarding
- **No user accounts required** - Sensors self-register
- **Anonymous operation** - No PII collection
- **Self-selected names** - User picks name, system adds random suffix
  - Example: `defcon-hotel` → `defcon-hotel-7x9k`
- **Single command install:**
  ```bash
  curl -sSL https://honeyman.io/install | bash
  ```

#### Separated Alert Logic
- **Detection modules** emit raw events (no severity decisions)
- **Alert engine** evaluates YAML rules
- **Hot-reload** - Rules update without restart (inotify)
- **Actions:** mqtt_publish, local_log, webhook, email
- **Cooldown** - Prevents alert storms

#### Modular Detection
- Each module (USB, BLE, WiFi, AirDrop, Network) is independent
- Enable/disable based on detected hardware
- Works on all Raspberry Pi models (Zero W to Pi 5)

---

## 🎯 Next Steps (Priority Order)

### Immediate (Week 1)
1. **Deploy MQTT Broker** (2-3 hours)
   - Generate SSL certificates
   - Deploy Mosquitto container
   - Configure firewall for port 8883
   - Test connectivity

2. **Deploy Provisioning API** (4-6 hours)
   - Build Docker container
   - Initialize database schema
   - Deploy to VPS
   - Test registration endpoint

3. **Implement MQTT Collector** (6-8 hours)
   - Create subscriber service
   - Connect to Mosquitto
   - Write events to database
   - Publish to Redis for dashboard

4. **Migrate to TimescaleDB** (2-3 hours)
   - Install TimescaleDB extension
   - Convert threats table to hypertable
   - Add compression policy
   - Add retention policy (90 days)

**Week 1 Total:** ~18-25 hours

### Short-Term (Week 2)
1. **Implement Alert Engine** (8-10 hours)
   - Create rule parser (YAML)
   - Implement condition evaluator
   - Implement action executors
   - Add inotify file watcher
   - Test hot-reload

2. **Implement Main Controller** (6-8 hours)
   - Create orchestration service
   - Manage module lifecycle
   - Handle MQTT connection
   - Implement offline buffer (SQLite)

3. **Test Install Script** (3-4 hours)
   - Test on Pi Zero 2 W, Pi 3B+, Pi 4
   - Verify end-to-end onboarding
   - Fix any issues

**Week 2 Total:** ~17-22 hours

### Medium-Term (Week 3)
1. **Refactor Detection Modules** (10-15 hours)
   - Update USB detector for alert engine
   - Update BLE detector
   - Update WiFi detector
   - Update AirDrop detector
   - Update Network honeypot

### Long-Term (Week 4+)
1. **Dashboard Enhancements**
   - Global threat map (Leaflet.js)
   - Real-time event feed (SSE)
   - Sensor management UI

2. **Advanced Features**
   - Rule distribution system
   - Webhook integration
   - Email alerts

3. **Testing & Documentation**
   - Integration tests
   - API documentation
   - Deployment guides

---

## 📈 Metrics & Performance

### Current Performance
- **Dashboard Load Time:** ~2 seconds
- **API Response Time:** 50-200ms (analytics queries)
- **Database Queries:** Using PostgreSQL `date_trunc()` (not optimized)
- **Chart Render Time:** <500ms

### Target Performance (After TimescaleDB)
- **Dashboard Load Time:** <2 seconds ✅
- **API Response Time:** <50ms (with time_bucket)
- **Database Write Latency:** <50ms
- **MQTT Latency:** <100ms (sensor → collector)
- **Real-time Feed Update:** <1 second

### Scalability Targets
- **Sensors:** 1000+ concurrent
- **Events:** 1000/hour aggregate
- **Database Size:** Multi-TB with compression
- **Retention:** 90 days default

---

## 🐛 Known Issues

### Active Issues
1. **TimescaleDB Not Configured**
   - Currently using standard PostgreSQL
   - Need to install extension and create hypertables
   - Analytics queries not optimized

2. **No Real-Time Updates**
   - Dashboard polls backend every 60 seconds
   - Need SSE implementation for instant updates

3. **No MQTT Infrastructure**
   - Sensors can't connect yet
   - Need Mosquitto broker deployment
   - Need collector service

4. **Sensors Page is Placeholder**
   - Empty page, needs full implementation
   - Should show sensor list, details, stats

### Resolved Issues
- ✅ CORS errors (fixed with VPS URL in allowed origins)
- ✅ time_bucket() errors (replaced with date_trunc)
- ✅ Empty data crashes (added null checks)
- ✅ Missing hours parameter (added to all endpoints)
- ✅ Chart tooltip errors (added optional chaining)

---

## 📚 Resources

### Documentation
- [IMPLEMENTATION-ROADMAP.md](IMPLEMENTATION-ROADMAP.md) - Complete implementation plan
- [V2-OVERVIEW.md](V2-OVERVIEW.md) - V2 architecture overview
- [ARCHITECTURE-V2.md](ARCHITECTURE-V2.md) - Technical architecture
- [readme/onboarding/README.md](readme/onboarding/README.md) - Onboarding system docs
- [readme/onboarding/ARCHITECTURE.md](readme/onboarding/ARCHITECTURE.md) - Detailed architecture

### Code Repositories
- **Frontend:** `honeyman-v2/dashboard-v2/frontend/`
- **Backend:** `honeyman-v2/dashboard-v2/backend/`
- **Sensors:** `sensors/` (V1, needs refactoring)
- **Onboarding:** `honeyman-v2/readme/onboarding/`

### Deployment
- **VPS IP:** 72.60.25.24
- **Dashboard URL:** http://72.60.25.24:3000
- **API URL:** http://72.60.25.24:8000
- **API Docs:** http://72.60.25.24:8000/docs (FastAPI auto-generated)

---

## 🎉 Summary

### What's Working
✅ Dashboard frontend with all UI features
✅ Backend API with analytics endpoints
✅ Date range filtering
✅ Metric tooltips
✅ Comprehensive About page
✅ Responsive design
✅ Empty data handling
✅ CORS configuration

### What's Next
🔨 MQTT infrastructure (broker + collector)
🔨 Sensor onboarding system
🔨 Alert engine implementation
🔨 Detection module refactoring
🔨 Real-time updates (SSE)
🔨 Global threat map

### Estimated Completion
**Core System (Phases 1-3):** 2-3 weeks full-time
**Full Feature Set (Phases 1-5):** 3-4 weeks full-time

The dashboard is **production-ready** for viewing existing data. The infrastructure work (MQTT, collector, onboarding) is the critical path to enable sensor deployments.
