# Honeyman V2 Deployment Notes

## Production Deployment - December 12, 2025

### VPS Details
- **Server**: Hostinger VPS (72.60.25.24)
- **OS**: Debian 12
- **Domain**: honeymanproject.com

### Deployment Fixes Applied on VPS

The following fixes were applied directly on the production server and need to be synced back:

#### 1. Backend Schema Files - Type Annotation Fixes

**File**: `/root/honeyman-v2/backend/app/schemas/onboarding.py`
- Fixed: Changed `Dict[str, any]` to `Dict[str, Any]`
- Added `Any` to imports: `from typing import Optional, Dict, List, Any`

**File**: `/root/honeyman-v2/backend/app/schemas/analytics.py`
- Fixed: Changed `Dict[str, any]` to `Dict[str, Any]` (multiple occurrences)
- Added `Any` to imports: `from typing import List, Dict, Optional, Any`

#### 2. Python Dependencies

**Additional package installed**:
```bash
pip install email-validator
```

Should be added to `requirements.txt`:
```
email-validator>=2.3.0
```

### Production URLs

**Frontend**:
- Direct: http://72.60.25.24:3000
- Domain: http://honeymanproject.com/v2

**Backend API**:
- Health: http://72.60.25.24:8001/health
- API Docs: http://72.60.25.24:8001/api/v2/docs
- API Base: http://72.60.25.24:8001/api/v2

### Services Configuration

#### Backend Service
- **Service**: `honeyman-backend.service`
- **Port**: 8000 (internal), 8001 (nginx proxy)
- **Location**: `/etc/systemd/system/honeyman-backend.service`
- **Auto-start**: Enabled

#### Database
- **Type**: PostgreSQL 15
- **Database**: `honeyman_v2`
- **User**: `honeyman`
- **Tables**: users, sensors, threats

#### Nginx Configuration
- **Frontend**: Port 3000, proxied at `/v2` on main domain
- **Backend**: Port 8001 proxy to port 8000
- **Configs**:
  - `/etc/nginx/sites-available/honeyman-v2`
  - `/etc/nginx/sites-available/honeyman-v2-backend`

### Optional Services (Not Installed)
- MQTT Broker (for sensor communication)
- Redis (for WebSocket pub/sub)

Backend runs without these but shows warning logs.

### Next Steps

1. Pull VPS changes back to local repository
2. Add `email-validator` to requirements.txt
3. Fix empty schema files locally (onboarding.py, analytics.py)
4. Consider installing Redis and MQTT for full functionality
5. Set up SSL/HTTPS certificates

---
**Deployed by**: Claude Code
**Date**: December 12, 2025
