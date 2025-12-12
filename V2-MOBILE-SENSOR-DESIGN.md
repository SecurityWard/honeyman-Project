# Honeyman V2 - Mobile Sensor Design

**Document Version:** 1.0
**Last Updated:** 2025-10-23
**Status:** Architecture Amendment

---

## Overview

This document clarifies the **mobile sensor architecture** for Honeyman V2. Sensors are designed to be **portable/carried**, not permanently placed in fixed locations.

---

## Key Design Principles

### 1. Sensors Are Mobile
- Sensors are carried by users (e.g., to conferences, events, travel)
- No fixed/permanent location
- Location captured **only when threats are detected**
- No GPS tracking or movement trails

### 2. User-Named Sensors
- Users provide a custom name during enrollment
- Examples: "DefCon-2025-Portable", "BlackHat-Sensor", "Research-RPI-01"
- No automatic location-based naming

### 3. Location-Centric Dashboard
- Dashboard focuses on **where threats occurred**, not where sensors are
- Global map shows threat locations, not sensor locations
- Click on location to see all threats detected there

---

## Sensor Onboarding Flow

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1: User visits dashboard → "Add New Sensor"           │
├─────────────────────────────────────────────────────────────┤
│  Dashboard Form:                                             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Sensor Name: [DefCon-2025-Portable____________]        │ │
│  │                                                         │ │
│  │ Description (optional):                                │ │
│  │ [Portable sensor for DefCon 2025 event_______]        │ │
│  │                                                         │ │
│  │ [Generate Installation Command]                        │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│  Step 2: Dashboard generates token + command                │
├─────────────────────────────────────────────────────────────┤
│  Installation Command:                                       │
│  curl -sSL get.honeyman.sh | sudo bash -s -- <TOKEN>       │
│                                                              │
│  Or scan QR code: [QR CODE IMAGE]                          │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│  Step 3: User runs command on RPI5                          │
├─────────────────────────────────────────────────────────────┤
│  Installer:                                                  │
│  • Detects platform (RPI5)                                  │
│  • Installs dependencies                                    │
│  • Configures agent with sensor name from token             │
│  • Registers with dashboard                                 │
│  • Starts detection                                         │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│  Step 4: Sensor online, ready to detect                     │
├─────────────────────────────────────────────────────────────┤
│  Dashboard shows:                                            │
│  🟢 DefCon-2025-Portable                                    │
│     Status: Online                                           │
│     Platform: Raspberry Pi 5                                 │
│     Capabilities: WiFi, BLE, USB, Network, AirDrop          │
│     Last Heartbeat: 30s ago                                  │
│     Threats Detected: 0 (none yet)                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Geolocation Strategy

### When Threat is Detected

```python
# Agent code - when threat detected
def handle_threat_detection(self, event):
    # Get current location
    location = self.get_current_location()

    # Create threat object
    threat = {
        'timestamp': datetime.utcnow().isoformat(),
        'sensor_id': self.config.sensor_id,
        'sensor_name': self.config.sensor_name,  # e.g., "DefCon-2025-Portable"
        'threat_type': event.threat_type,
        'threat_score': event.threat_score,
        'geolocation': location,
        'raw_data': event.raw_data
    }

    # Send to dashboard
    self.transport.send(threat)

def get_current_location(self):
    """Get location using available methods"""

    # Try GPS first (if hardware available)
    gps_location = self.gps_service.get_location()
    if gps_location:
        return {
            'lat': gps_location.latitude,
            'lon': gps_location.longitude,
            'accuracy': gps_location.accuracy,
            'source': 'gps'
        }

    # Fallback to WiFi positioning
    wifi_location = self.wifi_geolocation_service.get_location()
    if wifi_location:
        return {
            'lat': wifi_location.latitude,
            'lon': wifi_location.longitude,
            'accuracy': wifi_location.accuracy,
            'source': 'wifi'
        }

    # Last resort: IP geolocation (least accurate)
    ip_location = self.ip_geolocation_service.get_location()
    if ip_location:
        return {
            'lat': ip_location.latitude,
            'lon': ip_location.longitude,
            'accuracy': ip_location.accuracy,
            'source': 'ip'
        }

    # No location available
    return None
```

### Geolocation Methods Priority

1. **GPS** (most accurate, 5-10m accuracy)
   - Requires GPS hardware (USB GPS dongle or built-in)
   - Best for outdoor use
   - May not work indoors

2. **WiFi Positioning** (good accuracy, 20-100m)
   - Uses surrounding WiFi access points
   - Google Geolocation API or Mozilla Location Service
   - Works indoors and outdoors

3. **IP Geolocation** (city-level, km accuracy)
   - Uses public IP address
   - Services: ipapi.co, ipinfo.io, MaxMind GeoIP2
   - Least accurate but always available

---

## Database Schema

### Sensors Table (No Location)

```sql
CREATE TABLE sensors (
    sensor_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,  -- User-provided name
    description TEXT,             -- Optional user description
    platform VARCHAR(100) NOT NULL,

    -- Capabilities
    capabilities JSONB NOT NULL DEFAULT '{
        "wifi": false,
        "bluetooth": false,
        "usb": false,
        "network": false,
        "airdrop": false
    }',

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'offline',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat TIMESTAMPTZ,

    -- Configuration
    config JSONB,

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Note: NO location field - sensors don't have a "home" location
```

### Threats Table (Location Per Threat)

```sql
CREATE TABLE threats (
    threat_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sensor_id UUID NOT NULL REFERENCES sensors(sensor_id) ON DELETE CASCADE,
    sensor_name VARCHAR(255) NOT NULL,  -- Denormalized for easy querying

    -- Temporal
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Threat classification
    source VARCHAR(100) NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    threat_score FLOAT NOT NULL,
    risk_level VARCHAR(50) NOT NULL,

    -- Geolocation (captured at time of detection)
    geolocation GEOGRAPHY(POINT, 4326),
    geolocation_accuracy FLOAT,  -- meters
    geolocation_source VARCHAR(20),  -- 'gps', 'wifi', 'ip'
    city VARCHAR(100),
    country VARCHAR(2),

    -- Details
    threats_detected TEXT[],
    message TEXT,
    raw_data JSONB,

    CONSTRAINT valid_risk_level CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'info')),
    CONSTRAINT valid_geolocation_source CHECK (geolocation_source IN ('gps', 'wifi', 'ip', 'manual', NULL))
);

-- Convert to hypertable
SELECT create_hypertable('threats', 'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- Indexes
CREATE INDEX idx_threats_sensor_time ON threats(sensor_id, timestamp DESC);
CREATE INDEX idx_threats_location ON threats USING GIST(geolocation) WHERE geolocation IS NOT NULL;
CREATE INDEX idx_threats_city_country ON threats(country, city) WHERE city IS NOT NULL;
CREATE INDEX idx_threats_sensor_name ON threats(sensor_name);
```

---

## Dashboard Visualization

### Global Threat Map

```
┌──────────────────────────────────────────────────────────────┐
│  🌍 Global Threat Map                      [Filters ▼]       │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  🗺️  Interactive World Map (Leaflet.js)                     │
│                                                               │
│     ┌─────────────────────────────────────────────────────┐ │
│     │                                                      │ │
│     │                    🔴 Las Vegas                      │ │
│     │                       157                            │ │
│     │                                                      │ │
│     │      🟡 San Francisco                                │ │
│     │         34                                           │ │
│     │                                                      │ │
│     │                           🟢 New York                │ │
│     │                              8                       │ │
│     │                                                      │ │
│     │  🟠 London                                          │ │
│     │     23                                               │ │
│     │                                                      │ │
│     └─────────────────────────────────────────────────────┘ │
│                                                               │
│  Legend:                                                      │
│  🔴 Critical (50+)  🟠 High (20-49)  🟡 Medium (10-19)      │
│  🟢 Low (<10)                                                │
│                                                               │
│  Filters:                                                     │
│  Time: [Last 7 days ▼]  Sensor: [All ▼]  Type: [All ▼]     │
└──────────────────────────────────────────────────────────────┘
```

### Location Detail View (User Clicks "Las Vegas")

```
┌──────────────────────────────────────────────────────────────┐
│  📍 Las Vegas, NV, USA                         [← Back to Map]│
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  📊 Threat Summary                                           │
│  Total Threats: 157                                          │
│  Timeframe: Last 7 days                                      │
│  First Detection: 2025-10-18 14:32 UTC                      │
│  Last Detection: 2 minutes ago                               │
│                                                               │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                               │
│  🎯 Threat Types                                             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Evil Twin AP         ████████████████ 67 (43%)         │ │
│  │ BLE Spam             ███████████ 45 (29%)              │ │
│  │ USB Malware          ██████ 23 (15%)                   │ │
│  │ Port Scans           █████ 22 (14%)                    │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                               │
│  🔬 Sensors That Detected Threats Here                       │
│  • DefCon-2025-Portable (145 threats)                        │
│    └─ Last active: 5 min ago                                 │
│  • BlackHat-Sensor (12 threats)                              │
│    └─ Last active: 2 hours ago                               │
│                                                               │
│  ⚠️ Risk Distribution                                        │
│  🔴 Critical: 15    🟠 High: 48    🟡 Medium: 94            │
│                                                               │
│  📈 Timeline (Last 7 days)                                   │
│  ▁▂▃▅▄▃▅█▆▄▃▂▁ (Interactive hourly chart)                  │
│                                                               │
│  🔝 Top Threats                                              │
│  1. Evil Twin: "DefCon-Free" SSID (score: 0.92, critical)   │
│     Detected by: DefCon-2025-Portable                        │
│     Time: 2025-10-23 12:15:34 UTC                           │
│                                                               │
│  2. USB Malware: Stuxnet variant (score: 0.98, critical)    │
│     Detected by: DefCon-2025-Portable                        │
│     Time: 2025-10-22 15:42:18 UTC                           │
│                                                               │
│  3. BLE Spam: Flipper Zero signature (score: 0.85, high)    │
│     Detected by: DefCon-2025-Portable                        │
│     Time: 2025-10-23 11:08:52 UTC                           │
│                                                               │
│  [View All 157 Threats] [Export Data] [Generate Report]      │
└──────────────────────────────────────────────────────────────┘
```

---

## Dashboard Queries

### Get Threat Counts by Location

```sql
-- Aggregate threats by geographic location
SELECT
    country,
    city,
    ST_Y(geolocation::geometry) as lat,
    ST_X(geolocation::geometry) as lon,
    COUNT(*) as threat_count,
    COUNT(DISTINCT sensor_id) as sensor_count,
    COUNT(*) FILTER (WHERE risk_level = 'critical') as critical_count,
    COUNT(*) FILTER (WHERE risk_level = 'high') as high_count,
    COUNT(*) FILTER (WHERE risk_level = 'medium') as medium_count,
    COUNT(*) FILTER (WHERE risk_level = 'low') as low_count,
    array_agg(DISTINCT threat_type) as threat_types,
    array_agg(DISTINCT sensor_name) as sensors,
    MAX(threat_score) as max_severity,
    MIN(timestamp) as first_seen,
    MAX(timestamp) as last_seen
FROM threats
WHERE timestamp > NOW() - INTERVAL '7 days'
  AND geolocation IS NOT NULL
GROUP BY country, city, lat, lon
ORDER BY threat_count DESC;
```

### Get Threats for Specific Location

```sql
-- Get all threats detected in Las Vegas
SELECT
    threat_id,
    sensor_name,
    timestamp,
    threat_type,
    threat_score,
    risk_level,
    threats_detected,
    message,
    geolocation_accuracy,
    geolocation_source
FROM threats
WHERE city = 'Las Vegas'
  AND country = 'US'
  AND timestamp > NOW() - INTERVAL '7 days'
ORDER BY threat_score DESC, timestamp DESC
LIMIT 100;
```

### Get Sensor Activity by Location

```sql
-- Which sensors have been active in a location?
SELECT
    sensor_name,
    COUNT(*) as detection_count,
    MIN(timestamp) as first_detection,
    MAX(timestamp) as last_detection,
    AVG(threat_score) as avg_threat_score,
    array_agg(DISTINCT threat_type) as threat_types_detected
FROM threats
WHERE city = 'Las Vegas'
  AND country = 'US'
  AND timestamp > NOW() - INTERVAL '30 days'
GROUP BY sensor_name
ORDER BY detection_count DESC;
```

---

## Agent Implementation

### Location Service

```python
# src/agent/services/location_service.py

import gpsd
import requests
from typing import Optional, Dict

class LocationService:
    def __init__(self, config: dict):
        self.config = config
        self.gps_available = self._check_gps()
        self.last_location = None
        self.location_cache_ttl = 300  # 5 minutes

    def _check_gps(self) -> bool:
        """Check if GPS hardware is available"""
        try:
            gpsd.connect()
            return True
        except:
            return False

    def get_location(self) -> Optional[Dict]:
        """Get current location using best available method"""

        # Try GPS
        if self.gps_available:
            location = self._get_gps_location()
            if location:
                self.last_location = location
                return location

        # Try WiFi positioning
        location = self._get_wifi_location()
        if location:
            self.last_location = location
            return location

        # Try IP geolocation
        location = self._get_ip_location()
        if location:
            self.last_location = location
            return location

        # Return cached location if available
        return self.last_location

    def _get_gps_location(self) -> Optional[Dict]:
        """Get location from GPS"""
        try:
            packet = gpsd.get_current()
            if packet.mode >= 2:  # 2D or 3D fix
                return {
                    'lat': packet.lat,
                    'lon': packet.lon,
                    'accuracy': packet.error.get('eph', 10.0),  # meters
                    'source': 'gps'
                }
        except Exception as e:
            logger.debug(f"GPS location failed: {e}")
        return None

    def _get_wifi_location(self) -> Optional[Dict]:
        """Get location using WiFi access points (Google Geolocation API)"""
        try:
            # Scan for WiFi networks
            wifi_networks = self._scan_wifi_networks()
            if not wifi_networks:
                return None

            # Call Google Geolocation API
            api_key = self.config.get('google_geolocation_api_key')
            if not api_key:
                return None

            response = requests.post(
                'https://www.googleapis.com/geolocation/v1/geolocate',
                params={'key': api_key},
                json={'wifiAccessPoints': wifi_networks},
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'lat': data['location']['lat'],
                    'lon': data['location']['lng'],
                    'accuracy': data.get('accuracy', 100),
                    'source': 'wifi'
                }
        except Exception as e:
            logger.debug(f"WiFi location failed: {e}")
        return None

    def _scan_wifi_networks(self) -> list:
        """Scan for nearby WiFi access points"""
        # Use iwlist or similar to scan WiFi
        # Return list of {macAddress, signalStrength, channel}
        pass

    def _get_ip_location(self) -> Optional[Dict]:
        """Get location from IP address"""
        try:
            response = requests.get('https://ipapi.co/json/', timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'lat': data['latitude'],
                    'lon': data['longitude'],
                    'accuracy': 5000,  # ~5km accuracy for IP
                    'source': 'ip',
                    'city': data.get('city'),
                    'country': data.get('country_code')
                }
        except Exception as e:
            logger.debug(f"IP location failed: {e}")
        return None
```

### Threat Detection with Location

```python
# src/agent/detectors/base_detector.py

class BaseDetector(ABC):
    def __init__(self, rule_engine, transport, config, location_service):
        self.rule_engine = rule_engine
        self.transport = transport
        self.config = config
        self.location_service = location_service

    def create_threat(self, event, rules):
        """Create threat with current location"""

        # Get current location
        location = self.location_service.get_location()

        threat = {
            'timestamp': datetime.utcnow().isoformat(),
            'sensor_id': self.config.sensor_id,
            'sensor_name': self.config.sensor_name,  # User-provided name
            'source': self.__class__.__name__,
            'threat_type': rules[0].threat_type,
            'threat_score': self.calculate_score(rules),
            'risk_level': self.get_risk_level(score),
            'threats_detected': [r.name for r in rules],
            'raw_data': event
        }

        # Add location if available
        if location:
            threat['geolocation'] = {
                'lat': location['lat'],
                'lon': location['lon'],
                'accuracy': location['accuracy'],
                'source': location['source']
            }

            # Add city/country if available
            if 'city' in location:
                threat['city'] = location['city']
            if 'country' in location:
                threat['country'] = location['country']

        return threat
```

---

## Sensor Management Dashboard

### Sensors List View

```
┌──────────────────────────────────────────────────────────────┐
│  Sensors (3 total)                             [+ Add New]   │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ 🟢 DefCon-2025-Portable                                │ │
│  │    Platform: Raspberry Pi 5                            │ │
│  │    Capabilities: WiFi, BLE, USB, Network, AirDrop      │ │
│  │    Status: Online (last seen 2 min ago)                │ │
│  │    Total Threats: 1,247                                │ │
│  │    Locations Visited: Las Vegas, San Francisco         │ │
│  │    [Configure] [View Detections] [Logs]                │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ 🟢 BlackHat-Sensor                                     │ │
│  │    Platform: Raspberry Pi 4                            │ │
│  │    Capabilities: WiFi, BLE, USB, Network               │ │
│  │    Status: Online (last seen 45s ago)                  │ │
│  │    Total Threats: 342                                  │ │
│  │    Locations Visited: New York, Boston                 │ │
│  │    [Configure] [View Detections] [Logs]                │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ 🔴 Research-RPI-01                                     │ │
│  │    Platform: Raspberry Pi 5                            │ │
│  │    Capabilities: WiFi, BLE, USB                        │ │
│  │    Status: Offline (last seen 3 hours ago)             │ │
│  │    Total Threats: 89                                   │ │
│  │    Last Location: London, UK                           │ │
│  │    [Investigate] [Alert History]                       │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

---

## Summary

### Key Changes from Original Plan

| Aspect | Original Plan | Mobile Design |
|--------|---------------|---------------|
| **Sensor Location** | Fixed location in database | No permanent location |
| **Geolocation** | Sensor location + threat source IP | Location captured per threat |
| **Naming** | Auto-generated or location-based | User-provided during enrollment |
| **Dashboard Map** | Shows sensor locations | Shows threat locations |
| **Movement Tracking** | N/A | Explicitly disabled (no trails) |
| **Location Methods** | IP geolocation only | GPS → WiFi → IP (prioritized) |

### Architecture Impact

✅ **Simplified Database**: Removed location fields from sensors table
✅ **Enhanced Threats Table**: Added geolocation per threat with accuracy and source
✅ **Location-Centric UI**: Map focuses on where threats occurred
✅ **Flexible Geolocation**: Support GPS, WiFi positioning, and IP fallback
✅ **User Control**: Custom sensor naming during onboarding

---

**This design supports the core use case:** Security researchers carrying portable sensors to events/conferences, detecting threats in various locations, and visualizing threat activity on a global map.
