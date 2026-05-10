# Honeyman V2 - Complete Implementation Roadmap

## Executive Summary

This roadmap outlines the complete implementation plan for Honeyman V2, incorporating:
- **Zero-account sensor onboarding** architecture (new)
- **Modular detection system** with separated alert logic (new)
- **Global dashboard** with real-time threat visualization (partially complete)
- **MQTT-based distributed architecture** (in progress)
- **Existing detection modules** integration (needs refactoring)

---

## Current Status

### ✅ Completed Components

#### Dashboard Frontend (v2.0.0)
- [x] Real-time threat visualization with charts
- [x] Sensor status monitoring
- [x] Date range selector (24h, 7d, 30d, 90d, all time, custom)
- [x] Metric tooltips explaining calculations
- [x] About page with comprehensive documentation
- [x] WebSocket integration for live updates
- [x] Responsive design
- [x] Deployed to VPS (http://72.60.25.24:3000)

#### Backend API (FastAPI)
- [x] Core REST API endpoints
- [x] PostgreSQL integration
- [x] Analytics queries (trends, top threats, top sensors)
- [x] Sensor management
- [x] CORS configuration
- [x] Health checks
- [x] Deployed to VPS

#### Detection Modules (Legacy V1)
- [x] Enhanced USB detector with 360+ malware hashes
- [x] Enhanced BLE detector (Flipper Zero detection)
- [x] WiFi detector (Evil Twin, deauth attacks)
- [x] AirDrop detector (Bonjour abuse)
- [x] Network honeypot (OpenCanary-based)

### 🚧 Partially Complete

#### Zero-Account Onboarding
- [x] Architecture documentation
- [x] Provisioning API design
- [x] Install script (bash)
- [x] Docker Compose configuration
- [x] Mosquitto MQTT config with ACL
- [ ] Provisioning API implementation
- [ ] MQTT collector service
- [ ] Alert engine with hot-reload rules

### ❌ Not Started

- [ ] Main controller service
- [ ] Detection module refactoring (to work with alert engine)
- [ ] Rule distribution system
- [ ] Sensor management UI
- [ ] Global threat map (Leaflet.js)
- [ ] SSE event streaming

---

## Phase 1: Core Infrastructure (Priority: CRITICAL)

### 1.1 MQTT Broker Setup
**Status:** Architecture designed, needs deployment
**Time Estimate:** 2-3 hours
**Dependencies:** VPS access, SSL certificates

**Tasks:**
- [ ] Generate SSL certificates for MQTT broker (Let's Encrypt)
- [ ] Deploy Mosquitto container with TLS configuration
- [ ] Create initial passwd/ACL files for system users (collector, dashboard)
- [ ] Test MQTT connectivity from sensor and collector
- [ ] Configure firewall rules for port 8883

**Files:**
- `honeyman-v2/readme/onboarding/docker-compose.yml`
- `honeyman-v2/readme/onboarding/mosquitto.conf`
- `honeyman-v2/readme/onboarding/acl`

**Verification:**
```bash
mosquitto_sub -h broker.honeyman.io -p 8883 \
  --cafile ca.crt -u collector -P <password> -t 'honeypot/#'
```

---

### 1.2 Provisioning API Implementation
**Status:** Skeleton code exists, needs deployment
**Time Estimate:** 4-6 hours
**Dependencies:** PostgreSQL, Mosquitto

**Tasks:**
- [ ] Create Dockerfile for provisioning API
- [ ] Implement database migration/init script
- [ ] Deploy provisioning API container
- [ ] Test registration endpoint with mock data
- [ ] Implement rate limiting and abuse prevention
- [ ] Add admin authentication for DELETE endpoint
- [ ] Create cleanup cron job for stale sensors (30 days)

**API Endpoints to Verify:**
```bash
# Health check
curl http://api.honeyman.io/v1/health

# Register sensor
curl -X POST http://api.honeyman.io/v1/sensors/register \
  -H "Content-Type: application/json" \
  -d '{
    "requested_name": "test-sensor",
    "location": "Seattle, WA",
    "modules": ["usb", "ble", "wifi"]
  }'

# List sensors
curl http://api.honeyman.io/v1/sensors
```

**Files:**
- `honeyman-v2/readme/onboarding/provisioning_api.py`
- `honeyman-v2/readme/onboarding/requirements.txt`

---

### 1.3 MQTT Collector Service
**Status:** Not started
**Time Estimate:** 6-8 hours
**Dependencies:** Mosquitto, TimescaleDB, Redis

**Purpose:**
Subscribes to all sensor MQTT topics (`honeypot/#`), writes events to TimescaleDB, publishes to Redis for real-time dashboard updates.

**Implementation Plan:**
1. **Create collector service** (`vps/collector/mqtt_collector.py`)
   ```python
   import paho.mqtt.client as mqtt
   import psycopg2
   import redis
   import json

   def on_message(client, userdata, message):
       payload = json.loads(message.payload)
       topic = message.topic

       # Parse topic: honeypot/{sensor_id}/{type}
       parts = topic.split('/')
       sensor_id = parts[1]
       message_type = parts[2]  # events, health, alerts

       if message_type == 'events':
           write_threat_to_db(payload)
           publish_to_redis(payload)
       elif message_type == 'health':
           update_sensor_heartbeat(sensor_id, payload)
   ```

2. **Database schema** (extend existing)
   ```sql
   CREATE TABLE IF NOT EXISTS threats (
       id SERIAL PRIMARY KEY,
       event_id VARCHAR(50) UNIQUE NOT NULL,
       sensor_id VARCHAR(50) NOT NULL,
       timestamp TIMESTAMPTZ NOT NULL,
       module VARCHAR(20) NOT NULL,
       event_type VARCHAR(50) NOT NULL,
       severity VARCHAR(20) NOT NULL,
       confidence FLOAT NOT NULL,
       details JSONB,
       location JSONB,
       FOREIGN KEY (sensor_id) REFERENCES sensors(sensor_id)
   );

   CREATE INDEX idx_threats_timestamp ON threats(timestamp DESC);
   CREATE INDEX idx_threats_sensor_id ON threats(sensor_id);
   CREATE INDEX idx_threats_severity ON threats(severity);
   ```

3. **Redis pub/sub** for dashboard
   ```python
   redis_client.publish('honeyman:threats', json.dumps(payload))
   ```

**Tasks:**
- [ ] Implement MQTT subscriber
- [ ] Create database writer with connection pooling
- [ ] Implement Redis publisher
- [ ] Add error handling and retry logic
- [ ] Create systemd service
- [ ] Add logging and monitoring
- [ ] Test with simulated sensor data

**Files to Create:**
- `vps/collector/mqtt_collector.py`
- `vps/collector/Dockerfile`
- `vps/collector/requirements.txt`

---

### 1.4 TimescaleDB Migration
**Status:** Backend uses PostgreSQL, needs TimescaleDB hypertable
**Time Estimate:** 2-3 hours
**Dependencies:** Existing PostgreSQL database

**Tasks:**
- [ ] Backup existing `threats` table
- [ ] Install TimescaleDB extension
  ```sql
  CREATE EXTENSION IF NOT EXISTS timescaledb;
  ```
- [ ] Convert `threats` table to hypertable
  ```sql
  SELECT create_hypertable('threats', 'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
  );
  ```
- [ ] Add compression policy
  ```sql
  ALTER TABLE threats SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'sensor_id'
  );

  SELECT add_compression_policy('threats', INTERVAL '7 days');
  ```
- [ ] Add retention policy (90 days)
  ```sql
  SELECT add_retention_policy('threats', INTERVAL '90 days');
  ```
- [ ] Update analytics queries to use `time_bucket()`
- [ ] Test query performance

**Files to Update:**
- `backend/app/api/analytics.py` - replace `date_trunc()` with `time_bucket()`

---

## Phase 2: Sensor Onboarding System (Priority: HIGH)

### 2.1 Install Script Finalization
**Status:** Complete bash script exists
**Time Estimate:** 3-4 hours
**Dependencies:** Provisioning API

**Tasks:**
- [ ] Test install script on clean Raspberry Pi
- [ ] Add error handling for network failures
- [ ] Add rollback mechanism on failure
- [ ] Create detection module stubs (placeholders until Phase 3)
- [ ] Test non-interactive mode with environment variables
- [ ] Host install script on public URL
  ```bash
  # Add to nginx config
  location /install {
      alias /var/www/install.sh;
      default_type text/plain;
  }
  ```
- [ ] Create quick-start documentation

**Testing Checklist:**
- [ ] Install on Pi Zero 2 W
- [ ] Install on Pi 3B+
- [ ] Install on Pi 4
- [ ] Verify all modules enable/disable correctly
- [ ] Verify MQTT connection and authentication
- [ ] Verify sensor appears on dashboard

**Files:**
- `honeyman-v2/readme/onboarding/install.sh`

---

### 2.2 Alert Engine Implementation
**Status:** Architecture designed, not implemented
**Time Estimate:** 8-10 hours
**Dependencies:** None (runs on sensor)

**Purpose:**
Separates detection logic from alerting logic. Detection modules emit raw events, alert engine evaluates rules and decides actions.

**Architecture:**
```
Detection Module → Unix Socket → Alert Engine → MQTT Publish
                                      ↑
                                   YAML Rules
                                   (inotify)
```

**Implementation Plan:**

1. **Create alert engine** (`sensor/alert_engine.py`)
   ```python
   class AlertEngine:
       def __init__(self, rules_dir='/etc/honeyman/rules'):
           self.rules = {}
           self.load_all_rules()
           self.watch_rules_dir()

       def load_all_rules(self):
           """Load all YAML rule files"""
           for file in os.listdir(self.rules_dir):
               if file.endswith('.yaml'):
                   self.load_rule_file(file)

       def evaluate_event(self, event):
           """Evaluate event against all rules"""
           module = event['module']
           for rule in self.rules.get(module, []):
               if self.matches_conditions(event, rule):
                   self.execute_actions(event, rule)

       def matches_conditions(self, event, rule):
           """Check if event matches rule conditions"""
           conditions = rule['conditions']

           if 'all' in conditions:
               return all(self.check_condition(event, c)
                         for c in conditions['all'])
           elif 'any' in conditions:
               return any(self.check_condition(event, c)
                         for c in conditions['any'])

       def execute_actions(self, event, rule):
           """Execute rule actions (mqtt_publish, log, webhook)"""
           if 'mqtt_publish' in rule['actions']:
               self.mqtt_publish(event, rule['severity'])
           if 'local_log' in rule['actions']:
               self.log_alert(event, rule)
   ```

2. **Create Unix socket server**
   ```python
   import socket
   import json

   sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
   sock.bind('/var/run/honeyman/alert_engine.sock')
   sock.listen(5)

   while True:
       conn, _ = sock.accept()
       data = conn.recv(4096)
       event = json.loads(data)
       alert_engine.evaluate_event(event)
       conn.close()
   ```

3. **Implement inotify file watcher**
   ```python
   import inotify.adapters

   def watch_rules_dir(self):
       i = inotify.adapters.Inotify()
       i.add_watch(self.rules_dir)

       for event in i.event_gen(yield_nones=False):
           if 'IN_CLOSE_WRITE' in event[1]:
               self.load_rule_file(event[3])
               logger.info(f"Reloaded rules: {event[3]}")
   ```

**Tasks:**
- [ ] Implement rule parser (YAML → Python objects)
- [ ] Implement condition evaluator (>, >=, <, <=, ==, !=, in, contains)
- [ ] Implement action executors (MQTT, log, webhook)
- [ ] Add cooldown mechanism (prevent alert storms)
- [ ] Create default rule files (copy from install script)
- [ ] Add unit tests for rule evaluation
- [ ] Create systemd service
- [ ] Test hot-reload functionality

**Files to Create:**
- `sensor/alert_engine.py`
- `sensor/lib/rule_parser.py`
- `sensor/lib/condition_evaluator.py`
- `sensor/lib/action_executor.py`

---

### 2.3 Main Controller Service
**Status:** Placeholder exists
**Time Estimate:** 6-8 hours
**Dependencies:** Alert engine, MQTT client

**Purpose:**
Orchestrates all sensor components, manages module lifecycle, handles MQTT connection, buffers events offline.

**Implementation Plan:**

1. **Create main controller** (`sensor/main_controller.py`)
   ```python
   class SensorController:
       def __init__(self):
           self.config = self.load_config()
           self.sensor_id = self.config['sensor']['id']
           self.mqtt_client = self.setup_mqtt()
           self.modules = {}
           self.alert_engine = None
           self.offline_buffer = SQLiteBuffer()

       def start(self):
           """Start all enabled modules"""
           self.start_alert_engine()

           for module_name, module_config in self.config['modules'].items():
               if module_config['enabled']:
                   self.start_module(module_name)

           self.connect_mqtt()
           self.start_heartbeat_timer()

       def start_module(self, name):
           """Start detection module as subprocess"""
           module_path = f"/opt/honeyman/bin/{name}_detector.py"
           process = subprocess.Popen([module_path])
           self.modules[name] = process

       def send_heartbeat(self):
           """Send health status to MQTT"""
           payload = {
               'sensor_id': self.sensor_id,
               'timestamp': datetime.utcnow().isoformat(),
               'status': 'online',
               'modules': self.get_module_status(),
               'system': self.get_system_stats()
           }
           self.mqtt_publish('health', payload, retain=True)
   ```

2. **Implement offline buffer** (SQLite)
   ```python
   class SQLiteBuffer:
       def __init__(self, db_path='/var/lib/honeyman/buffer.db'):
           self.conn = sqlite3.connect(db_path)
           self.create_table()

       def store_event(self, event):
           """Store event when MQTT is offline"""
           self.conn.execute('''
               INSERT INTO events (timestamp, topic, payload)
               VALUES (?, ?, ?)
           ''', (time.time(), event['topic'], json.dumps(event)))

       def flush(self, mqtt_client):
           """Flush buffered events when back online"""
           cursor = self.conn.execute('SELECT * FROM events ORDER BY timestamp')
           for row in cursor:
               mqtt_client.publish(row[1], row[2])
               self.conn.execute('DELETE FROM events WHERE id = ?', (row[0],))
   ```

**Tasks:**
- [ ] Implement config loader (YAML)
- [ ] Implement MQTT client with TLS
- [ ] Implement offline buffering
- [ ] Implement module lifecycle management
- [ ] Implement heartbeat timer
- [ ] Add graceful shutdown handling
- [ ] Create systemd service with auto-restart
- [ ] Add logging and error reporting
- [ ] Test offline → online transition

**Files to Create:**
- `sensor/main_controller.py`
- `sensor/lib/sqlite_buffer.py`
- `sensor/lib/mqtt_client.py`

---

## Phase 3: Detection Module Refactoring (Priority: MEDIUM)

### 3.1 Adapt Existing Detectors
**Status:** V1 detectors exist, need refactoring
**Time Estimate:** 12-16 hours (2-3 hours per module)
**Dependencies:** Alert engine

**Current Issues:**
- Detectors directly print/log results
- No standardized event format
- No integration with alert engine
- Hard-coded severity/confidence logic

**Refactoring Pattern:**

**Before (V1):**
```python
# enhanced_usb_detector.py (V1)
def detect_threat():
    if threat_score > 0.8:
        print(f"CRITICAL: BadUSB detected {device_info}")
        # Direct MQTT publish or log
```

**After (V2):**
```python
# usb_detector.py (V2)
def detect_threat():
    event = {
        'event_id': f"evt_{uuid.uuid4().hex[:8]}",
        'timestamp': datetime.utcnow().isoformat(),
        'module': 'usb',
        'event_type': 'badusb_detected',
        'confidence': threat_score,
        'details': device_info,
        'threat_indicators': indicators
    }

    # Send to alert engine (no severity decision here)
    send_to_alert_engine(event)

def send_to_alert_engine(event):
    """Send event to alert engine via Unix socket"""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect('/var/run/honeyman/alert_engine.sock')
    sock.sendall(json.dumps(event).encode())
    sock.close()
```

**Tasks Per Module:**

#### 3.1.1 USB Detector
- [ ] Refactor event output format
- [ ] Remove direct MQTT publishing
- [ ] Send events to alert engine
- [ ] Read config from `/etc/honeyman/config.yaml`
- [ ] Test with USB rules in `/etc/honeyman/rules/usb_rules.yaml`

#### 3.1.2 BLE Detector
- [ ] Refactor event output format
- [ ] Remove direct MQTT publishing
- [ ] Send events to alert engine
- [ ] Read config from `/etc/honeyman/config.yaml`
- [ ] Test with BLE rules

#### 3.1.3 WiFi Detector
- [ ] Refactor event output format
- [ ] Remove direct MQTT publishing
- [ ] Send events to alert engine
- [ ] Add monitor mode detection
- [ ] Test with WiFi rules

#### 3.1.4 AirDrop Detector
- [ ] Refactor event output format
- [ ] Remove direct MQTT publishing
- [ ] Send events to alert engine
- [ ] Test with AirDrop rules

#### 3.1.5 Network Honeypot
- [ ] Integrate OpenCanary events
- [ ] Convert to standard event format
- [ ] Send events to alert engine
- [ ] Test with network rules

**Files to Refactor:**
- `sensors/enhanced_usb_detector.py` → `sensor/bin/usb_detector.py`
- `sensors/enhanced_ble_detector.py` → `sensor/bin/ble_detector.py`
- `sensors/wifi_detector_component.sh` → `sensor/bin/wifi_detector.py`
- `sensors/airdrop_detector_component.sh` → `sensor/bin/airdrop_detector.py`
- `sensors/network_honeypot_component.sh` → `sensor/bin/network_detector.py`

---

## Phase 4: Dashboard Enhancements (Priority: MEDIUM)

### 4.1 Global Threat Map
**Status:** Not started
**Time Estimate:** 6-8 hours
**Dependencies:** Sensor geo-location data

**Implementation Plan:**

1. **Install Leaflet.js**
   ```bash
   npm install leaflet react-leaflet
   ```

2. **Create ThreatMap component**
   ```typescript
   import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';

   export default function ThreatMap({ sensors }: Props) {
     return (
       <MapContainer center={[39.8283, -98.5795]} zoom={4}>
         <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />

         {sensors.map(sensor => (
           <Marker
             key={sensor.sensor_id}
             position={[sensor.latitude, sensor.longitude]}
             icon={getStatusIcon(sensor.status)}
           >
             <Popup>
               <h3>{sensor.sensor_id}</h3>
               <p>{sensor.location}</p>
               <p>Status: {sensor.status}</p>
               <p>Threats (24h): {sensor.threats_24h}</p>
             </Popup>
           </Marker>
         ))}
       </MapContainer>
     );
   }
   ```

3. **Add heat map overlay** (threat density)
   ```typescript
   import HeatmapLayer from 'react-leaflet-heatmap-layer';

   const heatPoints = threats.map(t => [t.latitude, t.longitude, t.severity_weight]);

   <HeatmapLayer points={heatPoints} />
   ```

**Tasks:**
- [ ] Create ThreatMap component
- [ ] Add marker clustering for dense areas
- [ ] Add heat map overlay
- [ ] Add filter controls (time range, severity, module)
- [ ] Implement marker click → sensor detail panel
- [ ] Add legend for status colors
- [ ] Test with mock sensor data

**Files to Create:**
- `frontend/src/components/map/ThreatMap.tsx`
- `frontend/src/components/map/ThreatMap.css`

---

### 4.2 Real-Time Event Feed (SSE)
**Status:** Backend WebSocket exists, frontend needs SSE
**Time Estimate:** 4-6 hours
**Dependencies:** MQTT collector, Redis

**Implementation Plan:**

1. **Create SSE endpoint** (backend)
   ```python
   from fastapi.responses import StreamingResponse
   import asyncio

   @app.get("/events/stream")
   async def event_stream():
       async def event_generator():
           pubsub = redis_client.pubsub()
           pubsub.subscribe('honeyman:threats')

           for message in pubsub.listen():
               if message['type'] == 'message':
                   yield f"data: {message['data']}\n\n"
                   await asyncio.sleep(0.1)

       return StreamingResponse(
           event_generator(),
           media_type="text/event-stream"
       )
   ```

2. **Create frontend SSE client**
   ```typescript
   export function useEventStream() {
     const [events, setEvents] = useState<Threat[]>([]);

     useEffect(() => {
       const eventSource = new EventSource('/api/events/stream');

       eventSource.onmessage = (event) => {
         const threat = JSON.parse(event.data);
         setEvents(prev => [threat, ...prev].slice(0, 50)); // Keep last 50
       };

       return () => eventSource.close();
     }, []);

     return events;
   }
   ```

3. **Create ThreatFeed component**
   ```typescript
   export default function ThreatFeed() {
     const events = useEventStream();

     return (
       <div className="threat-feed">
         <h2>Live Threat Feed</h2>
         {events.map(event => (
           <ThreatCard key={event.event_id} threat={event} />
         ))}
       </div>
     );
   }
   ```

**Tasks:**
- [ ] Implement SSE endpoint in backend
- [ ] Create useEventStream hook
- [ ] Create ThreatFeed component
- [ ] Add severity filtering
- [ ] Add module filtering
- [ ] Add auto-scroll toggle
- [ ] Add sound alerts for critical threats
- [ ] Test with simulated threat stream

**Files to Create:**
- `backend/app/api/events.py` - SSE endpoint
- `frontend/src/hooks/useEventStream.ts`
- `frontend/src/components/feed/ThreatFeed.tsx`

---

### 4.3 Sensor Management UI
**Status:** Not started
**Time Estimate:** 6-8 hours
**Dependencies:** Provisioning API

**Features:**
- View all registered sensors
- See sensor details (hardware, modules, location)
- View sensor event history
- Remove sensors (admin only)
- View sensor configuration

**Tasks:**
- [ ] Create SensorsPage (replace placeholder)
- [ ] Create sensor list view with filtering
- [ ] Create sensor detail modal
- [ ] Add sensor removal confirmation dialog
- [ ] Add sensor stats (uptime, events, etc.)
- [ ] Add module enable/disable UI (future: remote control)

**Files to Update:**
- `frontend/src/pages/SensorsPage.tsx`

---

## Phase 5: Advanced Features (Priority: LOW)

### 5.1 Rule Distribution System
**Status:** Architecture designed
**Time Estimate:** 8-10 hours
**Dependencies:** MQTT broker, alert engine

**Purpose:**
Push rule updates from VPS to sensors via MQTT control channel.

**Implementation:**
1. **Admin API endpoint** (VPS)
   ```python
   @app.post("/api/v1/rules/push")
   def push_rules(rule_file: str, content: str, target: str = "all"):
       """Push rule update to sensors via MQTT"""
       payload = {
           'rule_file': rule_file,
           'content': content,
           'checksum': hashlib.sha256(content.encode()).hexdigest()
       }

       if target == "all":
           mqtt_client.publish('honeypot/control/rules', json.dumps(payload))
       else:
           mqtt_client.publish(f'honeypot/control/{target}/rules', json.dumps(payload))
   ```

2. **Sensor rule receiver**
   ```python
   def on_rule_update(client, userdata, message):
       payload = json.loads(message.payload)
       rule_file = payload['rule_file']
       content = payload['content']

       # Verify checksum
       if hashlib.sha256(content.encode()).hexdigest() != payload['checksum']:
           logger.error("Rule checksum mismatch!")
           return

       # Write rule file
       with open(f"/etc/honeyman/rules/{rule_file}", 'w') as f:
           f.write(content)

       # Alert engine will auto-reload via inotify
       logger.info(f"Rule updated: {rule_file}")
   ```

**Tasks:**
- [ ] Implement rule push API endpoint
- [ ] Implement sensor rule receiver
- [ ] Add rule versioning
- [ ] Add rollback mechanism
- [ ] Create rule editor UI in dashboard
- [ ] Test rule distribution

---

### 5.2 Webhook Integration
**Status:** Not started
**Time Estimate:** 4-6 hours
**Dependencies:** Alert engine

**Features:**
- Send alerts to external services (Slack, Discord, custom webhooks)
- Configure webhooks per severity level
- Retry logic for failed deliveries

**Implementation:**
```python
# In alert engine action executor
def send_webhook(event, webhook_url):
    payload = {
        'sensor_id': event['sensor_id'],
        'severity': event['severity'],
        'threat_type': event['event_type'],
        'timestamp': event['timestamp'],
        'details': event['details']
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=5)
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Webhook delivery failed: {e}")
        # Queue for retry
```

**Tasks:**
- [ ] Implement webhook action in alert engine
- [ ] Add webhook configuration to rules
- [ ] Add retry queue (SQLite)
- [ ] Create webhook test endpoint
- [ ] Add Slack/Discord templates

---

### 5.3 Email Alerts
**Status:** Not started
**Time Estimate:** 4-6 hours
**Dependencies:** Alert engine, SMTP server

**Implementation:**
```python
def send_email_alert(event, recipients):
    msg = MIMEText(f"""
    HONEYMAN ALERT: {event['event_type']}

    Sensor: {event['sensor_id']}
    Severity: {event['severity']}
    Timestamp: {event['timestamp']}

    Details:
    {json.dumps(event['details'], indent=2)}
    """)

    msg['Subject'] = f"[HONEYMAN] {event['severity'].upper()} - {event['event_type']}"
    msg['From'] = 'alerts@honeyman.io'
    msg['To'] = ', '.join(recipients)

    smtp.send_message(msg)
```

---

## Phase 6: Testing & Documentation (Priority: HIGH)

### 6.1 Integration Testing
**Status:** Not started
**Time Estimate:** 8-12 hours

**Test Scenarios:**
1. **End-to-End Onboarding**
   - [ ] Run install script on clean Pi
   - [ ] Verify sensor registration
   - [ ] Verify MQTT connection
   - [ ] Verify sensor appears on dashboard

2. **Threat Detection Flow**
   - [ ] Simulate USB threat
   - [ ] Verify alert engine processes event
   - [ ] Verify MQTT publish
   - [ ] Verify collector writes to DB
   - [ ] Verify dashboard shows threat

3. **Offline Resilience**
   - [ ] Disconnect sensor from network
   - [ ] Generate threats
   - [ ] Reconnect sensor
   - [ ] Verify buffered events flush

4. **Rule Hot-Reload**
   - [ ] Modify rule file on sensor
   - [ ] Verify alert engine reloads
   - [ ] Verify new rules apply immediately

5. **Dashboard Real-Time Updates**
   - [ ] Generate threats
   - [ ] Verify SSE updates
   - [ ] Verify charts update
   - [ ] Verify map markers update

---

### 6.2 Documentation Updates
**Status:** Partial (onboarding docs exist)
**Time Estimate:** 6-8 hours

**Tasks:**
- [ ] Update README.md with V2 architecture
- [ ] Create deployment guide (VPS setup)
- [ ] Create sensor deployment guide (Raspberry Pi)
- [ ] Create API documentation (OpenAPI/Swagger)
- [ ] Create rule writing guide
- [ ] Create troubleshooting guide
- [ ] Add architecture diagrams (use ASCII art or Mermaid)

---

## Prioritized Task List

### Week 1: Core Infrastructure
1. Deploy MQTT broker with TLS (2-3 hours)
2. Deploy provisioning API (4-6 hours)
3. Implement MQTT collector (6-8 hours)
4. Migrate to TimescaleDB (2-3 hours)

**Total: ~18-25 hours**

### Week 2: Sensor System
1. Implement alert engine (8-10 hours)
2. Implement main controller (6-8 hours)
3. Test install script end-to-end (3-4 hours)

**Total: ~17-22 hours**

### Week 3: Detection Modules
1. Refactor USB detector (2-3 hours)
2. Refactor BLE detector (2-3 hours)
3. Refactor WiFi detector (2-3 hours)
4. Refactor AirDrop detector (2-3 hours)
5. Refactor Network honeypot (2-3 hours)

**Total: ~10-15 hours**

### Week 4: Dashboard & Testing
1. Implement threat map (6-8 hours)
2. Implement real-time feed (4-6 hours)
3. Integration testing (8-12 hours)
4. Documentation (6-8 hours)

**Total: ~24-34 hours**

---

## Success Metrics

### Technical Metrics
- [ ] Sensor onboarding completes in < 5 minutes
- [ ] MQTT latency < 100ms (sensor → collector)
- [ ] Database write latency < 50ms
- [ ] Dashboard loads in < 2 seconds
- [ ] Real-time feed updates within 1 second of event
- [ ] System handles 100 sensors with 1000 events/hour

### Functional Metrics
- [ ] All 5 detection modules operational
- [ ] Alert engine evaluates rules with 100% accuracy
- [ ] Zero data loss during network outages (offline buffer)
- [ ] Rule hot-reload works without service restart
- [ ] Dashboard shows all threats with correct severity

---

## Known Issues & Risks

### Technical Risks
1. **MQTT Scalability:** Mosquitto may struggle with 1000+ sensors
   - **Mitigation:** Implement sensor clustering or MQTT bridge

2. **Database Performance:** TimescaleDB queries may slow with millions of events
   - **Mitigation:** Aggressive compression and retention policies

3. **Raspberry Pi Limitations:** Limited CPU/RAM on older models
   - **Mitigation:** Module enable/disable, resource monitoring

4. **Network Reliability:** Sensors in poor network conditions
   - **Mitigation:** Offline buffer, adaptive heartbeat intervals

### Operational Risks
1. **Certificate Management:** Let's Encrypt certs expire every 90 days
   - **Mitigation:** Automated renewal with certbot

2. **Abuse Prevention:** Public registration endpoint may be abused
   - **Mitigation:** Rate limiting, sensor cleanup, monitoring

3. **Data Privacy:** Sensor data may contain sensitive information
   - **Mitigation:** No PII collection, optional geo-location, GDPR compliance

---

## Conclusion

This roadmap provides a clear path to completing Honeyman V2. The system is designed to be:
- **Scalable:** Handles 1000+ sensors with distributed architecture
- **Resilient:** Offline buffering, auto-reconnect, error recovery
- **Modular:** Enable/disable modules based on hardware
- **Flexible:** Hot-reload rules, remote configuration
- **User-Friendly:** Zero-account onboarding, single-command install

The core infrastructure (Phase 1) is the critical path. Once MQTT, provisioning, and collector are operational, the rest of the system can be built incrementally.

**Estimated Total Effort:** 70-100 hours (2-3 weeks full-time)
