#!/usr/bin/env python3
"""
Honeyman V2 - Provisioning API
Zero-account sensor registration and management

Endpoints:
  POST /api/v1/sensors/register  - Register new sensor
  GET  /api/v1/sensors           - List all sensors
  GET  /api/v1/sensors/<id>      - Get sensor details
  DELETE /api/v1/sensors/<id>    - Remove sensor (admin)
  GET  /api/v1/health            - API health check
"""

import os
import re
import secrets
import hashlib
import subprocess
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional

from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# Configuration
CONFIG = {
    'db_url': os.getenv('DATABASE_URL', 'postgresql://honeyman:secret@localhost/honeyman'),
    'mosquitto_passwd_file': os.getenv('MOSQUITTO_PASSWD_FILE', '/etc/mosquitto/passwd'),
    'mosquitto_acl_file': os.getenv('MOSQUITTO_ACL_FILE', '/etc/mosquitto/acl'),
    'max_sensors': int(os.getenv('MAX_SENSORS', 1000)),
    'broker_host': os.getenv('BROKER_HOST', 'broker.honeyman.io'),
    'broker_port': int(os.getenv('BROKER_PORT', 8883)),
    'ca_cert_path': os.getenv('CA_CERT_PATH', '/etc/honeyman/certs/ca.crt'),
    'stale_days': int(os.getenv('STALE_SENSOR_DAYS', 30)),
}

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

# Character set for random suffix (no ambiguous chars)
SUFFIX_CHARS = 'abcdefghjkmnpqrstuvwxyz23456789'
SUFFIX_LENGTH = 4


# =============================================================================
# Database
# =============================================================================

def get_db():
    """Get database connection."""
    conn = psycopg2.connect(CONFIG['db_url'])
    return conn


def init_db():
    """Initialize database schema."""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('''
        CREATE TABLE IF NOT EXISTS sensors (
            id SERIAL PRIMARY KEY,
            sensor_id VARCHAR(50) UNIQUE NOT NULL,
            secret_hash VARCHAR(128) NOT NULL,
            name VARCHAR(50) NOT NULL,
            location VARCHAR(100),
            latitude FLOAT,
            longitude FLOAT,
            modules JSONB DEFAULT '[]',
            hardware JSONB DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP,
            status VARCHAR(20) DEFAULT 'registered',
            events_count INTEGER DEFAULT 0
        );
        
        CREATE INDEX IF NOT EXISTS idx_sensors_sensor_id ON sensors(sensor_id);
        CREATE INDEX IF NOT EXISTS idx_sensors_status ON sensors(status);
        CREATE INDEX IF NOT EXISTS idx_sensors_last_seen ON sensors(last_seen);
    ''')
    
    conn.commit()
    cur.close()
    conn.close()


# =============================================================================
# Sensor ID Generation
# =============================================================================

def sanitize_name(name: str) -> str:
    """Sanitize user-provided name."""
    # Lowercase, keep only alphanumeric and hyphens
    sanitized = re.sub(r'[^a-z0-9-]', '', name.lower())
    # Remove leading/trailing hyphens
    sanitized = sanitized.strip('-')
    # Collapse multiple hyphens
    sanitized = re.sub(r'-+', '-', sanitized)
    # Truncate to 20 chars
    return sanitized[:20] if sanitized else 'sensor'


def generate_suffix() -> str:
    """Generate random suffix for sensor ID."""
    return ''.join(secrets.choice(SUFFIX_CHARS) for _ in range(SUFFIX_LENGTH))


def generate_sensor_id(requested_name: str) -> str:
    """Generate unique sensor ID from requested name."""
    base = sanitize_name(requested_name)
    
    conn = get_db()
    cur = conn.cursor()
    
    # Try up to 10 times to find unique ID
    for _ in range(10):
        suffix = generate_suffix()
        sensor_id = f"{base}-{suffix}"
        
        cur.execute('SELECT 1 FROM sensors WHERE sensor_id = %s', (sensor_id,))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            return sensor_id
    
    cur.close()
    conn.close()
    
    # Fallback: use timestamp-based suffix
    timestamp_suffix = hex(int(datetime.utcnow().timestamp()))[2:][-4:]
    return f"{base}-{timestamp_suffix}"


def generate_secret() -> str:
    """Generate random secret for sensor authentication."""
    return secrets.token_hex(32)


def hash_secret(secret: str) -> str:
    """Hash secret for storage."""
    return hashlib.sha256(secret.encode()).hexdigest()


# =============================================================================
# Mosquitto Management
# =============================================================================

def add_mosquitto_credentials(sensor_id: str, secret: str):
    """Add sensor credentials to Mosquitto password file."""
    try:
        # Use mosquitto_passwd to add user
        subprocess.run([
            'mosquitto_passwd', '-b',
            CONFIG['mosquitto_passwd_file'],
            sensor_id,
            secret
        ], check=True, capture_output=True)
        
        # Add ACL entry
        acl_entry = f"""
# Sensor: {sensor_id}
user {sensor_id}
topic write honeypot/{sensor_id}/#
topic read honeypot/global/#
topic read honeypot/control/#
"""
        
        with open(CONFIG['mosquitto_acl_file'], 'a') as f:
            f.write(acl_entry)
        
        # Signal Mosquitto to reload config
        subprocess.run(['pkill', '-HUP', 'mosquitto'], capture_output=True)
        
        return True
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Failed to add Mosquitto credentials: {e}")
        return False
    except Exception as e:
        app.logger.error(f"Error managing Mosquitto: {e}")
        return False


def remove_mosquitto_credentials(sensor_id: str):
    """Remove sensor credentials from Mosquitto."""
    try:
        # Remove from password file
        subprocess.run([
            'mosquitto_passwd', '-D',
            CONFIG['mosquitto_passwd_file'],
            sensor_id
        ], check=True, capture_output=True)
        
        # Remove from ACL file (read, filter, write)
        with open(CONFIG['mosquitto_acl_file'], 'r') as f:
            lines = f.readlines()
        
        # Filter out lines for this sensor
        filtered_lines = []
        skip_until_next_sensor = False
        for line in lines:
            if f"# Sensor: {sensor_id}" in line:
                skip_until_next_sensor = True
                continue
            if skip_until_next_sensor and line.startswith("# Sensor:"):
                skip_until_next_sensor = False
            if not skip_until_next_sensor:
                filtered_lines.append(line)
        
        with open(CONFIG['mosquitto_acl_file'], 'w') as f:
            f.writelines(filtered_lines)
        
        # Reload Mosquitto
        subprocess.run(['pkill', '-HUP', 'mosquitto'], capture_output=True)
        
        return True
    except Exception as e:
        app.logger.error(f"Error removing Mosquitto credentials: {e}")
        return False


# =============================================================================
# API Endpoints
# =============================================================================

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0'
    })


@app.route('/api/v1/sensors/register', methods=['POST'])
@limiter.limit("10 per hour")
def register_sensor():
    """
    Register a new sensor.
    
    Request body:
    {
        "requested_name": "my-sensor",
        "location": "Las Vegas, NV",  // optional
        "latitude": 36.1699,          // optional
        "longitude": -115.1398,       // optional
        "modules": ["usb", "ble", "wifi", "network"],
        "hardware": {                 // optional
            "model": "Raspberry Pi 4",
            "ram_gb": 4,
            "has_ble": true,
            "has_wifi": true
        }
    }
    
    Response:
    {
        "sensor_id": "my-sensor-7x9k",
        "secret": "a7b9c2d4e6f8...",
        "broker": {
            "host": "broker.honeyman.io",
            "port": 8883,
            "ca_cert": "-----BEGIN CERTIFICATE-----..."
        },
        "topics": {
            "events": "honeypot/my-sensor-7x9k/events",
            "health": "honeypot/my-sensor-7x9k/health",
            "alerts": "honeypot/my-sensor-7x9k/alerts"
        }
    }
    """
    data = request.get_json()
    
    if not data:
        abort(400, description="Request body required")
    
    if 'requested_name' not in data:
        abort(400, description="requested_name is required")
    
    # Check sensor limit
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM sensors')
    count = cur.fetchone()[0]
    
    if count >= CONFIG['max_sensors']:
        cur.close()
        conn.close()
        abort(503, description="Maximum sensor limit reached")
    
    # Generate sensor ID and secret
    sensor_id = generate_sensor_id(data['requested_name'])
    secret = generate_secret()
    
    # Add to Mosquitto
    if not add_mosquitto_credentials(sensor_id, secret):
        cur.close()
        conn.close()
        abort(500, description="Failed to provision MQTT credentials")
    
    # Store in database
    try:
        cur.execute('''
            INSERT INTO sensors (sensor_id, secret_hash, name, location, latitude, longitude, modules, hardware)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            sensor_id,
            hash_secret(secret),
            sanitize_name(data['requested_name']),
            data.get('location'),
            data.get('latitude'),
            data.get('longitude'),
            psycopg2.extras.Json(data.get('modules', [])),
            psycopg2.extras.Json(data.get('hardware', {}))
        ))
        conn.commit()
    except Exception as e:
        conn.rollback()
        remove_mosquitto_credentials(sensor_id)
        cur.close()
        conn.close()
        app.logger.error(f"Database error: {e}")
        abort(500, description="Failed to register sensor")
    
    cur.close()
    conn.close()
    
    # Load CA certificate
    ca_cert = ""
    try:
        with open(CONFIG['ca_cert_path'], 'r') as f:
            ca_cert = f.read()
    except Exception as e:
        app.logger.warning(f"Could not load CA cert: {e}")
    
    return jsonify({
        'sensor_id': sensor_id,
        'secret': secret,
        'broker': {
            'host': CONFIG['broker_host'],
            'port': CONFIG['broker_port'],
            'ca_cert': ca_cert
        },
        'topics': {
            'events': f"honeypot/{sensor_id}/events",
            'health': f"honeypot/{sensor_id}/health",
            'alerts': f"honeypot/{sensor_id}/alerts"
        },
        'dashboard_url': f"https://dashboard.honeyman.io/sensor/{sensor_id}"
    }), 201


@app.route('/api/v1/sensors', methods=['GET'])
def list_sensors():
    """List all registered sensors."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Query parameters
    status = request.args.get('status')
    limit = min(int(request.args.get('limit', 100)), 1000)
    offset = int(request.args.get('offset', 0))
    
    query = 'SELECT sensor_id, name, location, modules, status, last_seen, created_at FROM sensors'
    params = []
    
    if status:
        query += ' WHERE status = %s'
        params.append(status)
    
    query += ' ORDER BY created_at DESC LIMIT %s OFFSET %s'
    params.extend([limit, offset])
    
    cur.execute(query, params)
    sensors = cur.fetchall()
    
    # Get total count
    cur.execute('SELECT COUNT(*) FROM sensors')
    total = cur.fetchone()['count']
    
    cur.close()
    conn.close()
    
    return jsonify({
        'sensors': sensors,
        'total': total,
        'limit': limit,
        'offset': offset
    })


@app.route('/api/v1/sensors/<sensor_id>', methods=['GET'])
def get_sensor(sensor_id: str):
    """Get details for a specific sensor."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute('''
        SELECT sensor_id, name, location, latitude, longitude, modules, hardware, 
               status, last_seen, created_at, events_count
        FROM sensors WHERE sensor_id = %s
    ''', (sensor_id,))
    
    sensor = cur.fetchone()
    cur.close()
    conn.close()
    
    if not sensor:
        abort(404, description="Sensor not found")
    
    return jsonify(sensor)


@app.route('/api/v1/sensors/<sensor_id>', methods=['DELETE'])
def delete_sensor(sensor_id: str):
    """Delete a sensor (removes credentials and database entry)."""
    # In production, add authentication here
    
    conn = get_db()
    cur = conn.cursor()
    
    # Check if sensor exists
    cur.execute('SELECT 1 FROM sensors WHERE sensor_id = %s', (sensor_id,))
    if cur.fetchone() is None:
        cur.close()
        conn.close()
        abort(404, description="Sensor not found")
    
    # Remove from database
    cur.execute('DELETE FROM sensors WHERE sensor_id = %s', (sensor_id,))
    conn.commit()
    cur.close()
    conn.close()
    
    # Remove Mosquitto credentials
    remove_mosquitto_credentials(sensor_id)
    
    return jsonify({'message': f'Sensor {sensor_id} deleted'}), 200


@app.route('/api/v1/sensors/<sensor_id>/heartbeat', methods=['POST'])
def sensor_heartbeat(sensor_id: str):
    """Update sensor last_seen timestamp (called by sensors or MQTT collector)."""
    data = request.get_json() or {}
    
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('''
        UPDATE sensors 
        SET last_seen = CURRENT_TIMESTAMP, 
            status = %s,
            modules = COALESCE(%s, modules)
        WHERE sensor_id = %s
    ''', (
        data.get('status', 'online'),
        psycopg2.extras.Json(data.get('modules')) if data.get('modules') else None,
        sensor_id
    ))
    
    if cur.rowcount == 0:
        cur.close()
        conn.close()
        abort(404, description="Sensor not found")
    
    conn.commit()
    cur.close()
    conn.close()
    
    return jsonify({'message': 'Heartbeat recorded'}), 200


@app.route('/api/v1/stats', methods=['GET'])
def get_stats():
    """Get global statistics."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Total sensors
    cur.execute('SELECT COUNT(*) as total FROM sensors')
    total = cur.fetchone()['total']
    
    # Online sensors (seen in last 5 minutes)
    cur.execute('''
        SELECT COUNT(*) as online FROM sensors 
        WHERE last_seen > NOW() - INTERVAL '5 minutes'
    ''')
    online = cur.fetchone()['online']
    
    # Sensors by status
    cur.execute('''
        SELECT status, COUNT(*) as count FROM sensors GROUP BY status
    ''')
    by_status = {row['status']: row['count'] for row in cur.fetchall()}
    
    # Recent registrations (last 24h)
    cur.execute('''
        SELECT COUNT(*) as recent FROM sensors 
        WHERE created_at > NOW() - INTERVAL '24 hours'
    ''')
    recent = cur.fetchone()['recent']
    
    cur.close()
    conn.close()
    
    return jsonify({
        'total_sensors': total,
        'online_sensors': online,
        'by_status': by_status,
        'registrations_24h': recent
    })


# =============================================================================
# Maintenance Tasks
# =============================================================================

def cleanup_stale_sensors():
    """Remove sensors that haven't been seen in STALE_DAYS days."""
    conn = get_db()
    cur = conn.cursor()
    
    cutoff = datetime.utcnow() - timedelta(days=CONFIG['stale_days'])
    
    # Get stale sensor IDs
    cur.execute('''
        SELECT sensor_id FROM sensors 
        WHERE last_seen < %s OR (last_seen IS NULL AND created_at < %s)
    ''', (cutoff, cutoff))
    
    stale_sensors = [row[0] for row in cur.fetchall()]
    
    for sensor_id in stale_sensors:
        # Remove from database
        cur.execute('DELETE FROM sensors WHERE sensor_id = %s', (sensor_id,))
        # Remove Mosquitto credentials
        remove_mosquitto_credentials(sensor_id)
        app.logger.info(f"Cleaned up stale sensor: {sensor_id}")
    
    conn.commit()
    cur.close()
    conn.close()
    
    return len(stale_sensors)


# =============================================================================
# Error Handlers
# =============================================================================

@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': str(e.description)}), 400


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': str(e.description)}), 404


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Maximum 10 sensor registrations per hour per IP'
    }), 429


@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500


@app.errorhandler(503)
def service_unavailable(e):
    return jsonify({'error': str(e.description)}), 503


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=os.getenv('DEBUG', 'false').lower() == 'true')
