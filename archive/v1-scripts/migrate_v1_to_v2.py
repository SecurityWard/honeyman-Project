#!/usr/bin/env python3
"""
Migrate threat data from Honeyman V1 (in-memory) to V2 (PostgreSQL)
"""

import json
import sys
import asyncio
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import requests

# V2 Database configuration
DATABASE_URL = "postgresql://honeyman:honeyman_secure_123@localhost/honeyman_v2"

# V1 API endpoint
V1_API_URL = "http://localhost:8080/api/threats/recent?limit=500"

def fetch_v1_threats():
    """Fetch all threats from V1 API"""
    print("Fetching threats from V1 API...")
    response = requests.get(V1_API_URL)
    response.raise_for_status()
    data = response.json()
    threats = data.get('threats', [])
    print(f"Found {len(threats)} threats in V1")
    return threats

def map_severity(risk_level):
    """Map V1 risk_level to V2 severity"""
    mapping = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info'
    }
    return mapping.get(risk_level.lower(), 'medium')

def map_detector_type(source):
    """Map V1 source to V2 detector_type"""
    if 'wifi' in source.lower():
        return 'wifi'
    elif 'ble' in source.lower() or 'bluetooth' in source.lower():
        return 'bluetooth'
    elif 'usb' in source.lower():
        return 'usb'
    elif 'airdrop' in source.lower():
        return 'airdrop'
    elif 'network' in source.lower():
        return 'network'
    else:
        return 'unknown'

def parse_timestamp(ts_str):
    """Parse V1 timestamp to datetime"""
    try:
        # Try ISO format
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except:
        try:
            # Try other common formats
            return datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S.%f')
        except:
            # Default to now if parsing fails
            return datetime.utcnow()

def transform_threat(v1_threat):
    """Transform V1 threat to V2 format"""
    # Extract network info for location (if available)
    network_info = v1_threat.get('network_info', {})

    # Determine threat type from threats_detected
    threats_detected = v1_threat.get('threats_detected', [])
    threat_type = threats_detected[0] if threats_detected else v1_threat.get('detection_type', 'unknown')

    # Build metadata
    metadata = {
        'v1_id': v1_threat.get('id'),
        'log_type': v1_threat.get('log_type'),
        'threat_score': v1_threat.get('threat_score'),
        'message': v1_threat.get('message'),
        'threats_detected': threats_detected,
        'network_info': network_info,
        'device_info': v1_threat.get('device_info', {}),
        'service_info': v1_threat.get('service_info', {}),
        'attack_info': v1_threat.get('attack_info', {})
    }

    v2_threat = {
        'timestamp': parse_timestamp(v1_threat.get('timestamp')),
        'sensor_id': 'honeyman-01',  # V1 sensor ID
        'detector_type': map_detector_type(v1_threat.get('source', '')),
        'threat_type': threat_type,
        'severity': map_severity(v1_threat.get('risk_level', 'medium')),
        'confidence_score': v1_threat.get('threat_score', 0.5),
        'device_identifier': network_info.get('bssid') or network_info.get('mac_address'),
        'device_name': network_info.get('ssid') or network_info.get('device_name'),
        'manufacturer': None,  # V1 doesn't track this
        'ssid': network_info.get('ssid'),
        'mac_address': network_info.get('bssid') or network_info.get('mac_address'),
        'ip_address': network_info.get('ip_address'),
        'latitude': None,  # V1 doesn't have location data
        'longitude': None,
        'metadata': json.dumps(metadata),
        'acknowledged': False
    }

    return v2_threat

def insert_threats_sql(threats):
    """Generate SQL INSERT statements"""
    print(f"Generating SQL for {len(threats)} threats...")

    sql_statements = []
    sql_statements.append("-- Honeyman V1 to V2 Migration")
    sql_statements.append("-- Generated: " + datetime.utcnow().isoformat())
    sql_statements.append("")

    # First, ensure sensor exists
    sql_statements.append("-- Ensure V1 sensor exists")
    sql_statements.append("""
INSERT INTO sensors (
    sensor_id, name, is_active, is_online,
    enabled_detectors, capabilities, platform,
    created_at, updated_at
) VALUES (
    'honeyman-01',
    'Honeyman V1 Sensor',
    false,
    false,
    ARRAY['wifi', 'bluetooth', 'usb', 'network'],
    '{"wifi": true, "bluetooth": true, "usb": true, "network": true}'::jsonb,
    'Legacy V1',
    NOW(),
    NOW()
) ON CONFLICT (sensor_id) DO NOTHING;
""")

    sql_statements.append("-- Insert threats")
    sql_statements.append("BEGIN;")

    for threat in threats:
        v2_threat = transform_threat(threat)

        # Escape single quotes in strings
        def escape_sql(val):
            if val is None:
                return 'NULL'
            elif isinstance(val, str):
                return f"'{val.replace(chr(39), chr(39)+chr(39))}'"  # Escape single quotes
            elif isinstance(val, (int, float)):
                return str(val)
            elif isinstance(val, datetime):
                return f"'{val.isoformat()}'"
            elif isinstance(val, bool):
                return 'true' if val else 'false'
            else:
                return f"'{str(val)}'"

        sql = f"""
INSERT INTO threats (
    timestamp, sensor_id, detector_type, threat_type, severity,
    confidence_score, device_identifier, device_name, ssid, mac_address,
    ip_address, latitude, longitude, metadata, acknowledged
) VALUES (
    {escape_sql(v2_threat['timestamp'])},
    {escape_sql(v2_threat['sensor_id'])},
    {escape_sql(v2_threat['detector_type'])},
    {escape_sql(v2_threat['threat_type'])},
    {escape_sql(v2_threat['severity'])},
    {v2_threat['confidence_score']},
    {escape_sql(v2_threat['device_identifier'])},
    {escape_sql(v2_threat['device_name'])},
    {escape_sql(v2_threat['ssid'])},
    {escape_sql(v2_threat['mac_address'])},
    {escape_sql(v2_threat['ip_address'])},
    {escape_sql(v2_threat['latitude'])},
    {escape_sql(v2_threat['longitude'])},
    {escape_sql(v2_threat['metadata'])},
    {escape_sql(v2_threat['acknowledged'])}
);"""
        sql_statements.append(sql)

    sql_statements.append("COMMIT;")
    sql_statements.append("")
    sql_statements.append(f"-- Migrated {len(threats)} threats from V1 to V2")

    return '\n'.join(sql_statements)

def main():
    try:
        # Fetch V1 threats
        v1_threats = fetch_v1_threats()

        if not v1_threats:
            print("No threats found in V1")
            return

        # Generate SQL
        sql_script = insert_threats_sql(v1_threats)

        # Save to file
        output_file = '/tmp/v1_to_v2_migration.sql'
        with open(output_file, 'w') as f:
            f.write(sql_script)

        print(f"\nSQL migration script saved to: {output_file}")
        print(f"Total threats to migrate: {len(v1_threats)}")
        print("\nTo apply the migration, run:")
        print(f"  sudo -u postgres psql -d honeyman_v2 < {output_file}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
