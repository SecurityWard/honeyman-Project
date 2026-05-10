"""Initial schema with TimescaleDB hypertable — V2 (no users)

Revision ID: 001
Revises:
Create Date: 2026-05-09

V2 migration:
- No users table (public dashboard, no accounts)
- Sensors authenticate writes via per-sensor API key (api_key_hash column)
- Threats hypertable with TimescaleDB compression + 90d retention
- No is_acknowledged columns (no actions in V2)
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Enable TimescaleDB extension
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")

    # Sensors table
    op.create_table(
        'sensors',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('sensor_id', sa.String(100), unique=True, nullable=False, index=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.String(500), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_online', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('last_heartbeat', sa.DateTime(timezone=True), nullable=True),

        # Location
        sa.Column('latitude', sa.Float(), nullable=True),
        sa.Column('longitude', sa.Float(), nullable=True),
        sa.Column('location_method', sa.String(20), nullable=True),
        sa.Column('location_accuracy', sa.Float(), nullable=True),
        sa.Column('city', sa.String(100), nullable=True),
        sa.Column('country', sa.String(100), nullable=True),

        # Configuration
        sa.Column('enabled_detectors', postgresql.JSON(), nullable=False, server_default='[]'),
        sa.Column('transport_protocol', sa.String(20), nullable=False, server_default='https'),
        sa.Column('capabilities', postgresql.JSON(), nullable=False, server_default='{}'),
        sa.Column('platform', sa.String(50), nullable=True),
        sa.Column('architecture', sa.String(20), nullable=True),
        sa.Column('agent_version', sa.String(20), nullable=True),
        sa.Column('python_version', sa.String(20), nullable=True),

        # Stats
        sa.Column('total_threats_detected', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('threats_last_24h', sa.Integer(), nullable=False, server_default='0'),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now(), nullable=True),
        sa.Column('registered_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),

        # V2: per-sensor API key (SHA256 hex digest, 64 chars)
        sa.Column('api_key_hash', sa.String(64), nullable=False, index=True),
    )

    # Threats table (then converted to hypertable below)
    op.create_table(
        'threats',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('sensor_id', sa.String(100), sa.ForeignKey('sensors.sensor_id'), nullable=False, index=True),
        sa.Column('threat_type', sa.String(100), nullable=False, index=True),
        sa.Column('detector_type', sa.String(20), nullable=False, index=True),
        sa.Column('severity', sa.String(20), nullable=False, index=True),
        sa.Column('device_name', sa.String(255), nullable=True),
        sa.Column('device_mac', sa.String(50), nullable=True, index=True),
        sa.Column('device_ip', sa.String(50), nullable=True),
        sa.Column('src_host', sa.String(100), nullable=True),
        sa.Column('src_port', sa.Integer(), nullable=True),
        sa.Column('dst_host', sa.String(100), nullable=True),
        sa.Column('dst_port', sa.Integer(), nullable=True),
        sa.Column('latitude', sa.Float(), nullable=True),
        sa.Column('longitude', sa.Float(), nullable=True),
        sa.Column('city', sa.String(100), nullable=True),
        sa.Column('country', sa.String(100), nullable=True),
        sa.Column('matched_rules', postgresql.JSON(), nullable=False, server_default='[]'),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('threat_score', sa.Float(), nullable=True),
        sa.Column('raw_event', postgresql.JSON(), nullable=True),
        sa.Column('mitre_tactics', postgresql.JSON(), nullable=True, server_default='[]'),
        sa.Column('mitre_techniques', postgresql.JSON(), nullable=True, server_default='[]'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Threats indexes
    op.create_index('idx_threats_time_sensor', 'threats', ['timestamp', 'sensor_id'])
    op.create_index('idx_threats_type_severity', 'threats', ['threat_type', 'severity'])
    op.create_index('idx_threats_detector', 'threats', ['detector_type', 'timestamp'])
    op.create_index('idx_threats_location', 'threats', ['latitude', 'longitude'])

    # Convert threats to TimescaleDB hypertable
    op.execute("""
        SELECT create_hypertable('threats', 'timestamp',
            chunk_time_interval => INTERVAL '1 day',
            if_not_exists => TRUE
        );
    """)

    # Compression — chunks older than 7 days
    op.execute("""
        ALTER TABLE threats SET (
            timescaledb.compress,
            timescaledb.compress_segmentby = 'sensor_id,detector_type'
        );
    """)
    op.execute("""
        SELECT add_compression_policy('threats', INTERVAL '7 days', if_not_exists => TRUE);
    """)

    # Retention — drop chunks older than 90 days
    op.execute("""
        SELECT add_retention_policy('threats', INTERVAL '90 days', if_not_exists => TRUE);
    """)

    # Hourly continuous aggregate for dashboard analytics
    op.execute("""
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
        GROUP BY bucket, sensor_id, detector_type, severity
        WITH NO DATA;
    """)

    op.execute("""
        SELECT add_continuous_aggregate_policy('threat_stats_hourly',
            start_offset => INTERVAL '3 hours',
            end_offset => INTERVAL '1 hour',
            schedule_interval => INTERVAL '1 hour',
            if_not_exists => TRUE
        );
    """)


def downgrade() -> None:
    op.execute("DROP MATERIALIZED VIEW IF EXISTS threat_stats_hourly CASCADE;")
    op.drop_table('threats')
    op.drop_table('sensors')
    # TimescaleDB extension is intentionally not dropped.
