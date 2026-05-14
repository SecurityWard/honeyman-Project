"""
Threat database model (TimescaleDB hypertable)
"""

from sqlalchemy import Column, String, DateTime, Float, JSON, Integer, ForeignKey, Index, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
from ..db.base import Base


class Threat(Base):
    """Threat model - TimescaleDB hypertable for time-series threat data"""

    __tablename__ = "threats"

    # Composite primary key (id, timestamp). TimescaleDB requires the
    # partitioning column (`timestamp`) to be part of any unique/PK index
    # on a hypertable, so the SQLAlchemy metadata must mirror that.
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Time dimension (critical for TimescaleDB) - also part of the PK
    timestamp = Column(DateTime(timezone=True), primary_key=True, nullable=False, index=True)

    # Sensor reference
    sensor_id = Column(String(100), ForeignKey("sensors.sensor_id"), nullable=False, index=True)

    # Threat classification
    threat_type = Column(String(100), nullable=False, index=True)
    # usb_rubber_ducky, wifi_evil_twin, ble_spam, ssh_brute_force, etc.

    detector_type = Column(String(20), nullable=False, index=True)
    # usb, wifi, ble, network, airdrop

    severity = Column(String(20), nullable=False, index=True)
    # critical, high, medium, low

    # Threat details
    device_name = Column(String(255), nullable=True)
    device_mac = Column(String(50), nullable=True, index=True)
    device_ip = Column(String(50), nullable=True)

    # Network-specific
    src_host = Column(String(100), nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_host = Column(String(100), nullable=True)
    dst_port = Column(Integer, nullable=True)

    # Location (denormalized for performance)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    city = Column(String(100), nullable=True)
    country = Column(String(100), nullable=True)
    # Phase D: accuracy + how the sensor derived the coordinates.
    # location_method in {'gps','wifi','ip','manual'}; accuracy_meters in metres.
    accuracy_meters = Column(Float, nullable=True)
    location_method = Column(String(20), nullable=True)

    # Detection metadata
    matched_rules = Column(JSON, default=list, nullable=False)
    # [
    #   {"rule_id": "usb_rubber_ducky_001", "name": "...", "confidence": 0.95},
    #   ...
    # ]

    confidence = Column(Float, nullable=True)
    threat_score = Column(Float, nullable=True)  # 0.0 - 1.0

    # Raw event data
    raw_event = Column(JSON, nullable=True)

    # MITRE ATT&CK mapping
    mitre_tactics = Column(JSON, default=list, nullable=True)
    mitre_techniques = Column(JSON, default=list, nullable=True)

    # V2: no acknowledge/dismiss fields. The dashboard is view-only.

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Indexes for common queries
    __table_args__ = (
        Index('idx_threats_time_sensor', 'timestamp', 'sensor_id'),
        Index('idx_threats_type_severity', 'threat_type', 'severity'),
        Index('idx_threats_detector', 'detector_type', 'timestamp'),
        Index('idx_threats_location', 'latitude', 'longitude'),
    )

    def __repr__(self):
        return f"<Threat {self.threat_type} from {self.sensor_id} at {self.timestamp}>"


# TimescaleDB hypertable creation SQL (executed in migration)
CREATE_HYPERTABLE_SQL = text("""
    SELECT create_hypertable('threats', 'timestamp',
        chunk_time_interval => INTERVAL '1 day',
        if_not_exists => TRUE
    );
""")

# Compression policy (compress chunks older than 7 days)
CREATE_COMPRESSION_POLICY_SQL = text("""
    ALTER TABLE threats SET (
        timescaledb.compress,
        timescaledb.compress_segmentby = 'sensor_id,detector_type'
    );

    SELECT add_compression_policy('threats', INTERVAL '7 days', if_not_exists => TRUE);
""")

# Retention policy (drop chunks older than 90 days)
CREATE_RETENTION_POLICY_SQL = text("""
    SELECT add_retention_policy('threats', INTERVAL '90 days', if_not_exists => TRUE);
""")
