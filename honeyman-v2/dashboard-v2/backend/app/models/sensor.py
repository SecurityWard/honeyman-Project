"""
Sensor database model
"""

from sqlalchemy import Column, String, Boolean, DateTime, Float, JSON, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
from ..db.base import Base


class Sensor(Base):
    """Sensor model - represents a deployed Honeyman sensor"""

    __tablename__ = "sensors"

    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Sensor identification
    sensor_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(String(500), nullable=True)

    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    is_online = Column(Boolean, default=False, nullable=False)
    last_heartbeat = Column(DateTime(timezone=True), nullable=True)

    # Location
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    location_method = Column(String(20), nullable=True)  # gps, wifi, ip, static
    location_accuracy = Column(Float, nullable=True)
    city = Column(String(100), nullable=True)
    country = Column(String(100), nullable=True)

    # Configuration
    enabled_detectors = Column(JSON, default=list, nullable=False)
    transport_protocol = Column(String(20), default="mqtt", nullable=False)

    # Capabilities
    capabilities = Column(JSON, default=dict, nullable=False)
    # {
    #   "usb": true,
    #   "wifi": true,
    #   "ble": true,
    #   "network": true,
    #   "airdrop": false
    # }

    # System information
    platform = Column(String(50), nullable=True)  # linux, darwin, etc.
    architecture = Column(String(20), nullable=True)  # arm64, x86_64
    agent_version = Column(String(20), nullable=True)
    python_version = Column(String(20), nullable=True)

    # Statistics
    total_threats_detected = Column(Integer, default=0, nullable=False)
    threats_last_24h = Column(Integer, default=0, nullable=False)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), nullable=True)
    registered_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # MQTT credentials (encrypted)
    mqtt_username = Column(String(255), nullable=True)
    mqtt_password_hash = Column(String(255), nullable=True)

    def __repr__(self):
        return f"<Sensor {self.sensor_id} ({self.name})>"
