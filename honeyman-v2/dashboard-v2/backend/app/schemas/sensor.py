"""
Pydantic schemas for Sensor API
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID


class SensorBase(BaseModel):
    """Base sensor schema"""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=500)
    latitude: Optional[float] = Field(None, ge=-90, le=90)
    longitude: Optional[float] = Field(None, ge=-180, le=180)
    city: Optional[str] = Field(None, max_length=100)
    country: Optional[str] = Field(None, max_length=100)


class SensorCreate(SensorBase):
    """Schema for creating a sensor"""
    sensor_id: str = Field(..., min_length=1, max_length=100)
    enabled_detectors: List[str] = Field(default_factory=list)
    capabilities: Dict[str, bool] = Field(default_factory=dict)
    platform: Optional[str] = None
    architecture: Optional[str] = None
    agent_version: Optional[str] = None


class SensorUpdate(BaseModel):
    """Schema for updating a sensor"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=500)
    is_active: Optional[bool] = None
    latitude: Optional[float] = Field(None, ge=-90, le=90)
    longitude: Optional[float] = Field(None, ge=-180, le=180)
    city: Optional[str] = None
    country: Optional[str] = None
    enabled_detectors: Optional[List[str]] = None


class SensorResponse(SensorBase):
    """Schema for sensor response"""
    id: UUID
    sensor_id: str
    is_active: bool
    is_online: bool
    last_heartbeat: Optional[datetime]
    location_method: Optional[str]
    location_accuracy: Optional[float]
    enabled_detectors: List[str]
    transport_protocol: str
    capabilities: Dict[str, Any]
    platform: Optional[str]
    architecture: Optional[str]
    agent_version: Optional[str]
    python_version: Optional[str]
    total_threats_detected: int
    threats_last_24h: int
    created_at: datetime
    updated_at: Optional[datetime]
    registered_at: datetime

    class Config:
        from_attributes = True


class SensorListResponse(BaseModel):
    """Schema for sensor list response"""
    sensors: List[SensorResponse]
    total: int
    page: int
    page_size: int


class SensorStats(BaseModel):
    """Schema for sensor statistics"""
    sensor_id: str
    total_threats: int
    threats_last_24h: int
    threats_last_7d: int
    threats_by_severity: Dict[str, int]
    threats_by_detector: Dict[str, int]
    most_common_threat_type: Optional[str]
    last_threat_timestamp: Optional[datetime]


class SensorHeartbeat(BaseModel):
    """Schema for sensor heartbeat"""
    sensor_id: str
    timestamp: datetime
    is_online: bool
    enabled_detectors: List[str]
    system_info: Optional[Dict[str, Any]] = None
    location: Optional[Dict[str, Any]] = None
