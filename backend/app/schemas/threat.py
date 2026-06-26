"""
Pydantic schemas for Threat API
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID


class ThreatBase(BaseModel):
    """Base threat schema"""
    timestamp: datetime
    sensor_id: str
    threat_type: str = Field(..., max_length=100)
    detector_type: str = Field(..., max_length=20)
    severity: str = Field(..., pattern="^(critical|high|medium|low)$")


class ThreatCreate(ThreatBase):
    """Schema for creating a threat.

    [Audit F5] Sizes on each collection field so a compromised sensor key
    can't push a payload large enough to spike backend memory or eat the
    Postgres jsonb byte limit.  Limits are generous for real detector
    output and tight enough to keep a worst-case request comfortably
    under nginx's 256k cap.
    """
    device_name: Optional[str] = Field(None, max_length=255)
    device_mac: Optional[str] = Field(None, max_length=64)
    device_ip: Optional[str] = Field(None, max_length=64)
    src_host: Optional[str] = Field(None, max_length=255)
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_host: Optional[str] = Field(None, max_length=255)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
    latitude: Optional[float] = Field(None, ge=-90, le=90)
    longitude: Optional[float] = Field(None, ge=-180, le=180)
    city: Optional[str] = Field(None, max_length=100)
    country: Optional[str] = Field(None, max_length=100)
    accuracy_meters: Optional[float] = Field(None, ge=0, le=1_000_000)
    location_method: Optional[str] = Field(None, max_length=20)
    matched_rules: List[Dict[str, Any]] = Field(default_factory=list, max_length=32)
    confidence: Optional[float] = Field(None, ge=0, le=1)
    threat_score: Optional[float] = Field(None, ge=0, le=1)
    raw_event: Optional[Dict[str, Any]] = None
    mitre_tactics: Optional[List[str]] = Field(default_factory=list, max_length=16)
    mitre_techniques: Optional[List[str]] = Field(default_factory=list, max_length=32)


class ThreatResponse(ThreatBase):
    """Schema for threat response."""
    id: UUID
    device_name: Optional[str]
    device_mac: Optional[str]
    device_ip: Optional[str]
    src_host: Optional[str]
    src_port: Optional[int]
    dst_host: Optional[str]
    dst_port: Optional[int]
    latitude: Optional[float]
    longitude: Optional[float]
    city: Optional[str]
    country: Optional[str]
    accuracy_meters: Optional[float]
    location_method: Optional[str]
    matched_rules: List[Dict[str, Any]]
    confidence: Optional[float]
    threat_score: Optional[float]
    raw_event: Optional[Dict[str, Any]]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ThreatListResponse(BaseModel):
    """Schema for threat list response"""
    items: List[ThreatResponse]
    total: int
    page: int
    page_size: int


class ThreatQuery(BaseModel):
    """Schema for threat query filters"""
    sensor_id: Optional[str] = None
    detector_type: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[List[str]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=1000)
    sort_by: str = Field(default="timestamp")
    sort_order: str = Field(default="desc", pattern="^(asc|desc)$")


class ThreatMapPoint(BaseModel):
    """Schema for map visualization"""
    latitude: float
    longitude: float
    threat_count: int
    severity_breakdown: Dict[str, int]
    sensor_id: str
    city: Optional[str]
    country: Optional[str]


class ThreatTimeSeries(BaseModel):
    """Schema for time-series data"""
    timestamp: datetime
    threat_count: int
    avg_threat_score: Optional[float]
    severity_breakdown: Dict[str, int]
