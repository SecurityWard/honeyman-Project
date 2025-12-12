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
    """Schema for creating a threat"""
    device_name: Optional[str] = None
    device_mac: Optional[str] = None
    device_ip: Optional[str] = None
    src_host: Optional[str] = None
    src_port: Optional[int] = None
    dst_host: Optional[str] = None
    dst_port: Optional[int] = None
    latitude: Optional[float] = Field(None, ge=-90, le=90)
    longitude: Optional[float] = Field(None, ge=-180, le=180)
    city: Optional[str] = None
    country: Optional[str] = None
    matched_rules: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: Optional[float] = Field(None, ge=0, le=1)
    threat_score: Optional[float] = Field(None, ge=0, le=1)
    raw_event: Optional[Dict[str, Any]] = None
    mitre_tactics: Optional[List[str]] = Field(default_factory=list)
    mitre_techniques: Optional[List[str]] = Field(default_factory=list)


class ThreatResponse(ThreatBase):
    """Schema for threat response"""
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
    matched_rules: List[Dict[str, Any]]
    confidence: Optional[float]
    threat_score: Optional[float]
    raw_event: Optional[Dict[str, Any]]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    is_acknowledged: bool
    acknowledged_at: Optional[datetime]
    acknowledged_by: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ThreatListResponse(BaseModel):
    """Schema for threat list response"""
    threats: List[ThreatResponse]
    total: int
    page: int
    page_size: int


class ThreatAcknowledge(BaseModel):
    """Schema for acknowledging a threat"""
    acknowledged_by: str = Field(..., min_length=1, max_length=100)
    notes: Optional[str] = None


class ThreatQuery(BaseModel):
    """Schema for threat query filters"""
    sensor_id: Optional[str] = None
    detector_type: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[List[str]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    is_acknowledged: Optional[bool] = None
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
