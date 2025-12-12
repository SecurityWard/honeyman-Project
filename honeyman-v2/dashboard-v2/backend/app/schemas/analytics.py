"""
Pydantic schemas for Analytics API
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from datetime import datetime


class OverviewStats(BaseModel):
    """Schema for dashboard overview statistics"""
    total_sensors: int
    active_sensors: int
    online_sensors: int
    total_threats: int
    threats_last_24h: int
    threats_last_7d: int
    critical_threats: int
    high_threats: int
    threat_velocity: float  # threats per hour
    avg_threat_score: Optional[float]


class SeverityDistribution(BaseModel):
    """Schema for severity distribution"""
    critical: int
    high: int
    medium: int
    low: int


class DetectorDistribution(BaseModel):
    """Schema for detector distribution"""
    usb: int
    wifi: int
    ble: int
    network: int
    airdrop: int


class ThreatTrend(BaseModel):
    """Schema for threat trends over time"""
    period: str  # hourly, daily, weekly
    data_points: List[Dict[str, any]]
    # [
    #   {"timestamp": "2025-11-30T12:00:00Z", "count": 45, "severity": {...}},
    #   ...
    # ]


class TopThreatType(BaseModel):
    """Schema for top threat types"""
    threat_type: str
    count: int
    percentage: float
    severity: str


class TopSensor(BaseModel):
    """Schema for top sensors by threat count"""
    sensor_id: str
    sensor_name: str
    threat_count: int
    city: Optional[str]
    country: Optional[str]


class GeographicDistribution(BaseModel):
    """Schema for geographic threat distribution"""
    country: str
    threat_count: int
    sensors_count: int
    coordinates: Dict[str, float]  # {"lat": 37.7749, "lon": -122.4194}


class MitreAttackCoverage(BaseModel):
    """Schema for MITRE ATT&CK coverage"""
    tactic: str
    tactic_name: str
    technique_count: int
    threat_count: int
    techniques: List[Dict[str, any]]
    # [
    #   {"id": "T1200", "name": "Hardware Additions", "count": 15},
    #   ...
    # ]


class ThreatVelocity(BaseModel):
    """Schema for threat velocity metrics"""
    current_rate: float  # threats per hour
    avg_rate_24h: float
    avg_rate_7d: float
    peak_rate: float
    peak_timestamp: Optional[datetime]
    trend: str  # "increasing", "decreasing", "stable"


class AnalyticsQuery(BaseModel):
    """Schema for analytics query parameters"""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    sensor_ids: Optional[List[str]] = None
    detector_types: Optional[List[str]] = None
    granularity: str = Field(default="hourly", pattern="^(hourly|daily|weekly)$")
