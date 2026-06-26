"""
Analytics response schemas
"""

from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class OverviewStats(BaseModel):
    total_sensors: int
    active_sensors: int
    online_sensors: int
    total_threats: int
    threats_last_24h: int
    threats_last_7d: int
    critical_threats: int
    high_threats: int
    threat_velocity: float
    avg_threat_score: Optional[float]


class ThreatTrend(BaseModel):
    timestamp: str
    count: int
    critical: int
    high: int
    medium: int
    low: int


class TopThreatType(BaseModel):
    threat_type: str
    count: int
    percentage: float
    severity: str


class TopSensor(BaseModel):
    sensor_id: str
    sensor_name: str
    threat_count: int
    city: Optional[str] = None
    country: Optional[str] = None


class GeographicDistribution(BaseModel):
    sensor_id: str
    latitude: float
    longitude: float
    city: Optional[str]
    country: Optional[str]
    threat_count: int
    severity_breakdown: dict


class MitreAttackCoverage(BaseModel):
    tactic: str
    technique_count: int
    threat_count: int


class ThreatVelocity(BaseModel):
    current_rate: float
    avg_rate_24h: float
    avg_rate_7d: float
    peak_rate: int
    peak_timestamp: Optional[datetime]
    trend: str
