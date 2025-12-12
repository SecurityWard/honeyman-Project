"""
Pydantic schemas for Onboarding API
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, List
from datetime import datetime


class OnboardingTokenCreate(BaseModel):
    """Schema for creating onboarding token"""
    sensor_name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    validity_hours: int = Field(default=24, ge=1, le=168)  # Max 7 days


class OnboardingTokenResponse(BaseModel):
    """Schema for onboarding token response"""
    token: str
    sensor_name: str
    expires_at: datetime
    qr_code_url: str  # URL to get QR code image


class SensorRegistration(BaseModel):
    """Schema for sensor registration"""
    onboarding_token: str
    sensor_id: str = Field(..., min_length=1, max_length=100)
    capabilities: Dict[str, bool]
    platform: str
    architecture: str
    agent_version: str
    python_version: str
    location: Optional[Dict[str, any]] = None
    # {
    #   "latitude": 37.7749,
    #   "longitude": -122.4194,
    #   "method": "gps",
    #   "accuracy": 10.5
    # }


class SensorRegistrationResponse(BaseModel):
    """Schema for successful sensor registration"""
    sensor_id: str
    mqtt_broker: str
    mqtt_port: int
    mqtt_username: str
    mqtt_password: str
    mqtt_use_tls: bool
    mqtt_topics: Dict[str, str]
    # {
    #   "threats": "honeyman/sensors/{sensor_id}/threats",
    #   "heartbeat": "honeyman/sensors/{sensor_id}/heartbeat",
    #   "control": "honeyman/control/{sensor_id}"
    # }
    api_endpoint: str
    fallback_http_url: str


class SensorProvisioningStatus(BaseModel):
    """Schema for provisioning status check"""
    sensor_id: str
    status: str  # "pending", "provisioned", "active", "failed"
    created_at: datetime
    provisioned_at: Optional[datetime]
    error: Optional[str] = None
