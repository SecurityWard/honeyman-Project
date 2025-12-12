"""
Onboarding API endpoints - sensor registration
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta
import secrets

from ..db.base import get_db
from ..models.sensor import Sensor
from ..models.user import User
from ..schemas.onboarding import (
    OnboardingTokenCreate, OnboardingTokenResponse,
    SensorRegistration, SensorRegistrationResponse
)
from ..core.security import generate_onboarding_token, verify_onboarding_token, get_password_hash
from ..core.config import settings
from .deps import require_admin

router = APIRouter()


@router.post("/onboarding/tokens", response_model=OnboardingTokenResponse)
async def create_onboarding_token(
    token_request: OnboardingTokenCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Generate a one-time onboarding token for sensor registration (admin only)"""

    # Generate token
    token = generate_onboarding_token(
        sensor_name=token_request.sensor_name,
        validity_hours=token_request.validity_hours
    )

    expires_at = datetime.utcnow() + timedelta(hours=token_request.validity_hours)

    # Generate QR code URL
    qr_code_url = f"{settings.API_PREFIX}/onboarding/qrcode/{token}"

    return OnboardingTokenResponse(
        token=token,
        sensor_name=token_request.sensor_name,
        expires_at=expires_at,
        qr_code_url=qr_code_url
    )


@router.post("/onboarding/register", response_model=SensorRegistrationResponse)
async def register_sensor(
    registration: SensorRegistration,
    db: AsyncSession = Depends(get_db)
):
    """Register a new sensor using onboarding token"""

    # Verify onboarding token
    sensor_name = verify_onboarding_token(registration.onboarding_token)

    if not sensor_name:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired onboarding token"
        )

    # Check if sensor_id already exists
    result = await db.execute(
        select(Sensor).where(Sensor.sensor_id == registration.sensor_id)
    )
    existing_sensor = result.scalar_one_or_none()

    if existing_sensor:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Sensor {registration.sensor_id} already registered"
        )

    # Generate MQTT credentials
    mqtt_username = f"sensor_{registration.sensor_id}"
    mqtt_password = secrets.token_urlsafe(32)
    mqtt_password_hash = get_password_hash(mqtt_password)

    # Create sensor
    sensor = Sensor(
        sensor_id=registration.sensor_id,
        name=sensor_name,
        is_active=True,
        is_online=False,
        enabled_detectors=list(registration.capabilities.keys()),
        capabilities=registration.capabilities,
        platform=registration.platform,
        architecture=registration.architecture,
        agent_version=registration.agent_version,
        python_version=registration.python_version,
        mqtt_username=mqtt_username,
        mqtt_password_hash=mqtt_password_hash
    )

    # Set location if provided
    if registration.location:
        sensor.latitude = registration.location.get('latitude')
        sensor.longitude = registration.location.get('longitude')
        sensor.location_method = registration.location.get('method', 'unknown')
        sensor.location_accuracy = registration.location.get('accuracy')

    db.add(sensor)
    await db.commit()
    await db.refresh(sensor)

    # Return credentials and connection info
    return SensorRegistrationResponse(
        sensor_id=registration.sensor_id,
        mqtt_broker=settings.MQTT_BROKER_HOST,
        mqtt_port=settings.MQTT_BROKER_PORT,
        mqtt_username=mqtt_username,
        mqtt_password=mqtt_password,  # Plain password only returned once!
        mqtt_use_tls=settings.MQTT_USE_TLS,
        mqtt_topics={
            "threats": f"honeyman/sensors/{registration.sensor_id}/threats",
            "heartbeat": f"honeyman/sensors/{registration.sensor_id}/heartbeat",
            "control": f"honeyman/control/{registration.sensor_id}"
        },
        api_endpoint=f"https://api.honeyman.io{settings.API_PREFIX}",
        fallback_http_url=f"https://api.honeyman.io{settings.API_PREFIX}/threats"
    )


@router.get("/onboarding/qrcode/{token}")
async def get_qr_code(token: str):
    """Get QR code image for onboarding token"""

    # Verify token is valid
    sensor_name = verify_onboarding_token(token)

    if not sensor_name:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid or expired token"
        )

    # In production, generate actual QR code image
    # For now, return the registration URL
    registration_url = f"https://dashboard.honeyman.io/onboard?token={token}"

    return {
        "token": token,
        "sensor_name": sensor_name,
        "registration_url": registration_url,
        "note": "In production, this would return a QR code image"
    }
