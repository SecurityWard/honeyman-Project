"""Sensor self-register endpoint.

POST /sensors/register accepts a self-selected name and hardware capabilities,
assigns a unique sensor_id (with a random suffix), and returns a one-time API
key the sensor uses for all subsequent writes.
"""

from datetime import datetime
import secrets
import re

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.api_key import generate_api_key, hash_api_key
from ..core.config import settings
from ..db.base import get_db
from ..models.sensor import Sensor
from ..schemas.onboarding import SensorRegistration, SensorRegistrationResponse

router = APIRouter()

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$")


def _normalize_name(raw: str) -> str:
    """Slug-style name: lowercase alphanumeric + hyphens."""
    cleaned = raw.strip().lower()
    cleaned = re.sub(r"[^a-z0-9-]+", "-", cleaned).strip("-")
    return cleaned[:60] or "sensor"


def _make_unique_sensor_id(base: str) -> str:
    """Append a 4-char random suffix; e.g. 'defcon-hotel' -> 'defcon-hotel-7x9k'."""
    suffix = secrets.token_hex(2)  # 4 hex chars
    return f"{base}-{suffix}"


@router.post(
    "/sensors/register",
    response_model=SensorRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_sensor(
    registration: SensorRegistration,
    db: AsyncSession = Depends(get_db),
) -> SensorRegistrationResponse:
    """
    Self-register a new sensor. Returns a one-time plaintext API key.

    The install script captures the api_key from this response and writes
    it to /etc/honeyman/credentials. The plaintext is never retrievable
    again — only its SHA256 hash is stored.
    """

    base_name = _normalize_name(registration.requested_name)
    if not NAME_RE.match(base_name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid sensor name. Use lowercase letters, digits, and hyphens.",
        )

    # Try a few times in the (vanishingly rare) event of a suffix collision
    for _ in range(5):
        candidate_id = _make_unique_sensor_id(base_name)
        existing = await db.execute(
            select(Sensor.id).where(Sensor.sensor_id == candidate_id)
        )
        if existing.scalar_one_or_none() is None:
            sensor_id = candidate_id
            break
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not allocate a unique sensor_id. Try again.",
        )

    api_key = generate_api_key()

    sensor = Sensor(
        sensor_id=sensor_id,
        name=base_name,
        description=registration.location_label,
        is_active=True,
        is_online=False,
        enabled_detectors=registration.enabled_detectors,
        capabilities=registration.capabilities,
        platform=registration.platform,
        architecture=registration.architecture,
        agent_version=registration.agent_version,
        python_version=registration.python_version,
        api_key_hash=hash_api_key(api_key),
        transport_protocol="https",
    )

    if registration.initial_location:
        loc = registration.initial_location
        sensor.latitude = loc.get("latitude")
        sensor.longitude = loc.get("longitude")
        sensor.location_method = loc.get("method", "manual")
        sensor.location_accuracy = loc.get("accuracy")

    db.add(sensor)
    await db.commit()
    await db.refresh(sensor)

    api_endpoint = f"{settings.PUBLIC_API_BASE_URL}{settings.API_PREFIX}"

    response = SensorRegistrationResponse(
        sensor_id=sensor_id,
        api_key=api_key,  # plaintext, returned exactly once
        api_endpoint=api_endpoint,
        mqtt_enabled=settings.MQTT_OFFERED,
        registered_at=sensor.registered_at,
    )

    if settings.MQTT_OFFERED:
        response.mqtt_broker = settings.MQTT_BROKER_HOST
        response.mqtt_port = settings.MQTT_BROKER_PORT
        response.mqtt_topic_threats = f"honeyman/sensors/{sensor_id}/threats"
        response.mqtt_topic_heartbeat = f"honeyman/sensors/{sensor_id}/heartbeat"

    return response
