"""
API dependencies — V2 uses per-sensor API keys for writes; reads are public.
"""

from fastapi import Depends, HTTPException, Header, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..core.api_key import hash_api_key, extract_bearer_token
from ..db.base import get_db
from ..models.sensor import Sensor


async def authenticated_sensor(
    authorization: str | None = Header(default=None),
    sensor_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> Sensor:
    """
    Resolve the calling sensor from its Authorization: Bearer <api_key> header.

    If the path includes a `sensor_id` (e.g. /sensors/{sensor_id}/heartbeat),
    we additionally verify that the key belongs to that sensor — preventing
    one compromised sensor from impersonating another.

    Returns the Sensor row. Raises 401 on missing/invalid key, 403 on mismatch.
    """
    api_key = extract_bearer_token(authorization)
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected: Bearer <api_key>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    key_hash = hash_api_key(api_key)
    result = await db.execute(
        select(Sensor).where(Sensor.api_key_hash == key_hash)
    )
    sensor = result.scalar_one_or_none()

    if sensor is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    if not sensor.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sensor is deactivated",
        )

    # Path-bound sensor_id check (when present)
    if sensor_id is not None and sensor.sensor_id != sensor_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key does not belong to this sensor",
        )

    return sensor
