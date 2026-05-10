"""
Sensor API endpoints — V2.

Reads (list, get, stats) are public.
Writes (heartbeat) require the sensor's API key.
There are no admin update/delete endpoints; operators manage sensors via SSH.
"""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.base import get_db
from ..models.sensor import Sensor
from ..models.threat import Threat
from ..schemas.sensor import (
    SensorHeartbeat,
    SensorListResponse,
    SensorResponse,
    SensorStats,
)
from .deps import authenticated_sensor

router = APIRouter()


@router.get("/sensors", response_model=SensorListResponse)
async def list_sensors(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    is_active: Optional[bool] = None,
    is_online: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
):
    """List all sensors. Public read."""

    query = select(Sensor)
    if is_active is not None:
        query = query.where(Sensor.is_active == is_active)
    if is_online is not None:
        query = query.where(Sensor.is_online == is_online)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    query = query.offset((page - 1) * page_size).limit(page_size)
    query = query.order_by(Sensor.created_at.desc())
    sensors = (await db.execute(query)).scalars().all()

    return SensorListResponse(
        sensors=[SensorResponse.from_orm(s) for s in sensors],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/sensors/{sensor_id}", response_model=SensorResponse)
async def get_sensor(sensor_id: str, db: AsyncSession = Depends(get_db)):
    """Get sensor by ID. Public read."""
    result = await db.execute(select(Sensor).where(Sensor.sensor_id == sensor_id))
    sensor = result.scalar_one_or_none()
    if not sensor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sensor {sensor_id} not found",
        )
    return SensorResponse.from_orm(sensor)


@router.get("/sensors/{sensor_id}/stats", response_model=SensorStats)
async def get_sensor_stats(sensor_id: str, db: AsyncSession = Depends(get_db)):
    """Get sensor statistics. Public read."""

    sensor_result = await db.execute(select(Sensor).where(Sensor.sensor_id == sensor_id))
    sensor = sensor_result.scalar_one_or_none()
    if not sensor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sensor {sensor_id} not found",
        )

    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    total_threats = (
        await db.execute(select(func.count()).where(Threat.sensor_id == sensor_id))
    ).scalar()

    threats_24h = (
        await db.execute(
            select(func.count()).where(
                and_(Threat.sensor_id == sensor_id, Threat.timestamp >= last_24h)
            )
        )
    ).scalar()

    threats_7d = (
        await db.execute(
            select(func.count()).where(
                and_(Threat.sensor_id == sensor_id, Threat.timestamp >= last_7d)
            )
        )
    ).scalar()

    severity_rows = await db.execute(
        select(Threat.severity, func.count())
        .where(Threat.sensor_id == sensor_id)
        .group_by(Threat.severity)
    )
    threats_by_severity = {row[0]: row[1] for row in severity_rows}

    detector_rows = await db.execute(
        select(Threat.detector_type, func.count())
        .where(Threat.sensor_id == sensor_id)
        .group_by(Threat.detector_type)
    )
    threats_by_detector = {row[0]: row[1] for row in detector_rows}

    most_common_row = (
        await db.execute(
            select(Threat.threat_type, func.count().label("count"))
            .where(Threat.sensor_id == sensor_id)
            .group_by(Threat.threat_type)
            .order_by(func.count().desc())
            .limit(1)
        )
    ).first()
    most_common_threat_type = most_common_row[0] if most_common_row else None

    last_threat = (
        await db.execute(
            select(Threat.timestamp)
            .where(Threat.sensor_id == sensor_id)
            .order_by(Threat.timestamp.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    return SensorStats(
        sensor_id=sensor_id,
        total_threats=total_threats,
        threats_last_24h=threats_24h,
        threats_last_7d=threats_7d,
        threats_by_severity=threats_by_severity,
        threats_by_detector=threats_by_detector,
        most_common_threat_type=most_common_threat_type,
        last_threat_timestamp=last_threat,
    )


@router.post("/sensors/{sensor_id}/heartbeat")
async def sensor_heartbeat(
    sensor_id: str,
    heartbeat: SensorHeartbeat,
    db: AsyncSession = Depends(get_db),
    sensor: Sensor = Depends(authenticated_sensor),
):
    """
    Receive sensor heartbeat. Requires API key.

    The dependency `authenticated_sensor` resolves the calling sensor from the
    Authorization header and verifies that the key belongs to {sensor_id}.
    """
    # `authenticated_sensor` already verified key ownership via path param.
    # We re-attach to the session here so the update flushes.
    sensor.last_heartbeat = heartbeat.timestamp
    sensor.is_online = heartbeat.is_online

    if heartbeat.enabled_detectors:
        sensor.enabled_detectors = heartbeat.enabled_detectors

    if heartbeat.location:
        sensor.latitude = heartbeat.location.get("latitude")
        sensor.longitude = heartbeat.location.get("longitude")
        sensor.location_method = heartbeat.location.get("method")
        sensor.location_accuracy = heartbeat.location.get("accuracy")
        if heartbeat.location.get("city"):
            sensor.city = heartbeat.location["city"]
        if heartbeat.location.get("country"):
            sensor.country = heartbeat.location["country"]

    await db.commit()
    return {"message": "Heartbeat received"}
