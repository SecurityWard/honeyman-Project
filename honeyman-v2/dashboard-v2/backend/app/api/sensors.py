"""
Sensor API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from typing import List, Optional
from uuid import UUID
from datetime import datetime, timedelta

from ..db.base import get_db
from ..models.sensor import Sensor
from ..models.threat import Threat
from ..models.user import User
from ..schemas.sensor import (
    SensorResponse, SensorListResponse, SensorUpdate,
    SensorStats, SensorHeartbeat
)
from .deps import get_current_user, require_admin

router = APIRouter()


@router.get("/sensors", response_model=SensorListResponse)
async def list_sensors(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    is_active: Optional[bool] = None,
    is_online: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all sensors with pagination and filters"""

    # Build query
    query = select(Sensor)

    if is_active is not None:
        query = query.where(Sensor.is_active == is_active)

    if is_online is not None:
        query = query.where(Sensor.is_online == is_online)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Apply pagination
    query = query.offset((page - 1) * page_size).limit(page_size)
    query = query.order_by(Sensor.created_at.desc())

    # Execute query
    result = await db.execute(query)
    sensors = result.scalars().all()

    return SensorListResponse(
        sensors=[SensorResponse.from_orm(s) for s in sensors],
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/sensors/{sensor_id}", response_model=SensorResponse)
async def get_sensor(
    sensor_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get sensor by ID"""

    result = await db.execute(
        select(Sensor).where(Sensor.sensor_id == sensor_id)
    )
    sensor = result.scalar_one_or_none()

    if not sensor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sensor {sensor_id} not found"
        )

    return SensorResponse.from_orm(sensor)


@router.put("/sensors/{sensor_id}", response_model=SensorResponse)
async def update_sensor(
    sensor_id: str,
    sensor_update: SensorUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Update sensor configuration (admin only)"""

    result = await db.execute(
        select(Sensor).where(Sensor.sensor_id == sensor_id)
    )
    sensor = result.scalar_one_or_none()

    if not sensor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sensor {sensor_id} not found"
        )

    # Update fields
    update_data = sensor_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(sensor, field, value)

    sensor.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(sensor)

    return SensorResponse.from_orm(sensor)


@router.delete("/sensors/{sensor_id}")
async def delete_sensor(
    sensor_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete sensor (admin only)"""

    result = await db.execute(
        select(Sensor).where(Sensor.sensor_id == sensor_id)
    )
    sensor = result.scalar_one_or_none()

    if not sensor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sensor {sensor_id} not found"
        )

    await db.delete(sensor)
    await db.commit()

    return {"message": f"Sensor {sensor_id} deleted successfully"}


@router.get("/sensors/{sensor_id}/stats", response_model=SensorStats)
async def get_sensor_stats(
    sensor_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get sensor statistics"""

    # Verify sensor exists
    sensor_result = await db.execute(
        select(Sensor).where(Sensor.sensor_id == sensor_id)
    )
    sensor = sensor_result.scalar_one_or_none()

    if not sensor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sensor {sensor_id} not found"
        )

    # Calculate time ranges
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    # Total threats
    total_result = await db.execute(
        select(func.count()).where(Threat.sensor_id == sensor_id)
    )
    total_threats = total_result.scalar()

    # Threats last 24h
    threats_24h_result = await db.execute(
        select(func.count()).where(
            and_(
                Threat.sensor_id == sensor_id,
                Threat.timestamp >= last_24h
            )
        )
    )
    threats_24h = threats_24h_result.scalar()

    # Threats last 7d
    threats_7d_result = await db.execute(
        select(func.count()).where(
            and_(
                Threat.sensor_id == sensor_id,
                Threat.timestamp >= last_7d
            )
        )
    )
    threats_7d = threats_7d_result.scalar()

    # Threats by severity
    severity_result = await db.execute(
        select(Threat.severity, func.count()).where(
            Threat.sensor_id == sensor_id
        ).group_by(Threat.severity)
    )
    threats_by_severity = {row[0]: row[1] for row in severity_result}

    # Threats by detector
    detector_result = await db.execute(
        select(Threat.detector_type, func.count()).where(
            Threat.sensor_id == sensor_id
        ).group_by(Threat.detector_type)
    )
    threats_by_detector = {row[0]: row[1] for row in detector_result}

    # Most common threat type
    threat_type_result = await db.execute(
        select(Threat.threat_type, func.count().label('count')).where(
            Threat.sensor_id == sensor_id
        ).group_by(Threat.threat_type).order_by(func.count().desc()).limit(1)
    )
    most_common = threat_type_result.first()
    most_common_threat_type = most_common[0] if most_common else None

    # Last threat timestamp
    last_threat_result = await db.execute(
        select(Threat.timestamp).where(
            Threat.sensor_id == sensor_id
        ).order_by(Threat.timestamp.desc()).limit(1)
    )
    last_threat = last_threat_result.scalar_one_or_none()

    return SensorStats(
        sensor_id=sensor_id,
        total_threats=total_threats,
        threats_last_24h=threats_24h,
        threats_last_7d=threats_7d,
        threats_by_severity=threats_by_severity,
        threats_by_detector=threats_by_detector,
        most_common_threat_type=most_common_threat_type,
        last_threat_timestamp=last_threat
    )


@router.post("/sensors/{sensor_id}/heartbeat")
async def sensor_heartbeat(
    sensor_id: str,
    heartbeat: SensorHeartbeat,
    db: AsyncSession = Depends(get_db)
):
    """Receive sensor heartbeat (no auth required for sensors)"""

    result = await db.execute(
        select(Sensor).where(Sensor.sensor_id == sensor_id)
    )
    sensor = result.scalar_one_or_none()

    if not sensor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sensor {sensor_id} not found"
        )

    # Update heartbeat
    sensor.last_heartbeat = heartbeat.timestamp
    sensor.is_online = heartbeat.is_online

    if heartbeat.enabled_detectors:
        sensor.enabled_detectors = heartbeat.enabled_detectors

    if heartbeat.location:
        sensor.latitude = heartbeat.location.get('latitude')
        sensor.longitude = heartbeat.location.get('longitude')
        sensor.location_method = heartbeat.location.get('method')
        sensor.location_accuracy = heartbeat.location.get('accuracy')

    await db.commit()

    return {"message": "Heartbeat received"}
