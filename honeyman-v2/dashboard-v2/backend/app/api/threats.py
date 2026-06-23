"""Threat endpoints. Reads are public; writes require the sensor's API key."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.base import get_db
from ..models.sensor import Sensor
from ..models.threat import Threat
from ..schemas.threat import ThreatCreate, ThreatListResponse, ThreatResponse
from .deps import authenticated_sensor

router = APIRouter()


@router.get("/threats", response_model=ThreatListResponse)
async def list_threats(
    sensor_id: Optional[str] = None,
    detector_type: Optional[str] = None,
    threat_type: Optional[str] = None,
    severity: Optional[List[str]] = Query(None),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc", regex="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
):
    """Query threats with filters and pagination. Public read."""

    query = select(Threat)
    filters = []

    if sensor_id:
        filters.append(Threat.sensor_id == sensor_id)
    if detector_type:
        filters.append(Threat.detector_type == detector_type)
    if threat_type:
        filters.append(Threat.threat_type == threat_type)
    if severity:
        filters.append(Threat.severity.in_(severity))
    if start_time:
        filters.append(Threat.timestamp >= start_time)
    if end_time:
        filters.append(Threat.timestamp <= end_time)

    if filters:
        query = query.where(and_(*filters))

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    sort_column = getattr(Threat, sort_by, Threat.timestamp)
    query = query.order_by(sort_column.desc() if sort_order == "desc" else sort_column.asc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    threats = (await db.execute(query)).scalars().all()

    return ThreatListResponse(
        items=[ThreatResponse.from_orm(t) for t in threats],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/threats/{threat_id}", response_model=ThreatResponse)
async def get_threat(threat_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get threat by ID. Public read."""
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat {threat_id} not found",
        )
    return ThreatResponse.from_orm(threat)


@router.post(
    "/threats",
    response_model=ThreatResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_threat(
    threat: ThreatCreate,
    db: AsyncSession = Depends(get_db),
    sensor: Sensor = Depends(authenticated_sensor),
):
    """
    Create a new threat. Requires sensor API key.

    The sensor_id in the body MUST match the sensor authenticated by the
    API key — sensors can't push events as other sensors.
    """
    if threat.sensor_id != sensor.sensor_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key does not match sensor_id in payload",
        )

    db_threat = Threat(**threat.dict())
    db.add(db_threat)
    await db.commit()
    await db.refresh(db_threat)

    return ThreatResponse.from_orm(db_threat)
