"""
Threat API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from ..db.base import get_db
from ..models.threat import Threat
from ..models.user import User
from ..schemas.threat import (
    ThreatResponse, ThreatListResponse, ThreatCreate,
    ThreatAcknowledge, ThreatQuery
)
from .deps import get_current_user, require_analyst_or_admin

router = APIRouter()


@router.get("/threats", response_model=ThreatListResponse)
async def list_threats(
    sensor_id: Optional[str] = None,
    detector_type: Optional[str] = None,
    threat_type: Optional[str] = None,
    severity: Optional[List[str]] = Query(None),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    is_acknowledged: Optional[bool] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc", regex="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Query threats with filters and pagination"""

    # Build query
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

    if is_acknowledged is not None:
        filters.append(Threat.is_acknowledged == is_acknowledged)

    if filters:
        query = query.where(and_(*filters))

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Apply sorting
    sort_column = getattr(Threat, sort_by, Threat.timestamp)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * page_size).limit(page_size)

    # Execute query
    result = await db.execute(query)
    threats = result.scalars().all()

    return ThreatListResponse(
        threats=[ThreatResponse.from_orm(t) for t in threats],
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/threats/{threat_id}", response_model=ThreatResponse)
async def get_threat(
    threat_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get threat by ID"""

    result = await db.execute(
        select(Threat).where(Threat.id == threat_id)
    )
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat {threat_id} not found"
        )

    return ThreatResponse.from_orm(threat)


@router.put("/threats/{threat_id}/acknowledge", response_model=ThreatResponse)
async def acknowledge_threat(
    threat_id: UUID,
    ack_data: ThreatAcknowledge,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Acknowledge a threat (analyst or admin)"""

    result = await db.execute(
        select(Threat).where(Threat.id == threat_id)
    )
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat {threat_id} not found"
        )

    # Update acknowledgment
    threat.is_acknowledged = True
    threat.acknowledged_at = datetime.utcnow()
    threat.acknowledged_by = ack_data.acknowledged_by

    await db.commit()
    await db.refresh(threat)

    return ThreatResponse.from_orm(threat)


@router.post("/threats", response_model=ThreatResponse)
async def create_threat(
    threat: ThreatCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create a new threat (called by MQTT subscriber or sensors)"""

    # Create threat object
    db_threat = Threat(**threat.dict())

    db.add(db_threat)
    await db.commit()
    await db.refresh(db_threat)

    return ThreatResponse.from_orm(db_threat)


@router.delete("/threats/{threat_id}")
async def delete_threat(
    threat_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Delete threat (analyst or admin)"""

    result = await db.execute(
        select(Threat).where(Threat.id == threat_id)
    )
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat {threat_id} not found"
        )

    await db.delete(threat)
    await db.commit()

    return {"message": f"Threat {threat_id} deleted successfully"}
