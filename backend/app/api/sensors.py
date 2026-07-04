"""Sensor endpoints. Reads are public; heartbeats require the sensor's API key."""

from datetime import datetime, timedelta, timezone
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

# --- Sensor liveness windows -----------------------------------------
# The agent's heartbeat interval is 60s. We derive online/offline from
# the last_heartbeat age at read time rather than trusting the stored
# is_online boolean, which nothing ever set back to false — so every
# sensor that ever checked in read "online" forever.
ONLINE_WINDOW = timedelta(minutes=5)   # heard from within 5 min = online

# A sensor silent this long drops off the default sensor list and the
# active-sensor count. Its threats are never touched — history stays on
# the map and in the feed. Pass ?include_stale=true to list it anyway,
# and a direct GET /sensors/{id} always resolves (threat click-through
# to an aged sensor keeps working).
STALE_WINDOW = timedelta(hours=72)


def _derive_online(last_heartbeat: Optional[datetime], now: datetime) -> bool:
    """True if we heard from the sensor within ONLINE_WINDOW."""
    if last_heartbeat is None:
        return False
    if last_heartbeat.tzinfo is None:            # tolerate naive legacy rows
        last_heartbeat = last_heartbeat.replace(tzinfo=timezone.utc)
    return (now - last_heartbeat) <= ONLINE_WINDOW


@router.get("/sensors", response_model=SensorListResponse)
async def list_sensors(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    is_active: Optional[bool] = None,
    include_stale: bool = Query(
        False,
        description="Include sensors silent longer than 72h (they drop off by default).",
    ),
    db: AsyncSession = Depends(get_db),
):
    """List sensors. Public read.

    By default, sensors we haven't heard from in >72h are hidden — a
    sensor that's been retired or reflashed shouldn't clutter the list
    forever. Their threats are never removed, so history stays on the
    map and in the feed; pass ?include_stale=true to see them here too.
    """
    now = datetime.now(timezone.utc)

    query = select(Sensor)
    if is_active is not None:
        query = query.where(Sensor.is_active == is_active)
    if not include_stale:
        # Liveness anchor is the last heartbeat, or registration time for
        # a sensor that registered but never checked in. Coalesce so a
        # brand-new sensor still appears immediately.
        stale_cutoff = now - STALE_WINDOW
        query = query.where(
            func.coalesce(Sensor.last_heartbeat, Sensor.registered_at) >= stale_cutoff
        )

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    query = query.offset((page - 1) * page_size).limit(page_size)
    query = query.order_by(Sensor.created_at.desc())
    sensors = (await db.execute(query)).scalars().all()

    # Live threat-count overlay. The Sensor table has columns for
    # total_threats_detected and threats_last_24h, but nothing maintains
    # them — they sit at 0 forever, which made the Sensors page report
    # 0/0 for a sensor that had clearly fired alerts. Two cheap GROUP BY
    # queries scoped to this page's sensor_ids give accurate counts every
    # request without the drift risk of denormalized counters.
    sensor_ids = [s.sensor_id for s in sensors]
    total_counts: dict[str, int] = {}
    counts_24h: dict[str, int] = {}
    if sensor_ids:
        last_24h = now - timedelta(hours=24)
        total_rows = await db.execute(
            select(Threat.sensor_id, func.count())
            .where(Threat.sensor_id.in_(sensor_ids))
            .group_by(Threat.sensor_id)
        )
        total_counts = {sid: cnt for sid, cnt in total_rows.all()}

        recent_rows = await db.execute(
            select(Threat.sensor_id, func.count())
            .where(
                and_(
                    Threat.sensor_id.in_(sensor_ids),
                    Threat.timestamp >= last_24h,
                )
            )
            .group_by(Threat.sensor_id)
        )
        counts_24h = {sid: cnt for sid, cnt in recent_rows.all()}

    responses = []
    for s in sensors:
        s.total_threats_detected = total_counts.get(s.sensor_id, 0)
        s.threats_last_24h = counts_24h.get(s.sensor_id, 0)
        # Derived at read time — the stored is_online boolean was never
        # reset to false, so it read "online" forever. See _derive_online.
        s.is_online = _derive_online(s.last_heartbeat, now)
        responses.append(SensorResponse.from_orm(s))

    return SensorListResponse(
        sensors=responses,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/sensors/{sensor_id}", response_model=SensorResponse)
async def get_sensor(sensor_id: str, db: AsyncSession = Depends(get_db)):
    """Get sensor by ID. Public read.

    A direct lookup always resolves, even for a sensor past the 72h
    staleness window — so clicking through from an old threat to its
    sensor keeps working after the sensor has dropped off the list.
    """
    result = await db.execute(select(Sensor).where(Sensor.sensor_id == sensor_id))
    sensor = result.scalar_one_or_none()
    if not sensor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sensor {sensor_id} not found",
        )
    sensor.is_online = _derive_online(sensor.last_heartbeat, datetime.now(timezone.utc))
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
