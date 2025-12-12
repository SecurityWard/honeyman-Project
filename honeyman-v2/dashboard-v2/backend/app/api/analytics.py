"""
Analytics API endpoints
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, text
from typing import List, Optional
from datetime import datetime, timedelta

from ..db.base import get_db
from ..models.sensor import Sensor
from ..models.threat import Threat
from ..models.user import User
from ..schemas.analytics import (
    OverviewStats, ThreatTrend, TopThreatType, TopSensor,
    GeographicDistribution, MitreAttackCoverage, ThreatVelocity
)
from .deps import get_current_user

router = APIRouter()


@router.get("/analytics/overview", response_model=OverviewStats)
async def get_overview_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get dashboard overview statistics"""

    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    # Total sensors
    total_sensors_result = await db.execute(select(func.count()).select_from(Sensor))
    total_sensors = total_sensors_result.scalar()

    # Active sensors
    active_sensors_result = await db.execute(
        select(func.count()).where(Sensor.is_active == True)
    )
    active_sensors = active_sensors_result.scalar()

    # Online sensors
    online_sensors_result = await db.execute(
        select(func.count()).where(Sensor.is_online == True)
    )
    online_sensors = online_sensors_result.scalar()

    # Total threats
    total_threats_result = await db.execute(select(func.count()).select_from(Threat))
    total_threats = total_threats_result.scalar()

    # Threats last 24h
    threats_24h_result = await db.execute(
        select(func.count()).where(Threat.timestamp >= last_24h)
    )
    threats_24h = threats_24h_result.scalar()

    # Threats last 7d
    threats_7d_result = await db.execute(
        select(func.count()).where(Threat.timestamp >= last_7d)
    )
    threats_7d = threats_7d_result.scalar()

    # Critical threats
    critical_result = await db.execute(
        select(func.count()).where(Threat.severity == 'critical')
    )
    critical_threats = critical_result.scalar()

    # High threats
    high_result = await db.execute(
        select(func.count()).where(Threat.severity == 'high')
    )
    high_threats = high_result.scalar()

    # Threat velocity (threats per hour in last 24h)
    threat_velocity = threats_24h / 24.0 if threats_24h > 0 else 0.0

    # Average threat score
    avg_score_result = await db.execute(
        select(func.avg(Threat.threat_score)).where(Threat.threat_score.isnot(None))
    )
    avg_threat_score = avg_score_result.scalar()

    return OverviewStats(
        total_sensors=total_sensors,
        active_sensors=active_sensors,
        online_sensors=online_sensors,
        total_threats=total_threats,
        threats_last_24h=threats_24h,
        threats_last_7d=threats_7d,
        critical_threats=critical_threats,
        high_threats=high_threats,
        threat_velocity=round(threat_velocity, 2),
        avg_threat_score=round(avg_threat_score, 3) if avg_threat_score else None
    )


@router.get("/analytics/trends")
async def get_threat_trends(
    period: str = Query("hourly", regex="^(hourly|daily|weekly)$"),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    sensor_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get threat trends over time"""

    # Default time range
    if not end_time:
        end_time = datetime.utcnow()

    if not start_time:
        if period == "hourly":
            start_time = end_time - timedelta(days=1)
        elif period == "daily":
            start_time = end_time - timedelta(days=30)
        else:  # weekly
            start_time = end_time - timedelta(days=90)

    # Time bucket interval
    interval_map = {
        "hourly": "1 hour",
        "daily": "1 day",
        "weekly": "1 week"
    }
    interval = interval_map[period]

    # Build query using TimescaleDB time_bucket
    query = text(f"""
        SELECT
            time_bucket('{interval}', timestamp) AS bucket,
            COUNT(*) as count,
            COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical,
            COUNT(CASE WHEN severity = 'high' THEN 1 END) as high,
            COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium,
            COUNT(CASE WHEN severity = 'low' THEN 1 END) as low
        FROM threats
        WHERE timestamp >= :start_time AND timestamp <= :end_time
        {'AND sensor_id = :sensor_id' if sensor_id else ''}
        GROUP BY bucket
        ORDER BY bucket ASC
    """)

    params = {"start_time": start_time, "end_time": end_time}
    if sensor_id:
        params["sensor_id"] = sensor_id

    result = await db.execute(query, params)
    rows = result.fetchall()

    data_points = [
        {
            "timestamp": row[0].isoformat(),
            "count": row[1],
            "severity": {
                "critical": row[2],
                "high": row[3],
                "medium": row[4],
                "low": row[5]
            }
        }
        for row in rows
    ]

    return {
        "period": period,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "data_points": data_points
    }


@router.get("/analytics/top-threats", response_model=List[TopThreatType])
async def get_top_threats(
    limit: int = Query(10, ge=1, le=50),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get top threat types"""

    # Build query
    query = select(
        Threat.threat_type,
        Threat.severity,
        func.count().label('count')
    )

    if start_time:
        query = query.where(Threat.timestamp >= start_time)
    if end_time:
        query = query.where(Threat.timestamp <= end_time)

    query = query.group_by(Threat.threat_type, Threat.severity)\
                 .order_by(func.count().desc())\
                 .limit(limit)

    result = await db.execute(query)
    rows = result.all()

    # Calculate total for percentages
    total = sum(row.count for row in rows)

    return [
        TopThreatType(
            threat_type=row.threat_type,
            count=row.count,
            percentage=round((row.count / total * 100), 2) if total > 0 else 0,
            severity=row.severity
        )
        for row in rows
    ]


@router.get("/analytics/top-sensors", response_model=List[TopSensor])
async def get_top_sensors(
    limit: int = Query(10, ge=1, le=50),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get top sensors by threat count"""

    # Build subquery for threat counts
    threat_counts = select(
        Threat.sensor_id,
        func.count().label('threat_count')
    )

    if start_time:
        threat_counts = threat_counts.where(Threat.timestamp >= start_time)
    if end_time:
        threat_counts = threat_counts.where(Threat.timestamp <= end_time)

    threat_counts = threat_counts.group_by(Threat.sensor_id).subquery()

    # Join with sensors table
    query = select(
        Sensor.sensor_id,
        Sensor.name,
        Sensor.city,
        Sensor.country,
        threat_counts.c.threat_count
    ).join(
        threat_counts, Sensor.sensor_id == threat_counts.c.sensor_id
    ).order_by(
        threat_counts.c.threat_count.desc()
    ).limit(limit)

    result = await db.execute(query)
    rows = result.all()

    return [
        TopSensor(
            sensor_id=row.sensor_id,
            sensor_name=row.name,
            threat_count=row.threat_count,
            city=row.city,
            country=row.country
        )
        for row in rows
    ]


@router.get("/analytics/map")
async def get_threat_map(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    severity: Optional[List[str]] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get geographic threat distribution for map visualization"""

    query = text("""
        SELECT
            t.sensor_id,
            s.latitude,
            s.longitude,
            s.city,
            s.country,
            COUNT(*) as threat_count,
            COUNT(CASE WHEN t.severity = 'critical' THEN 1 END) as critical,
            COUNT(CASE WHEN t.severity = 'high' THEN 1 END) as high,
            COUNT(CASE WHEN t.severity = 'medium' THEN 1 END) as medium,
            COUNT(CASE WHEN t.severity = 'low' THEN 1 END) as low
        FROM threats t
        JOIN sensors s ON t.sensor_id = s.sensor_id
        WHERE s.latitude IS NOT NULL AND s.longitude IS NOT NULL
        {'AND t.timestamp >= :start_time' if start_time else ''}
        {'AND t.timestamp <= :end_time' if end_time else ''}
        {'AND t.severity = ANY(:severity)' if severity else ''}
        GROUP BY t.sensor_id, s.latitude, s.longitude, s.city, s.country
        ORDER BY threat_count DESC
    """)

    params = {}
    if start_time:
        params["start_time"] = start_time
    if end_time:
        params["end_time"] = end_time
    if severity:
        params["severity"] = severity

    result = await db.execute(query, params)
    rows = result.fetchall()

    return [
        {
            "sensor_id": row[0],
            "latitude": row[1],
            "longitude": row[2],
            "city": row[3],
            "country": row[4],
            "threat_count": row[5],
            "severity_breakdown": {
                "critical": row[6],
                "high": row[7],
                "medium": row[8],
                "low": row[9]
            }
        }
        for row in rows
    ]


@router.get("/analytics/velocity", response_model=ThreatVelocity)
async def get_threat_velocity(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get threat velocity metrics"""

    now = datetime.utcnow()
    last_hour = now - timedelta(hours=1)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    # Current rate (last hour)
    current_result = await db.execute(
        select(func.count()).where(Threat.timestamp >= last_hour)
    )
    current_count = current_result.scalar()
    current_rate = current_count  # threats per hour

    # 24h average
    avg_24h_result = await db.execute(
        select(func.count()).where(Threat.timestamp >= last_24h)
    )
    avg_24h_count = avg_24h_result.scalar()
    avg_rate_24h = avg_24h_count / 24.0

    # 7d average
    avg_7d_result = await db.execute(
        select(func.count()).where(Threat.timestamp >= last_7d)
    )
    avg_7d_count = avg_7d_result.scalar()
    avg_rate_7d = avg_7d_count / (7.0 * 24.0)

    # Peak rate (max threats in any hour in last 7 days)
    peak_query = text("""
        SELECT
            time_bucket('1 hour', timestamp) AS bucket,
            COUNT(*) as count
        FROM threats
        WHERE timestamp >= :start_time
        GROUP BY bucket
        ORDER BY count DESC
        LIMIT 1
    """)

    peak_result = await db.execute(peak_query, {"start_time": last_7d})
    peak_row = peak_result.first()

    peak_rate = peak_row[1] if peak_row else 0
    peak_timestamp = peak_row[0] if peak_row else None

    # Determine trend
    if current_rate > avg_rate_24h * 1.2:
        trend = "increasing"
    elif current_rate < avg_rate_24h * 0.8:
        trend = "decreasing"
    else:
        trend = "stable"

    return ThreatVelocity(
        current_rate=round(current_rate, 2),
        avg_rate_24h=round(avg_rate_24h, 2),
        avg_rate_7d=round(avg_rate_7d, 2),
        peak_rate=peak_rate,
        peak_timestamp=peak_timestamp,
        trend=trend
    )
