"""
Configuration management for Honeyman Dashboard Backend
"""

from typing import Optional, List
from pydantic import Field, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""

    # Application
    APP_NAME: str = "Honeyman Dashboard API"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False
    API_PREFIX: str = "/api/v2"

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4

    # Security
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "https://dashboard.honeyman.io"
    ]

    # Database (PostgreSQL + TimescaleDB)
    DATABASE_URL: str
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    DATABASE_ECHO: bool = False

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_CACHE_TTL: int = 300  # 5 minutes

    # MQTT Broker
    MQTT_BROKER_HOST: str
    MQTT_BROKER_PORT: int = 8883
    MQTT_BROKER_USERNAME: str
    MQTT_BROKER_PASSWORD: str
    MQTT_USE_TLS: bool = True
    MQTT_CA_CERT: Optional[str] = None

    # MQTT Topics
    MQTT_TOPIC_THREATS: str = "honeyman/sensors/+/threats"
    MQTT_TOPIC_HEARTBEAT: str = "honeyman/sensors/+/heartbeat"
    MQTT_TOPIC_CONTROL: str = "honeyman/control/#"

    # Data Retention
    DATA_RETENTION_DAYS: int = 90
    CLEANUP_INTERVAL_HOURS: int = 24

    # Geolocation
    GOOGLE_GEOLOCATION_API_KEY: Optional[str] = None
    IP_GEOLOCATION_API_KEY: Optional[str] = None

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 60

    # WebSocket
    WS_HEARTBEAT_INTERVAL: int = 30  # seconds

    class Config:
        env_file = ".env"
        case_sensitive = True

    @validator("DATABASE_URL")
    def validate_database_url(cls, v):
        """Ensure PostgreSQL URL is valid"""
        if not v.startswith(("postgresql://", "postgresql+asyncpg://")):
            raise ValueError("DATABASE_URL must be a PostgreSQL connection string")
        return v


settings = Settings()
