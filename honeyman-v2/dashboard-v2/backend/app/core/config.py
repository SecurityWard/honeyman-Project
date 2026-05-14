"""
Configuration management for Honeyman Dashboard Backend
"""

from typing import Optional, List
from typing_extensions import Annotated
from pydantic import Field, field_validator, validator
from pydantic_settings import BaseSettings

# pydantic-settings >= 2.3 ships NoDecode, which tells the env source to
# skip its eager json.loads() pass for this field. Without it, declaring
# a List[str] field forces operators to write CORS_ORIGINS as a JSON array
# in .env; with it, our field_validator below sees the raw string and can
# parse either JSON-array or CSV.
try:
    from pydantic_settings import NoDecode
    _CORS_ORIGINS_TYPE = Annotated[List[str], NoDecode]
except ImportError:                                  # pragma: no cover
    # pydantic-settings < 2.3 has no NoDecode. CSV in .env will still fail
    # because the env source's eager json.loads() runs first; the JSON-array
    # form continues to work.
    _CORS_ORIGINS_TYPE = List[str]


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
    PUBLIC_API_BASE_URL: str = "https://api.honeyman.io"

    # CORS
    # Accepted forms in the environment variable:
    #   CSV string:  CORS_ORIGINS=http://localhost:3000,https://example.com
    #   JSON array:  CORS_ORIGINS=["http://localhost:3000","https://example.com"]
    # Either parses to List[str]. CSV is friendlier when operators are editing
    # .env by hand; the field_validator below normalises both shapes.
    CORS_ORIGINS: _CORS_ORIGINS_TYPE = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://72.60.25.24:3000",
        "https://dashboard.honeyman.io",
    ]

    # Database (PostgreSQL + TimescaleDB)
    DATABASE_URL: str
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    DATABASE_ECHO: bool = False

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_CACHE_TTL: int = 300  # 5 minutes

    # MQTT Broker (V2: optional - HTTPS is the default sensor transport)
    MQTT_OFFERED: bool = False
    MQTT_BROKER_HOST: Optional[str] = None
    MQTT_BROKER_PORT: int = 8883
    MQTT_BROKER_USERNAME: Optional[str] = None
    MQTT_BROKER_PASSWORD: Optional[str] = None
    MQTT_USE_TLS: bool = True
    MQTT_CA_CERT: Optional[str] = None

    # MQTT Topics (only used if MQTT_OFFERED=true)
    MQTT_TOPIC_THREATS: str = "honeyman/sensors/+/threats"
    MQTT_TOPIC_HEARTBEAT: str = "honeyman/sensors/+/heartbeat"
    MQTT_TOPIC_CONTROL: str = "honeyman/control/#"

    # Data Retention
    DATA_RETENTION_DAYS: int = 90
    CLEANUP_INTERVAL_HOURS: int = 24

    # Rule distribution (Phase C)
    RULES_DIR: Optional[str] = None

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
    WS_HEARTBEAT_INTERVAL: int = 30

    class Config:
        env_file = ".env"
        case_sensitive = True

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_cors_origins(cls, v):
        """
        Accept CORS_ORIGINS as either:
        - list[str]  (Python default, or JSON array decoded into a list)
        - str        (raw env var: CSV or JSON-array literal)

        Returns a clean list[str] either way. Empty strings dropped.
        """
        if v is None:
            return []
        if isinstance(v, str):
            stripped = v.strip()
            if not stripped:
                return []
            # JSON array literal - parse explicitly since NoDecode skipped that step.
            if stripped.startswith("["):
                import json
                try:
                    parsed = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"CORS_ORIGINS looks like JSON but doesn't parse: {exc}")
                if not isinstance(parsed, list):
                    raise ValueError("CORS_ORIGINS JSON value must be an array")
                return [str(item).strip() for item in parsed if str(item).strip()]
            # CSV form
            return [item.strip() for item in stripped.split(",") if item.strip()]
        # Already a list (default value or list[Any])
        return [str(item).strip() for item in v if str(item).strip()]

    @validator("DATABASE_URL")
    def validate_database_url(cls, v):
        """Ensure PostgreSQL URL is valid"""
        if not v.startswith(("postgresql://", "postgresql+asyncpg://")):
            raise ValueError("DATABASE_URL must be a PostgreSQL connection string")
        return v


settings = Settings()
