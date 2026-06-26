"""Onboarding request/response schemas for POST /sensors/register."""

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class SensorRegistration(BaseModel):
    """Sent by the sensor at install time."""

    requested_name: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Self-selected sensor name. Backend appends a random suffix.",
    )
    location_label: str | None = Field(
        default=None,
        max_length=200,
        description='Free-text location, e.g. "DefCon 32 hotel lobby"',
    )

    # Hardware/software capabilities reported by the install script
    capabilities: dict[str, bool] = Field(
        default_factory=dict,
        description='e.g. {"usb": true, "wifi": true, "ble": true, "airdrop": false}',
    )
    enabled_detectors: list[str] = Field(default_factory=list)
    platform: str | None = None        # rpi5, rpi4, rpizero2w, linux
    architecture: str | None = None    # arm64, x86_64
    agent_version: str | None = None
    python_version: str | None = None

    # Optional initial location - operator can pin a sensor at install time
    initial_location: dict[str, Any] | None = Field(
        default=None,
        description='Optional. {"latitude": float, "longitude": float, "method": "manual", "accuracy": float}',
    )


class SensorRegistrationResponse(BaseModel):
    """
    Returned exactly once. The plaintext api_key is never retrievable again -
    the install script writes it to /etc/honeyman/credentials.
    """

    sensor_id: str = Field(..., description='e.g. "defcon-hotel-7x9k"')
    api_key: str = Field(..., description="One-time plaintext key. Store securely.")

    # Where to send data
    api_endpoint: str = Field(..., description='e.g. "https://api.honeymanproject.com/api/v2"')

    # Optional MQTT details - only populated if the deployment offers MQTT
    mqtt_enabled: bool = False
    mqtt_broker: str | None = None
    mqtt_port: int | None = None
    mqtt_topic_threats: str | None = None
    mqtt_topic_heartbeat: str | None = None

    registered_at: datetime
