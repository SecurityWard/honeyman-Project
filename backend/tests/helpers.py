"""Helpers shared across tests. Kept out of conftest.py because importing
from conftest.py via `from .conftest import ...` interacts badly with
pytest's collection machinery on some versions."""

from __future__ import annotations

from httpx import AsyncClient


async def register_sensor(
    client: AsyncClient,
    requested_name: str = "ci-sensor",
) -> tuple[str, str]:
    """Register a sensor; return (sensor_id, api_key)."""
    resp = await client.post(
        "/api/v2/sensors/register",
        json={
            "requested_name": requested_name,
            "capabilities": {"usb": True, "ble": True},
            "enabled_detectors": ["usb", "ble"],
            "platform": "ci",
            "agent_version": "test",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    return body["sensor_id"], body["api_key"]
