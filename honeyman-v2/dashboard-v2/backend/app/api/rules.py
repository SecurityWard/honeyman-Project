"""
Rules distribution endpoint.

GET /api/v2/rules
    Returns the current rule manifest for the calling sensor:

        {
          "version":      "<sha256 of all rules concatenated>",
          "count":        N,
          "generated_at": "<isoformat utc>",
          "rules": [
            {
              "path":     "usb/badusb_detection.yaml",
              "category": "usb",
              "sha256":   "<per-rule hash>",
              "content":  "<raw YAML string>"
            },
            ...
          ]
        }

    Optional query param:
        ?since_version=<hash>   If matches current global version, returns
                                an empty manifest with the same version
                                so the client can short-circuit. (We don't
                                return 304 because the client wants the
                                version string back regardless.)

Authentication: requires a valid sensor API key (Authorization: Bearer ...).

Source-of-truth directory is configured via settings.RULES_DIR. Defaults
to <backend>/rules. The directory is expected to contain YAML files
organised in category subdirectories (usb/, wifi/, ble/, network/,
airdrop/, …), matching the layout the agent expects under
/etc/honeyman/rules/.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from ..core.config import settings
from ..models.sensor import Sensor
from .deps import authenticated_sensor

logger = logging.getLogger(__name__)

router = APIRouter()


# --- Schemas ---------------------------------------------------------------


class RuleEntry(BaseModel):
    path: str = Field(..., description="Relative path, e.g. 'usb/badusb_detection.yaml'")
    category: str = Field(..., description="Top-level subdir, e.g. 'usb'")
    sha256: str = Field(..., description="SHA256 of the file's raw bytes")
    content: str = Field(..., description="Raw YAML text")


class RuleManifest(BaseModel):
    version: str = Field(..., description="SHA256 over all rule contents")
    count: int
    generated_at: datetime
    rules: list[RuleEntry]


# --- Helpers ---------------------------------------------------------------


def _rules_dir() -> Path:
    """Resolve the backend's rules source directory."""
    configured = getattr(settings, "RULES_DIR", None)
    if configured:
        return Path(configured)
    # Default: <backend>/rules (sibling of /app)
    return Path(__file__).resolve().parent.parent.parent / "rules"


def _collect_rules(root: Path) -> list[tuple[str, str, bytes]]:
    """
    Walk `root`, return [(rel_path, category, raw_bytes), ...] for every
    .yaml/.yml file. Sorted deterministically so the version hash is stable.
    """
    if not root.is_dir():
        return []
    out: list[tuple[str, str, bytes]] = []
    for path in sorted(root.rglob("*.y*ml")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        # Category = top-level subdir under root (e.g. 'usb' from 'usb/foo.yaml').
        parts = rel.split("/", 1)
        category = parts[0] if len(parts) > 1 else "uncategorised"
        try:
            raw = path.read_bytes()
        except OSError as exc:
            logger.warning("Could not read rule %s: %s", path, exc)
            continue
        out.append((rel, category, raw))
    return out


def _build_manifest(root: Path) -> RuleManifest:
    entries = _collect_rules(root)
    rule_list: list[RuleEntry] = []
    global_hasher = hashlib.sha256()
    for rel, category, raw in entries:
        per_hash = hashlib.sha256(raw).hexdigest()
        global_hasher.update(rel.encode("utf-8"))
        global_hasher.update(b"\x00")
        global_hasher.update(raw)
        global_hasher.update(b"\x00")
        rule_list.append(
            RuleEntry(
                path=rel,
                category=category,
                sha256=per_hash,
                content=raw.decode("utf-8", errors="replace"),
            )
        )
    return RuleManifest(
        version=global_hasher.hexdigest(),
        count=len(rule_list),
        generated_at=datetime.utcnow(),
        rules=rule_list,
    )


# --- Endpoint --------------------------------------------------------------


@router.get(
    "/rules",
    response_model=RuleManifest,
    summary="Fetch the current rule manifest for this sensor",
)
async def get_rules(
    since_version: str | None = Query(
        default=None,
        description="If provided and equal to the current global version, "
                    "returns an empty rules list (version unchanged).",
    ),
    sensor: Sensor = Depends(authenticated_sensor),
):
    """
    Returns the current rule set. The sensor caller is identified by its
    API key — future work may filter rules by sensor capabilities.
    """
    root = _rules_dir()
    if not root.is_dir():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Rules directory not configured (looked at {root})",
        )

    manifest = _build_manifest(root)

    # If the caller is already up to date, return an empty rules list.
    # Same version means nothing has changed; the client can short-circuit
    # the diff/write loop.
    if since_version and since_version == manifest.version:
        return RuleManifest(
            version=manifest.version,
            count=0,
            generated_at=manifest.generated_at,
            rules=[],
        )

    logger.info(
        "Served rule manifest to sensor %s (version=%s, count=%d)",
        sensor.sensor_id,
        manifest.version[:12],
        manifest.count,
    )
    return manifest
