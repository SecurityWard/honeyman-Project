#!/usr/bin/env python3
"""Validate detection rules against the fields the detectors actually emit.

Catches the silent-breakage class of bug where a rule matches a field a
detector never produces, so the rule can never fire. We found several this
way: evil_twin (`rssi` vs emitted `signal`), wps (`wps_enabled` never
emitted), flipper's NUS clause (`service_uuid` vs emitted `service_uuids`).

The core assertion: **every ENABLED rule must be satisfiable** — given its
AND/OR operator, at least the clauses required to fire must reference a
field the detector emits. A rule that can never fire is a dead capability.

Dead *individual* clauses (in an OR rule that can still fire via another
clause) are reported as warnings, not failures — the detection still works,
just not via that sub-signature.

Run:  python agent/tests/validate_rules.py       (exit 1 on any failure)

When a detector starts emitting a new field, add it to EMITTED_FIELDS below.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

# Fields each detector puts into the event dict passed to evaluate_event.
# Derived from the *_detector.py event construction. Keep in sync when a
# detector adds/renames an emitted field.
EMITTED_FIELDS = {
    "usb": {
        "vid", "pid", "vid_pid", "vendor", "product_name", "manufacturer",
        "model", "serial", "device_class", "device_node", "device_path",
        "partition", "fs_type", "fs_uuid", "is_storage", "usb_interfaces",
        "volume_label", "filename", "file_path", "file_size",
        "file_extension", "sha256", "md5", "malware_name", "malware_family",
        "malware_threat_type", "malware_description", "malware_db_severity",
        "timestamp", "add", "remove",
    },
    "ble": {
        "mac_address", "device_name", "rssi", "manufacturer_data",
        "service_uuids", "detection_method", "detector_type", "timestamp",
        "appearance_rate", "name_changes", "manufacturer_changes",
    },
    "wifi": {
        "ssid", "bssid", "channel", "signal", "encryption", "threat_type",
        "deauth_count_per_minute", "unique_ssids_per_scan", "client",
        "monitor", "timestamp",
    },
    "airdrop": {
        "address", "detector_type", "interface", "port", "protocol",
        "service_name", "timestamp", "txt_records",
    },
    # network events pass the raw OpenCanary record through (**event_data),
    # so their fields are dynamic and not statically checkable here. The
    # network honeypot also isn't wired yet. Exempt from the strict check.
    "network": None,
}


def clause_fields(clause: dict) -> list[str]:
    """Fields a single clause depends on. `behavioral` clauses use a
    `metric:` that no detector currently computes — treat as a field that
    isn't emitted so behavioral-only rules are flagged."""
    if "field" in clause:
        return [clause["field"]]
    if "metric" in clause:
        return [f"metric:{clause['metric']}"]
    return []


def is_emitted(field: str, emitted: set[str]) -> bool:
    # metric:* are behavioral anomalies nothing computes yet.
    if field.startswith("metric:"):
        return False
    return field in emitted


def check_rule(path: Path) -> tuple[list[str], list[str]]:
    """Return (errors, warnings) for one rule file."""
    errors: list[str] = []
    warnings: list[str] = []
    rel = path.relative_to(RULES_DIR.parent)

    try:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"{rel}: YAML parse error: {exc}"], []

    if not rule:
        return [f"{rel}: empty rule file"], []

    category = rule.get("category")
    if category not in EMITTED_FIELDS:
        return [f"{rel}: unknown category {category!r}"], []

    emitted = EMITTED_FIELDS[category]
    if emitted is None:
        return [], []  # exempt (e.g. network passthrough)

    if not rule.get("enabled", True):
        return [], []  # disabled rules aren't required to be satisfiable

    conditions = rule.get("conditions") or {}
    operator = (conditions.get("operator") or "AND").upper()
    clauses = conditions.get("clauses") or []
    if not clauses:
        return [f"{rel}: enabled rule has no clauses"], []

    per_clause_ok = []
    for c in clauses:
        fields = clause_fields(c)
        ok = bool(fields) and all(is_emitted(f, emitted) for f in fields)
        per_clause_ok.append(ok)
        if not ok:
            bad = [f for f in fields if not is_emitted(f, emitted)]
            warnings.append(f"{rel}: dead clause — field(s) not emitted by "
                            f"{category} detector: {', '.join(bad)}")

    # Satisfiability: AND needs every clause; OR needs at least one.
    satisfiable = all(per_clause_ok) if operator == "AND" else any(per_clause_ok)
    if not satisfiable:
        errors.append(
            f"{rel}: ENABLED but can never fire (operator {operator}; no "
            f"satisfiable clause against {category} detector fields)"
        )

    return errors, warnings


def main() -> int:
    rule_files = sorted(RULES_DIR.rglob("*.y*ml"))
    if not rule_files:
        print(f"No rule files under {RULES_DIR}", file=sys.stderr)
        return 1

    all_errors: list[str] = []
    all_warnings: list[str] = []
    for path in rule_files:
        errs, warns = check_rule(path)
        all_errors.extend(errs)
        all_warnings.extend(warns)

    if all_warnings:
        print(f"WARNINGS ({len(all_warnings)}): dead clauses (rule still fires "
              f"via another clause):")
        for w in all_warnings:
            print(f"  - {w}")
        print()

    if all_errors:
        print(f"FAILURES ({len(all_errors)}): rules that cannot fire:")
        for e in all_errors:
            print(f"  - {e}")
        return 1

    print(f"OK: {len(rule_files)} rule files checked, "
          f"every enabled rule is satisfiable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
