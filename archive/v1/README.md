# Honeyman V1 Archive

This directory contains the Honeyman V1 codebase, archived as of the V2 cleanup on 2026-05-09.

V1 was launched at DefCon (2024) and is no longer actively developed. It is kept here for reference only.

## What's here

| Path | Purpose |
|---|---|
| `src/detectors/` | V1 monolithic detector scripts (USB, WiFi, BLE, AirDrop, multi-vector) |
| `src/forwarders/` | V1 data forwarders (Hostinger, OpenCanary) |
| `src/utils/` | V1 utilities (threat feed updater) |
| `dashboard/` | V1 Node.js dashboard server + static HTML |
| `scripts/` | V1 install, control, and health-check scripts |
| `deployment/` | V1 systemd service files and Docker compose |
| `config/` | V1 configuration (filebeat, log filtering, WiFi whitelist) |
| `web/` | V1 honeypot web portal (corporate directory, payroll decoy) |
| `log_manager.py` | V1 log rotation/cleanup |
| `simple_log_collector.py` | V1 log aggregation |
| `system_monitor.py` | V1 system health monitor |
| `resync_*.py` | V1 dashboard data resync utilities |
| `opencanary.conf` | V1 OpenCanary config |
| `docker-compose.yml` | V1 Elasticsearch/Kibana stack |
| `requirements.txt` | V1 Python dependencies |
| `logrotate.conf`, `logrotate.d/` | V1 log rotation configs |
| `honeyman.jpeg` | V1 logo |

## Why it's archived

V2 is a complete redesign:

- Modular agent (replaces monolithic detector scripts)
- YAML rule engine (replaces hardcoded detection logic)
- HTTPS+API-key transport (replaces HTTP forwarders to Elasticsearch)
- React+FastAPI dashboard (replaces Kibana + static HTML)
- Postgres + TimescaleDB (replaces Elasticsearch)
- Public read-only dashboard (no V1-style admin features)

See `../../HONEYMAN-V2-PLAN.md` for the V2 vision and plan.

## Reusable assets still imported by V2

- `../../data/malware_hashes.db` (in repo root, not archived) — referenced by V2 USB detector.

## Reviving V1

Don't. If you absolutely must run V1, copy this entire directory back to the repo root and follow the (now-archived) `archive/v1/scripts/install-systemd-services.sh`. There's no support.
