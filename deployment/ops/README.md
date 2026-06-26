# Honeyman ops artifacts

Operator-side configuration for the things every production deployment
needs but the application doesn't ship by default: database backups,
log rotation, and a basic uptime probe.

These are deliberately separate from `phase_a_apply.sh` — they're
ongoing operational concerns, not first-time deploy steps. Apply once
per host; they're idempotent.

## Files

| File | Install to | Purpose |
|---|---|---|
| `postgres-backup.sh` | `/usr/local/sbin/honeyman-postgres-backup.sh` (mode 0755, owned by root) | Nightly `pg_dump` of the `honeyman_v2` DB, gzipped, written to `/var/backups/honeyman/`. Prunes anything older than `RETENTION_DAYS` (default 14). |
| `honeyman-backup.service` | `/etc/systemd/system/honeyman-backup.service` (mode 0644) | systemd unit for one-shot backup. |
| `honeyman-backup.timer` | `/etc/systemd/system/honeyman-backup.timer` (mode 0644) | Fires the backup at 03:17 UTC daily. **This is the canonical path** — modern Debian/Ubuntu images don't ship `cron`. |
| `honeyman-backup.cron` | `/etc/cron.d/honeyman-backup` (mode 0644) | *Alternative* for hosts that already run `cron`. Don't install alongside the systemd timer — pick one. |
| `honeyman.logrotate` | `/etc/logrotate.d/honeyman` (mode 0644) | Rotates `/var/log/honeyman-backend.log` daily, keeps 14 compressed copies, uses `copytruncate` so the running uvicorn process keeps writing. |
| `healthcheck.sh` | `/usr/local/sbin/honeyman-healthcheck.sh` (mode 0755) | Hits `${API_BASE}/health` plus a public read endpoint, logs to syslog, exits non-zero on failure. Optional webhook notification. |
| `honeyman-healthcheck.service` | `/etc/systemd/system/honeyman-healthcheck.service` (mode 0644) | systemd unit for one-shot probe. Reads optional `/etc/honeyman/healthcheck.env`. |
| `honeyman-healthcheck.timer` | `/etc/systemd/system/honeyman-healthcheck.timer` (mode 0644) | Fires the probe every 5 min. |
| `healthcheck.env.example` | Copy to `/etc/honeyman/healthcheck.env` (mode 0600) | Operator-edited overrides. Most important: `HEALTHCHECK_WEBHOOK=...` to actually get notified on failure. |

## Installing on a fresh VPS

```bash
# 0. Clone the repo (or pull the latest)
cd /root/honeyman-Project

# 1. Backups (systemd timer — canonical path)
install -m 0755 deployment/ops/postgres-backup.sh \
    /usr/local/sbin/honeyman-postgres-backup.sh
install -m 0644 deployment/ops/honeyman-backup.service \
    /etc/systemd/system/honeyman-backup.service
install -m 0644 deployment/ops/honeyman-backup.timer \
    /etc/systemd/system/honeyman-backup.timer

systemctl daemon-reload
systemctl enable --now honeyman-backup.timer

# Seed /var/backups/honeyman now so we don't have to wait until 03:17 UTC.
systemctl start honeyman-backup.service
journalctl -u honeyman-backup.service -n 20 --no-pager

# 2. Log rotation
install -m 0644 deployment/ops/honeyman.logrotate \
    /etc/logrotate.d/honeyman

# Smoke-test the config:
logrotate -d /etc/logrotate.d/honeyman   # dry-run; reports what it would do
logrotate -f /etc/logrotate.d/honeyman   # force a rotation now

# 3. Uptime probe
install -m 0755 deployment/ops/healthcheck.sh \
    /usr/local/sbin/honeyman-healthcheck.sh
install -m 0644 deployment/ops/honeyman-healthcheck.service \
    /etc/systemd/system/honeyman-healthcheck.service
install -m 0644 deployment/ops/honeyman-healthcheck.timer \
    /etc/systemd/system/honeyman-healthcheck.timer

systemctl daemon-reload
systemctl enable --now honeyman-healthcheck.timer

# Run it once and inspect:
systemctl start honeyman-healthcheck.service
journalctl -u honeyman-healthcheck.service -n 20 --no-pager
```

## Optional webhook for the uptime probe

The service unit already references `/etc/honeyman/healthcheck.env`
(`EnvironmentFile=-/etc/honeyman/healthcheck.env` with the leading `-`
so the unit still starts on hosts that haven't configured one). To
turn on notifications, copy the example and edit:

```bash
sudo install -m 0600 -o root -g root \
    deployment/ops/healthcheck.env.example \
    /etc/honeyman/healthcheck.env
sudo $EDITOR /etc/honeyman/healthcheck.env   # uncomment HEALTHCHECK_WEBHOOK=
sudo systemctl restart honeyman-healthcheck.service
sudo systemctl start honeyman-healthcheck.service   # fire one probe now
```

Without `HEALTHCHECK_WEBHOOK`, the probe still logs to syslog and the
systemd unit still goes red on failure — you just don't get pinged.

## Verifying the backups

```bash
ls -lh /var/backups/honeyman/
# A normal day shows ~14 files, the most recent dated today.

# Smoke-test a restore on a scratch DB:
gunzip -c /var/backups/honeyman/honeyman_v2-*.sql.gz | head -50
# Sanity-check that the dump is real SQL, not an error message.
```

## What this does NOT do

- No off-site backup transfer. If you want that, pipe `postgres-backup.sh`
  output to `rclone` / `aws s3 cp` / similar. The shell script is small
  enough to extend without breaking anything.
- No alerting beyond "exit non-zero so cron emails root" and an optional
  webhook. If you need PagerDuty / SMS, wrap the script or send the
  webhook to a router you already operate.
- No Prometheus metrics. The backend's `/health` endpoint reports `ok`
  binary; a real metrics surface is a separate piece of work.
