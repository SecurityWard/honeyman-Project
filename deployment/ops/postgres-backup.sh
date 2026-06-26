#!/usr/bin/env bash
# Honeyman Postgres backup script.
#
# Dumps the `honeyman_v2` DB to /var/backups/honeyman/ as a gzipped
# pg_dump, and prunes anything older than RETENTION_DAYS. Designed to be
# called from cron (see honeyman-backup.cron in this directory) or from
# a systemd timer.
#
# Failure modes we care about:
#   - DB unreachable     → exit non-zero so cron emails root
#   - Disk full          → pg_dump returns non-zero; we still exit non-zero
#   - Partial dump       → we write to a .tmp file and only rename on success
#
# Backup files are mode 0600 owned by root because they contain the
# entire threats table + every sensor's api_key_hash. Treat them like
# the live DB.

set -euo pipefail

DB_NAME="${DB_NAME:-honeyman_v2}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/honeyman}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
LOG_TAG="honeyman-backup"

ts=$(date -u +%Y-%m-%dT%H-%M-%SZ)
final="${BACKUP_DIR}/${DB_NAME}-${ts}.sql.gz"
tmp="${final}.tmp"

mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

logger -t "$LOG_TAG" "starting dump of $DB_NAME -> $final"

# Run as the postgres user; redirect stderr separately so a transient
# warning doesn't poison the gzip stream.
if ! sudo -u postgres pg_dump --no-owner --no-privileges "$DB_NAME" 2>/tmp/honeyman-backup.err | gzip -9 > "$tmp"; then
    logger -t "$LOG_TAG" "pg_dump FAILED — see /tmp/honeyman-backup.err"
    rm -f "$tmp"
    exit 1
fi

chmod 0600 "$tmp"
mv "$tmp" "$final"

bytes=$(stat -c%s "$final")
logger -t "$LOG_TAG" "wrote $final ($bytes bytes)"

# Prune. -mtime +N is "modified more than N*24h ago", so +14 keeps the
# 15 most recent dumps in practice. Good enough for this workload.
deleted=$(find "$BACKUP_DIR" -maxdepth 1 -name "${DB_NAME}-*.sql.gz" -mtime "+${RETENTION_DAYS}" -delete -print | wc -l)
if [[ "$deleted" -gt 0 ]]; then
    logger -t "$LOG_TAG" "pruned $deleted dump(s) older than ${RETENTION_DAYS} days"
fi
