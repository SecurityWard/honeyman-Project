set -euo pipefail
cd /root/honeyman-Project
git fetch --quiet origin main
git checkout main
git pull --ff-only origin main

OPS=/root/honeyman-Project/honeyman-v2/deployment/ops
test -d "$OPS" || { echo "MISSING $OPS — pull didn't land"; exit 1; }

install -m 0755 -o root -g root "$OPS/postgres-backup.sh" /usr/local/sbin/honeyman-postgres-backup.sh
install -m 0644 -o root -g root "$OPS/honeyman-backup.cron" /etc/cron.d/honeyman-backup
install -m 0644 -o root -g root "$OPS/honeyman.logrotate" /etc/logrotate.d/honeyman
install -m 0755 -o root -g root "$OPS/healthcheck.sh" /usr/local/sbin/honeyman-healthcheck.sh
install -m 0644 -o root -g root "$OPS/honeyman-healthcheck.service" /etc/systemd/system/honeyman-healthcheck.service
install -m 0644 -o root -g root "$OPS/honeyman-healthcheck.timer" /etc/systemd/system/honeyman-healthcheck.timer

echo "--- installed ---"
ls -l /usr/local/sbin/honeyman-postgres-backup.sh \
      /usr/local/sbin/honeyman-healthcheck.sh \
      /etc/cron.d/honeyman-backup \
      /etc/logrotate.d/honeyman \
      /etc/systemd/system/honeyman-healthcheck.service \
      /etc/systemd/system/honeyman-healthcheck.timer

echo "--- cron service status ---"
systemctl is-active cron || systemctl is-active crond || true
systemctl reload cron 2>/dev/null || systemctl restart cron 2>/dev/null || systemctl restart crond 2>/dev/null || true
echo "done step 1"
