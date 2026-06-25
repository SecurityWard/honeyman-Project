set -uo pipefail
echo "--- which cron ---"
which crontab cron crond 2>&1 || true
echo "--- systemctl list-unit-files | grep cron ---"
systemctl list-unit-files | grep -Ei '(^|/)cron|crond' || echo "(no cron units)"
echo "--- dpkg cron ---"
dpkg -l | grep -E '^ii\s+cron' 2>&1 || echo "(cron not installed via dpkg)"
echo "--- /etc/crontab present? ---"
ls -l /etc/crontab 2>&1 || true
echo "--- existing systemd timers ---"
systemctl list-timers --all --no-pager 2>&1 | head -30
