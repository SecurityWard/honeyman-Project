#!/usr/bin/env bash
# Honeyman uptime probe.
#
# Hits the backend's /health endpoint and a public read endpoint. Logs
# success silently (syslog only); on failure, exits non-zero so a
# systemd timer's `OnFailure=` hook can fire — or you can wire it to a
# webhook (Discord/Slack/email) via the HEALTHCHECK_WEBHOOK env var.
#
# Intentionally simple: no external monitoring SaaS. If you want
# alerting, set HEALTHCHECK_WEBHOOK to a URL that accepts a POST with
# `{"status": "down", "host": "...", "detail": "..."}`.
#
# Designed to be called from honeyman-healthcheck.timer (see this dir).

set -uo pipefail

API_BASE="${API_BASE:-https://api.honeymanproject.com}"
DASH_BASE="${DASH_BASE:-https://dashboard.honeymanproject.com}"
TIMEOUT="${TIMEOUT:-10}"
WEBHOOK="${HEALTHCHECK_WEBHOOK:-}"
LOG_TAG="honeyman-healthcheck"

fail() {
    local detail="$1"
    logger -t "$LOG_TAG" -p user.err "DOWN: $detail"
    if [[ -n "$WEBHOOK" ]]; then
        # Best-effort notification — don't let curl's failure mask the
        # underlying health failure we're reporting.
        curl -fsS -m 5 -H 'Content-Type: application/json' \
             -d "{\"status\":\"down\",\"host\":\"$(hostname)\",\"detail\":\"$detail\"}" \
             "$WEBHOOK" >/dev/null 2>&1 || true
    fi
    exit 1
}

# 1. /health responds 200 and reports status=ok
body=$(curl -fsS -m "$TIMEOUT" "${API_BASE}/health" 2>/dev/null) \
    || fail "/health unreachable or non-2xx"

if ! echo "$body" | grep -q '"status":"ok"'; then
    fail "/health returned unexpected body: ${body:0:200}"
fi

# 2. A public read endpoint is reachable through nginx (catches the
#    "backend running but nginx misconfigured" failure mode).
if ! curl -fsS -m "$TIMEOUT" -o /dev/null "${API_BASE}/api/v2/sensors"; then
    fail "/api/v2/sensors unreachable"
fi

# 3. The dashboard SPA's root resolves to a real HTML body. Catches
#    the "frontend/dist/ missing or nginx pointed at the wrong dir"
#    failure mode that bit us during the directory-flatten migration:
#    /health stayed green because the API was fine, but the SPA itself
#    was a 500 cycle and nobody was alerted.
if ! curl -fsS -m "$TIMEOUT" "${DASH_BASE}/" 2>/dev/null | grep -q '<title'; then
    fail "${DASH_BASE}/ did not return an HTML page (likely frontend/dist/ missing or nginx misrouted)"
fi

logger -t "$LOG_TAG" "ok"
