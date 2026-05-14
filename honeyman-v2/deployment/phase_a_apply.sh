#!/bin/bash
# Honeyman V2 Phase A apply script
#
# Run AS ROOT on the VPS (72.60.25.24) where the dashboard backend lives.
# Idempotent — safe to re-run after fixing a step that failed.
#
# What it does, in order:
#   1) Probes the existing layout (paths, services, Postgres version)
#   2) Installs TimescaleDB extension package + tunes Postgres
#   3) Creates a safety pg_dump of the current honeyman_v2 DB
#   4) Pulls the latest cleanup-PR code into the existing checkout
#   5) DROPs the old schema + re-runs alembic upgrade head
#   6) Syncs the backend .env to V2 settings
#   7) Restarts the backend systemd unit
#   8) Smoke-tests the API: register a fake sensor, push one threat
#   9) Prints a summary
#
# Usage:
#   curl -sSL https://transfer.sh/whatever/phase_a_apply.sh -o /root/phase_a_apply.sh
#   bash /root/phase_a_apply.sh 2>&1 | tee /root/phase_a_apply.log
#
# Or if you'd rather paste it:
#   nano /root/phase_a_apply.sh   # paste, save
#   bash /root/phase_a_apply.sh 2>&1 | tee /root/phase_a_apply.log
#
# After it finishes, send me /root/phase_a_apply.log so I can diagnose anything that didn't pass.

set -uo pipefail
LOG_PREFIX="[honeyman-phase-a]"
START_TS=$(date -Iseconds)

# -------- Tunables (override via env) --------
BACKEND_DIR="${BACKEND_DIR:-/root/honeyman-Project/honeyman-v2/dashboard-v2/backend}"
REPO_DIR="${REPO_DIR:-/root/honeyman-Project}"          # parent git checkout (if it exists)
DB_NAME="${DB_NAME:-honeyman_v2}"
DB_USER="${DB_USER:-honeyman}"
SERVICE_NAME="${SERVICE_NAME:-}"                          # autodetected if blank
PUBLIC_API_BASE_URL="${PUBLIC_API_BASE_URL:-http://72.60.25.24:8000}"
PG_BACKUP_PATH="/root/honeyman_v2_pre_phase_a_$(date +%Y%m%d_%H%M%S).sql.gz"
SMOKE_SENSOR_NAME="phase-a-smoke"

c_red()   { printf '\033[0;31m%s\033[0m' "$*"; }
c_grn()   { printf '\033[0;32m%s\033[0m' "$*"; }
c_yel()   { printf '\033[1;33m%s\033[0m' "$*"; }
c_cyn()   { printf '\033[0;36m%s\033[0m' "$*"; }

step()  { echo; echo "$(c_cyn "$LOG_PREFIX") $(c_cyn "==>") $*"; }
ok()    { echo "  $(c_grn "[OK]")   $*"; }
skip()  { echo "  $(c_yel "[SKIP]") $*"; }
warn()  { echo "  $(c_yel "[WARN]") $*"; }
fail()  { echo "  $(c_red "[FAIL]") $*" >&2; }
die()   { fail "$1"; echo; echo "Aborting at: $(date -Iseconds)" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || die "Must run as root"
}

probe_environment() {
    step "Probing environment"
    echo "  hostname: $(hostname)"
    echo "  uname:    $(uname -srm)"
    echo "  date:     $(date -Iseconds)"

    # Postgres
    if command -v psql >/dev/null 2>&1; then
        PG_FULL_VER="$(psql --version 2>/dev/null)"
        PG_MAJOR="$(echo "$PG_FULL_VER" | awk '{print $3}' | cut -d. -f1)"
        echo "  postgres: $PG_FULL_VER  (major=$PG_MAJOR)"
    else
        die "psql not on PATH — PostgreSQL not installed?"
    fi

    # Backend dir
    if [[ -d "$BACKEND_DIR" ]]; then
        ok "backend dir: $BACKEND_DIR"
    else
        warn "backend dir missing: $BACKEND_DIR"
        # Try to find it
        FOUND=$(find /root /opt /srv -maxdepth 5 -type d -name backend 2>/dev/null \
                  | xargs -I{} bash -c 'test -f "{}/app/main.py" && echo {}' \
                  | head -1)
        if [[ -n "$FOUND" ]]; then
            BACKEND_DIR="$FOUND"
            ok "found backend at: $BACKEND_DIR"
        else
            die "Could not locate backend dir; set BACKEND_DIR=... and retry"
        fi
    fi

    # venv inside backend dir
    if [[ -x "$BACKEND_DIR/venv/bin/python" ]]; then
        VENV_PY="$BACKEND_DIR/venv/bin/python"
        ok "venv: $BACKEND_DIR/venv"
    elif [[ -x "$BACKEND_DIR/.venv/bin/python" ]]; then
        VENV_PY="$BACKEND_DIR/.venv/bin/python"
        ok "venv: $BACKEND_DIR/.venv"
    else
        warn "no venv at $BACKEND_DIR/{venv,.venv} — will use system python"
        VENV_PY="$(command -v python3)"
    fi

    # Repo for git pull
    if [[ -d "$REPO_DIR/.git" ]]; then
        ok "git checkout: $REPO_DIR"
    elif [[ -d "$BACKEND_DIR/../../../.git" ]]; then
        REPO_DIR="$(realpath "$BACKEND_DIR/../../..")"
        ok "git checkout: $REPO_DIR (derived from backend)"
    else
        warn "no git checkout found at $REPO_DIR — code-pull step will be skipped"
        REPO_DIR=""
    fi

    # systemd service
    if [[ -z "$SERVICE_NAME" ]]; then
        for cand in honeyman-backend honeyman-api honeyman-dashboard honeyman; do
            if systemctl list-unit-files "${cand}.service" >/dev/null 2>&1 \
                && systemctl cat "${cand}.service" >/dev/null 2>&1; then
                SERVICE_NAME="$cand"
                break
            fi
        done
    fi
    if [[ -n "$SERVICE_NAME" ]]; then
        ok "service:  $SERVICE_NAME"
    else
        warn "no honeyman backend systemd service found — will skip restart step"
    fi
}

install_timescaledb() {
    step "Install TimescaleDB extension package (PG${PG_MAJOR})"
    PKG="timescaledb-2-postgresql-${PG_MAJOR}"
    if dpkg -s "$PKG" >/dev/null 2>&1; then
        ok "$PKG already installed"
    else
        # Add the timescale repo if it's not there
        if [[ ! -f /etc/apt/sources.list.d/timescaledb.list ]]; then
            apt-get install -y -qq gnupg postgresql-common apt-transport-https lsb-release wget >/dev/null
            CODENAME="$(lsb_release -cs)"
            DISTRO="$(lsb_release -is | tr '[:upper:]' '[:lower:]')"
            echo "deb https://packagecloud.io/timescale/timescaledb/${DISTRO}/ ${CODENAME} main" \
                > /etc/apt/sources.list.d/timescaledb.list
            wget --quiet -O - https://packagecloud.io/timescale/timescaledb/gpgkey \
                | gpg --dearmor -o /etc/apt/trusted.gpg.d/timescaledb.gpg
            apt-get update -qq
            ok "added timescaledb apt repo"
        fi
        apt-get install -y -qq "$PKG" || die "apt install $PKG failed"
        ok "installed $PKG"
    fi

    # Tune Postgres for TimescaleDB (idempotent — won't double-tune)
    if grep -q "timescaledb-tune" /etc/postgresql/${PG_MAJOR}/main/postgresql.conf 2>/dev/null; then
        skip "timescaledb-tune already applied"
    else
        timescaledb-tune --quiet --yes >/dev/null 2>&1 || warn "timescaledb-tune returned non-zero"
        ok "ran timescaledb-tune"
    fi

    systemctl restart postgresql || die "could not restart postgresql"
    sleep 2
    systemctl is-active --quiet postgresql || die "postgresql did not come back up"
    ok "postgresql restarted"

    # Enable extension in our DB
    sudo -u postgres psql -d "$DB_NAME" -c "CREATE EXTENSION IF NOT EXISTS timescaledb;" >/dev/null \
        || die "CREATE EXTENSION timescaledb failed"
    EXT_VER=$(sudo -u postgres psql -d "$DB_NAME" -tAc "SELECT extversion FROM pg_extension WHERE extname='timescaledb';")
    ok "timescaledb extension enabled (version $EXT_VER)"
}

backup_db() {
    step "pg_dump current $DB_NAME for safety -> $PG_BACKUP_PATH"
    sudo -u postgres pg_dump "$DB_NAME" 2>/dev/null | gzip > "$PG_BACKUP_PATH" \
        || die "pg_dump failed"
    SIZE=$(du -h "$PG_BACKUP_PATH" | awk '{print $1}')
    ok "backup written: $PG_BACKUP_PATH ($SIZE)"
}

pull_code() {
    step "Pull latest cleanup-PR code"
    if [[ -z "$REPO_DIR" ]]; then
        skip "no git checkout located — assuming code is already current"
        return
    fi
    cd "$REPO_DIR"
    BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
    BEFORE=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
    if git diff --quiet && git diff --cached --quiet; then
        git fetch --quiet || warn "git fetch failed"
        git pull --quiet --ff-only || warn "git pull --ff-only failed (local divergence?)"
        AFTER=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
        if [[ "$BEFORE" == "$AFTER" ]]; then
            ok "branch=$BRANCH already at $AFTER"
        else
            ok "branch=$BRANCH advanced $BEFORE -> $AFTER"
        fi
    else
        warn "uncommitted changes in $REPO_DIR — skipping pull, using current tree"
    fi
}

reset_schema() {
    step "Reset DB schema to V2 (DROP + alembic upgrade head)"
    # Drop the old tables. CASCADE handles FKs and the materialized view.
    sudo -u postgres psql -d "$DB_NAME" >/dev/null <<'SQL'
DROP MATERIALIZED VIEW IF EXISTS threat_stats_hourly CASCADE;
DROP TABLE IF EXISTS threats CASCADE;
DROP TABLE IF EXISTS sensors CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS alembic_version;
DROP TYPE IF EXISTS userrole;
SQL
    ok "old tables dropped"

    # Run alembic from the backend dir, using its venv if available
    cd "$BACKEND_DIR"
    if [[ -f .env ]]; then
        # Pull DATABASE_URL into env so alembic env.py can see it
        export $(grep -E '^DATABASE_URL=' .env | head -1 | xargs)
    fi
    "$VENV_PY" -m alembic upgrade head || die "alembic upgrade head failed — see logs above"
    ok "alembic upgrade head succeeded"

    # Verify
    HYP=$(sudo -u postgres psql -d "$DB_NAME" -tAc "SELECT count(*) FROM timescaledb_information.hypertables WHERE hypertable_name='threats';")
    [[ "$HYP" == "1" ]] && ok "threats is a hypertable" || warn "threats hypertable not detected"

    SENSORS_COL=$(sudo -u postgres psql -d "$DB_NAME" -tAc "SELECT count(*) FROM information_schema.columns WHERE table_name='sensors' AND column_name='api_key_hash';")
    [[ "$SENSORS_COL" == "1" ]] && ok "sensors.api_key_hash present" || warn "sensors.api_key_hash NOT present"

    USERS=$(sudo -u postgres psql -d "$DB_NAME" -tAc "SELECT to_regclass('public.users');")
    if [[ "$USERS" == "" || "$USERS" == "(null)" || "$USERS" == "" ]]; then
        ok "users table absent (V2 has no accounts)"
    else
        warn "users table still present: $USERS"
    fi
}

sync_env() {
    step "Sync backend .env to V2 settings"
    ENV_FILE="$BACKEND_DIR/.env"
    EXAMPLE="$BACKEND_DIR/.env.example"
    if [[ ! -f "$ENV_FILE" ]]; then
        if [[ -f "$EXAMPLE" ]]; then
            cp "$EXAMPLE" "$ENV_FILE"
            ok "no .env existed; copied .env.example -> .env (you'll need to edit DATABASE_URL etc)"
        else
            die ".env missing and no .env.example to bootstrap from"
        fi
    fi

    cp "$ENV_FILE" "${ENV_FILE}.pre_phase_a"
    ok "backed up to ${ENV_FILE}.pre_phase_a"

    # Drop JWT-era keys
    sed -i \
        -e '/^SECRET_KEY=/d' \
        -e '/^ACCESS_TOKEN_EXPIRE_MINUTES=/d' \
        -e '/^REFRESH_TOKEN_EXPIRE_DAYS=/d' \
        -e '/^ALGORITHM=/d' \
        "$ENV_FILE"

    # Ensure required V2 keys are present (append if missing)
    grep -q '^MQTT_OFFERED='        "$ENV_FILE" || echo "MQTT_OFFERED=false"                          >> "$ENV_FILE"
    grep -q '^PUBLIC_API_BASE_URL=' "$ENV_FILE" || echo "PUBLIC_API_BASE_URL=$PUBLIC_API_BASE_URL"   >> "$ENV_FILE"

    ok ".env updated (JWT keys removed, MQTT_OFFERED + PUBLIC_API_BASE_URL ensured)"
}

restart_backend() {
    step "Restart backend service"
    if [[ -z "$SERVICE_NAME" ]]; then
        skip "no systemd service identified — restart manually and re-run"
        return
    fi
    systemctl restart "$SERVICE_NAME" || die "systemctl restart $SERVICE_NAME failed"
    sleep 4
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        ok "$SERVICE_NAME is active"
    else
        warn "$SERVICE_NAME failed to start cleanly"
        journalctl -u "$SERVICE_NAME" --no-pager -n 30 | sed 's/^/    /'
        die "backend did not start; see journal output above"
    fi

    # Look for the v2 startup log line
    if journalctl -u "$SERVICE_NAME" --no-pager -n 50 | grep -q 'started successfully'; then
        ok "backend reports 'started successfully'"
    fi
    if journalctl -u "$SERVICE_NAME" --no-pager -n 50 | grep -q 'MQTT_OFFERED=False'; then
        ok "backend correctly skipping MQTT subscriber"
    fi
}

smoke_test() {
    step "Smoke test: register fake sensor, push one threat"
    HEALTH=$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:8000/health" || echo 000)
    [[ "$HEALTH" == "200" ]] && ok "GET /health -> 200" || die "GET /health -> $HEALTH"

    REG_BODY=$(cat <<'JSON'
{
  "requested_name": "phase-a-smoke",
  "location_label": "Phase A smoke test",
  "capabilities":   {"usb": true},
  "enabled_detectors": ["usb"],
  "platform":       "linux",
  "agent_version":  "2.0.0",
  "initial_location": {"latitude": 37.7749, "longitude": -122.4194, "method": "manual", "accuracy": 100}
}
JSON
)
    REG_RESP=$(curl -sS -X POST "http://127.0.0.1:8000/api/v2/sensors/register" \
        -H 'Content-Type: application/json' --data "$REG_BODY")
    SENSOR_ID=$(echo "$REG_RESP" | "$VENV_PY" -c 'import json,sys; print(json.load(sys.stdin).get("sensor_id",""))' 2>/dev/null || echo "")
    API_KEY=$(echo "$REG_RESP"  | "$VENV_PY" -c 'import json,sys; print(json.load(sys.stdin).get("api_key",""))' 2>/dev/null || echo "")
    if [[ -z "$SENSOR_ID" || -z "$API_KEY" ]]; then
        fail "register response did not include sensor_id+api_key:"
        echo "$REG_RESP" | sed 's/^/    /'
        die "register endpoint broken"
    fi
    ok "registered sensor $SENSOR_ID (api_key=${API_KEY:0:12}...)"

    NOW="$(date -u +%Y-%m-%dT%H:%M:%S)"
    THREAT_BODY=$(cat <<JSON
{
  "timestamp":     "$NOW",
  "sensor_id":     "$SENSOR_ID",
  "threat_type":   "usb_rubber_ducky",
  "detector_type": "usb",
  "severity":      "critical",
  "threat_score":  0.95,
  "confidence":    0.98,
  "matched_rules": [{"rule_id": "smoke_test", "name": "Phase A smoke", "severity": "critical", "confidence": 0.98}],
  "raw_event":     {"vendor_id": "0x03eb", "product_id": "0x2401"},
  "latitude":      37.7749,
  "longitude":     -122.4194,
  "city":          "San Francisco",
  "country":       "US",
  "device_name":   "Smoke Test Ducky"
}
JSON
)
    THREAT_RESP=$(curl -sS -o /tmp/phase_a_threat.json -w '%{http_code}' \
        -X POST "http://127.0.0.1:8000/api/v2/threats" \
        -H "Authorization: Bearer $API_KEY" \
        -H 'Content-Type: application/json' --data "$THREAT_BODY")
    if [[ "$THREAT_RESP" == "200" || "$THREAT_RESP" == "201" ]]; then
        ok "POST /threats -> $THREAT_RESP (threat ingested)"
    else
        fail "POST /threats -> $THREAT_RESP"
        cat /tmp/phase_a_threat.json | sed 's/^/    /'
        die "threat ingest broken"
    fi

    # Verify it's there
    LISTED=$(curl -sS "http://127.0.0.1:8000/api/v2/threats?sensor_id=$SENSOR_ID" \
              | "$VENV_PY" -c 'import json,sys; d=json.load(sys.stdin); print(d.get("total",0))')
    [[ "$LISTED" == "1" ]] && ok "GET /threats?sensor_id=... -> total=1" \
        || warn "GET /threats?sensor_id=... -> total=$LISTED (expected 1)"

    SMOKE_SENSOR_ID="$SENSOR_ID"
    export SMOKE_SENSOR_ID
}

cleanup_smoke() {
    step "Clean up smoke-test sensor + threat from DB"
    if [[ -z "${SMOKE_SENSOR_ID:-}" ]]; then
        skip "no smoke sensor to clean"
        return
    fi
    sudo -u postgres psql -d "$DB_NAME" >/dev/null <<SQL
DELETE FROM threats WHERE sensor_id='${SMOKE_SENSOR_ID}';
DELETE FROM sensors WHERE sensor_id='${SMOKE_SENSOR_ID}';
SQL
    ok "removed smoke sensor and its threats"
}

summary() {
    echo
    echo "$(c_grn '=================================================================')"
    echo "$(c_grn '  Phase A apply complete')"
    echo "$(c_grn '=================================================================')"
    echo "  start: $START_TS"
    echo "  end:   $(date -Iseconds)"
    echo "  backup:    $PG_BACKUP_PATH"
    echo "  service:   ${SERVICE_NAME:-<none>}"
    echo "  log file:  /root/phase_a_apply.log (if you used 'tee')"
    echo
    echo "  Next: open the dashboard. The smoke test sensor + threat have been"
    echo "  removed; you should see an empty map. Then deploy a real Pi using"
    echo "  the install script in honeyman-v2/readme/onboarding/install.sh"
    echo "  and watch a real sensor appear."
    echo
}

main() {
    require_root
    probe_environment
    install_timescaledb
    backup_db
    pull_code
    reset_schema
    sync_env
    restart_backend
    smoke_test
    cleanup_smoke
    summary
}

main "$@"
