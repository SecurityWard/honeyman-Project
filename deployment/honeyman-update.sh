#!/usr/bin/env bash
# Update an installed Honeyman sensor in one step:
#   pull the latest source, sync detection rules + the malware-hash DB into
#   place, and restart the agent.
#
# The agent reads rules from /etc/honeyman/rules and the hash DB from
# /var/lib/honeyman — neither of which a plain `git pull` of the source
# tree touches. That gap meant rule fixes silently never reached sensors
# (operators kept seeing already-fixed false positives). This is the
# supported update path.
#
# Installed to /usr/local/sbin/honeyman-update by install.sh. Run:
#   sudo honeyman-update
#
# Locally-customised rules are preserved: if a marker file exists next to a
# rule in /etc/honeyman/rules (e.g. usb/badusb_detection.yaml.local), that
# rule is left untouched — same contract as central rule_sync.

set -uo pipefail

SRC="${HONEYMAN_SRC:-/opt/honeyman/src}"
RULES_DIR="${HONEYMAN_RULES_DIR:-/etc/honeyman/rules}"
DATA_DIR="${HONEYMAN_DATA_DIR:-/var/lib/honeyman}"
SERVICE="${HONEYMAN_SERVICE:-honeyman-agent}"

fail() { echo "honeyman-update: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "must run as root (try: sudo honeyman-update)"
[[ -d "$SRC/.git" ]] || fail "no source checkout at $SRC — reinstall with the install script"

echo "==> Fetching latest source in $SRC"
# The installer makes a shallow clone; fetch + reset to the upstream tip
# updates it reliably (plain `pull --ff-only` can be awkward on shallow
# clones). The source tree isn't meant to be hand-edited — rule
# customisation lives in /etc/honeyman/rules — so a hard reset is safe.
git -C "$SRC" fetch --quiet origin || fail "git fetch failed (no network?)"
git -C "$SRC" reset --hard '@{u}' --quiet || fail "git reset to upstream failed"

echo "==> Syncing rules into $RULES_DIR (preserving *.yaml.local)"
synced=0; preserved=0
while IFS= read -r -d '' src_rule; do
    rel="${src_rule#"$SRC"/agent/rules/}"
    dst="$RULES_DIR/$rel"
    if [[ -f "${dst}.local" ]]; then
        preserved=$((preserved + 1))
        continue
    fi
    mkdir -p "$(dirname "$dst")"
    cp "$src_rule" "$dst"
    synced=$((synced + 1))
done < <(find "$SRC/agent/rules" -name '*.yaml' -print0)
echo "    $synced synced, $preserved preserved (.local override)"

echo "==> Syncing malware-hash DB into $DATA_DIR"
if [[ -f "$SRC/data/malware_hashes.db" ]]; then
    install -m 0644 "$SRC/data/malware_hashes.db" "$DATA_DIR/malware_hashes.db"
    echo "    malware_hashes.db updated"
else
    echo "    (no malware_hashes.db in source — skipped)"
fi

echo "==> Restarting $SERVICE"
systemctl restart "$SERVICE" || fail "could not restart $SERVICE"

echo "Done. Sensor updated and agent restarted."
