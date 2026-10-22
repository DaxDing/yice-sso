#!/usr/bin/env bash
# Deploy yice-sso to one systemd host over SSH. Touches only /opt/yice/yice-sso, its own systemd units
# (service + probe timer), logrotate file and port 8773; never restarts or reconfigures another
# service, nginx included (the /sso location is a separate host-config step).
#
# Each deploy builds a fresh release directory with its own venv, self-checks it, then switches the
# `current` symlink. If the restarted service is not healthy it switches back to the previous
# release and restarts that; a failure before the switch leaves the live release untouched.
#
# Usage: SSO_DEPLOY_HOST=root@<host> deploy/deploy.sh            dry-run: remote state, file changes vs current, tokens
#        SSO_DEPLOY_HOST=root@<host> deploy/deploy.sh --execute  test, build release, generate missing caller tokens,
#                                                               switch, read back
# Exit:  0 PASS · 1 FAIL (rolled back when a previous release exists) · 2 usage · 3 BLOCKED (nothing switched)
set -euo pipefail

BASE=/opt/yice/yice-sso
PORT=8773
KEEP=3
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

case "${1:-}" in
  "") MODE=dry-run ;;
  --execute) MODE=execute ;;
  -h | --help) sed -n '2,13p' "$0"; exit 0 ;;
  *) echo "usage: deploy/deploy.sh [--execute]" >&2; exit 2 ;;
esac
HOST="${SSO_DEPLOY_HOST:-}"
if [[ -z "$HOST" ]]; then
  echo "usage: SSO_DEPLOY_HOST=root@<host> deploy/deploy.sh [--execute]  (the server that runs yice-sso)" >&2; exit 2
fi

SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST")
# --no-owner/--no-group: files land root-owned instead of carrying the laptop's uid onto the host.
RSYNC=(rsync -az --delete --itemize-changes --no-owner --no-group
  --exclude .env --exclude '.env.*' --exclude .venv/ --exclude output/
  --exclude test/ --exclude tests/ --exclude __pycache__/ --exclude '*.pyc'
  --exclude .pytest_cache/ --exclude .ruff_cache/ --exclude .DS_Store --exclude /REVISION --exclude /publish/)

step() { printf '== %s\n' "$*"; }

step "remote preflight (read-only)"
"${SSH[@]}" bash -s -- "$BASE" "$PORT" <<'PREFLIGHT'
set -u
base=$1 port=$2
listener=$(ss -ltnpH "sport = :$port" 2>/dev/null || true)
active=$(systemctl is-active yice-sso 2>/dev/null || true)
echo "port_$port: ${listener:-free}"
echo "unit_active: ${active:-absent}"
if [ -n "$listener" ] && [ "$active" != "active" ]; then
  echo "BLOCKED: port $port is held by another process"; exit 3
fi
echo "env_file: $([ -f "$base/.env" ] && stat -c '%a' "$base/.env" || echo missing)"
echo "current: $(readlink "$base/current" 2>/dev/null || echo none)"
echo "releases: $(ls -1 "$base/releases" 2>/dev/null | wc -l)"
echo "python3.11: $(command -v python3.11 || echo missing)"
PREFLIGHT

if [[ "$MODE" == dry-run ]]; then
  step "file changes vs current release (dry-run)"
  "${RSYNC[@]}" --dry-run "$ROOT/" "$HOST:$BASE/current/" 2>/dev/null || echo "(no current release: first deploy)"
  step "caller tokens to generate (dry-run; key names only)"
  "${SSH[@]}" bash -s -- "$BASE/.env" <<'KEYS' | python3 "$ROOT/deploy/ensure_tokens.py" --callers "$ROOT/config/callers.v1.json" --env-keys -
sed -nE "/^(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=(''|\"\")?[[:space:]]*$/d; s/^(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=.*/\2/p" "$1" 2>/dev/null
KEYS
  echo "DRY-RUN: nothing changed; rerun with --execute"
  exit 0
fi

step "local gate"
if [[ -n "$(git -C "$ROOT" status --porcelain -- .)" ]]; then
  echo "FAIL: uncommitted changes under $ROOT; deploy only committed code"; exit 1
fi
REVISION="$(git -C "$ROOT" rev-parse HEAD)"
RELEASE="${REVISION:0:12}-$(date -u +%Y%m%dT%H%M%SZ)"
(cd "$ROOT" && uv run --locked pytest -q -p no:cacheprovider) || { echo "FAIL: tests"; exit 1; }

step "upload release $RELEASE"
"${SSH[@]}" "mkdir -p '$BASE/releases/$RELEASE'"
"${RSYNC[@]}" "$ROOT/" "$HOST:$BASE/releases/$RELEASE/" >/dev/null
"${SSH[@]}" "printf '%s\n' '$REVISION' > '$BASE/releases/$RELEASE/REVISION'"

step "build, check, switch, read back"
set +e
"${SSH[@]}" bash -s -- "$BASE" "$RELEASE" "$PORT" "$KEEP" <<'INSTALL'
set -euo pipefail
base=$1 release=$2 port=$3 keep=$4
dir="$base/releases/$release"
discard() { rm -rf "$dir"; }
# The sandboxed DynamicUser must traverse these, whatever umask created them.
install -d -m 755 -o root -g root "$base" "$base/releases"
chmod 755 "$dir"
if [ ! -f "$base/.env" ]; then
  discard; echo "BLOCKED: $base/.env missing; create it from deploy/production.env.example (chmod 600)"; exit 3
fi
chmod 600 "$base/.env"
# Enabled declared callers without a token get one appended; values never leave this host.
if ! tokens=$(/usr/bin/python3.11 "$dir/deploy/ensure_tokens.py" --callers "$dir/config/callers.v1.json" \
    --env "$base/.env" --execute); then
  discard; echo "BLOCKED: caller tokens: $tokens; live release untouched"; exit 3
fi
echo "caller tokens: $tokens"
# The venv is built in place: venvs are not relocatable, and this path is final once switched.
if ! { /usr/bin/python3.11 -m venv "$dir/.venv" \
    && "$dir/.venv/bin/python" -m pip install -q --disable-pip-version-check -r "$dir/requirements.txt"; }; then
  discard; echo "BLOCKED: dependency install failed; live release untouched"; exit 3
fi
# Same runtime environment as the unit, checked before anything is switched.
if ! (cd "$dir" && set -a && . "$base/.env" && set +a \
    && SSO_ENV_FILE=/dev/null SSO_HOST=0.0.0.0 SSO_ACCESS_LOG_PATH=/var/log/yice-sso/access.jsonl \
       .venv/bin/python -m sso_service.cli --self-check); then
  discard; echo "BLOCKED: self-check failed; live release untouched"; exit 3
fi

install_host_files() {  # $1 = release dir; returns 0 and sets reload when a unit changed
  local src=$1/deploy unit
  for unit in yice-sso.service yice-sso-probe.service yice-sso-probe.timer; do
    if ! cmp -s "$src/$unit" "/etc/systemd/system/$unit"; then
      install -m 644 "$src/$unit" "/etc/systemd/system/$unit"; reload=1
    fi
  done
  if ! cmp -s "$src/yice-sso.logrotate" /etc/logrotate.d/yice-sso; then
    install -m 644 "$src/yice-sso.logrotate" /etc/logrotate.d/yice-sso
  fi
}
switch_to() {  # atomic symlink swap
  ln -sfn "releases/$1" "$base/current.next" && mv -Tf "$base/current.next" "$base/current"
}
healthy() {
  local _
  for _ in $(seq 1 30); do
    if health=$(curl -fsS "http://127.0.0.1:$port/health" 2>/dev/null); then return 0; fi
    sleep 1
  done
  return 1
}

previous=$(basename "$(readlink "$base/current" 2>/dev/null || true)")
reload=0
switch_to "$release"
install_host_files "$dir"
logrotate -d /etc/logrotate.d/yice-sso >/dev/null 2>&1 || echo "WARN: logrotate config check failed"
# daemon-reload only re-reads unit files; it restarts nothing.
[ "$reload" = 1 ] && systemctl daemon-reload
systemctl enable -q yice-sso
# A unit that hit StartLimitBurst refuses restarts until its failed state is cleared.
systemctl reset-failed yice-sso 2>/dev/null || true
systemctl restart yice-sso
if ! healthy; then
  journalctl -u yice-sso -n 30 --no-pager || true
  if [ -n "$previous" ] && [ -d "$base/releases/$previous" ]; then
    reload=0
    switch_to "$previous"
    install_host_files "$base/releases/$previous"
    [ "$reload" = 1 ] && systemctl daemon-reload
    systemctl reset-failed yice-sso 2>/dev/null || true
    systemctl restart yice-sso
    if healthy; then
      echo "FAIL: $release unhealthy; rolled back to $previous (healthy)"
    else
      echo "FAIL: $release unhealthy; rolled back to $previous, which is ALSO unhealthy"
    fi
  else
    echo "FAIL: first release $release unhealthy; no previous release to roll back to"
  fi
  exit 1
fi
echo "health: $health"
systemctl show yice-sso -p ActiveState -p MainPID -p MemoryCurrent -p NRestarts
systemctl enable -q --now yice-sso-probe.timer
systemctl show yice-sso-probe.timer -p ActiveState -p NextElapseUSecRealtime
# Keep the live release plus the newest older ones for rollback.
# grep exits 1 when the new release is the only one; under pipefail that must not fail a healthy deploy.
ls -1t "$base/releases" | { grep -vx "$release" || true; } | tail -n +"$keep" | while read -r old; do
  rm -rf "$base/releases/$old"
done
echo "current: $(readlink "$base/current")"
INSTALL
code=$?
set -e
case "$code" in
  0) echo "PASS: deployed $REVISION as $RELEASE" ;;
  3) echo "BLOCKED"; exit 3 ;;
  *) echo "FAIL"; exit 1 ;;
esac
