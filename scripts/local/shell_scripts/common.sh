# Shared helpers for the local deployment shell scripts. Source it:
#   . "$(dirname "$0")/common.sh"
# Works in bash on Linux, macOS and Git Bash / MSYS on Windows.

set -euo pipefail

# Git Bash rewrites arguments that look like POSIX paths (/docker-entrypoint-initdb.d/...)
# into Windows paths before docker sees them. Turn that off for every docker call.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"
APP_URL="${APP_URL:-http://localhost:8091}"

# Migrations an EXISTING database must receive (fresh volumes run all of db/ at init).
UPGRADE_MIGRATIONS=(
  13_breach_notification_deadline.sql
  14_nomination_data_correction.sql
  15_p1_consent_lifecycle_alerts.sql
  16_p2_roles_mfa_retention.sql
  17_defect_fixes.sql
  18_brd_traceability.sql
  19_audit_ledger_integrity.sql
)
REQUIRED_SECRETS=(JWT_SECRET DB_ENCRYPTION_KEY TSI_LOOKUP_SALT BOOTSTRAP_TOKEN)
CONTAINER_NAMES=(tsi_dpdp_cms_py_db tsi_dpdp_cms_py_server tsi_dpdp_cms_py_worker)

if [ -t 1 ]; then
  C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_OFF=$'\033[0m'
else
  C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_OFF=''
fi
step() { printf '\n%s==> %s%s\n' "$C_CYAN" "$1" "$C_OFF"; }
ok()   { printf '  %s[ok]%s   %s\n' "$C_GREEN" "$C_OFF" "$1"; }
warn() { printf '  %s[warn]%s %s\n' "$C_YELLOW" "$C_OFF" "$1"; }
fail() { printf '  %s[FAIL]%s %s\n' "$C_RED" "$C_OFF" "$1"; }

# env_get KEY [DEFAULT] - value from .env (comments/blank lines skipped, quotes and CR stripped).
env_get() {
  local key="$1" default="${2:-}" value=""
  if [ -f "$ENV_FILE" ]; then
    value="$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- | tr -d '\r' \
      | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/")" || true
  fi
  if [ -n "$value" ]; then printf '%s' "$value"; else printf '%s' "$default"; fi
}

compose() { (cd "$REPO_ROOT" && docker compose "$@"); }

project_name() { compose config 2>/dev/null | sed -n 's/^name: *//p' | head -n 1; }

db_volume_exists() {
  local project; project="$(project_name)"
  [ -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$project" \
          --filter 'label=com.docker.compose.volume=postgres_py_data')" ]
}

# psql_q "SQL" - one statement in the postgres container, unaligned tuples-only output.
psql_q() {
  compose exec -T postgres_db psql -v ON_ERROR_STOP=1 \
    -U "$(env_get POSTGRES_USER tsi_admin)" -d "$(env_get POSTGRES_DB tsi_cms)" -tA -c "$1" | tr -d '\r'
}

wait_healthy() {
  local timeout="${1:-180}" waited=0
  while [ "$waited" -lt "$timeout" ]; do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$APP_URL/healthz" || true)" = "200" ]; then
      return 0
    fi
    sleep 3; waited=$((waited + 3))
  done
  return 1
}

# api_post PATH JSON [extra curl args...] - prints the body; HTTP status goes to $API_STATUS.
API_STATUS=0
api_post() {
  local path="$1" body="$2"; shift 2
  local tmp; tmp="$(mktemp)"
  API_STATUS="$(curl -s -o "$tmp" -w '%{http_code}' --max-time 20 -X POST "$APP_URL$path" \
    -H 'Content-Type: application/json' "$@" --data "$body" || true)"
  cat "$tmp"; rm -f "$tmp"
}

# json_str KEY < json - first string value of KEY (flat lookup; enough for these checks).
json_str() { sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -n 1; }
# json_raw KEY < json - first non-string value of KEY (true/false/number).
json_raw() { sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\([a-z0-9.]*\).*/\1/p" | head -n 1; }

# JSON-escape a string for embedding in a request body.
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
