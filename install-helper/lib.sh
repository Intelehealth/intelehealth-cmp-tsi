# shellcheck shell=bash
# Shared helpers for the Ubuntu install scripts. Source it:
#   . "$(dirname "$0")/lib.sh"

set -euo pipefail

HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$HELPER_DIR")"
INSTALL_CONF="${INSTALL_CONF:-$HELPER_DIR/install.conf}"

if [ -t 1 ]; then
  C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_OFF=$'\033[0m'
else
  C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_OFF=''
fi
step() { printf '\n%s==> %s%s\n' "$C_CYAN" "$1" "$C_OFF"; }
ok()   { printf '  %s[ok]%s   %s\n' "$C_GREEN" "$C_OFF" "$1"; }
warn() { printf '  %s[warn]%s %s\n' "$C_YELLOW" "$C_OFF" "$1"; }
fail() { printf '  %s[FAIL]%s %s\n' "$C_RED" "$C_OFF" "$1"; }
die()  { fail "$1"; exit 1; }

require_root() { [ "$(id -u)" = "0" ] || die "Run as root: sudo bash $0"; }

[ -f "$REPO_ROOT/python_port/requirements.lock" ] && [ -d "$REPO_ROOT/db" ] \
  || die "Repository not found above $HELPER_DIR (expected python_port/ and db/)."

# Defaults, overridden by install.conf.
DOMAIN=""; TLS_MODE=letsencrypt; LETSENCRYPT_EMAIL=""; ALLOWED_ORIGINS=""; EXTRA_TRUSTED_PROXY_IPS=""
APP_ENV=production; OUTBOUND_ALLOWED_HOSTS=""; BRAND_NAME=""; UVICORN_WORKERS=2; APP_PORT=8080; APP_BIND_HOST=127.0.0.1
PG_VERSION=15; DB_NAME=tsi_cms; DB_USER=tsi_admin
APP_USER=tsi; INSTALL_DIR=/opt/tsi-cms; DATA_DIR=/var/lib/tsi-cms; CONF_DIR=/etc/tsi-cms; BACKUP_DIR=/var/backups/tsi-cms
BACKUP_TIME=02:30; BACKUP_KEEP_DAYS=35; ENABLE_UFW=yes; SSH_PORT=22

if [ -f "$INSTALL_CONF" ]; then
  # shellcheck disable=SC1090
  . "$INSTALL_CONF"
elif [ "${LIB_CONF_OPTIONAL:-0}" != "1" ]; then
  die "No $INSTALL_CONF. Copy install.conf.example to install.conf and edit it."
fi

ENV_FILE="$CONF_DIR/tsi-cms.env"
VENV="$INSTALL_DIR/venv"
EXPORT_DIR="$DATA_DIR/exports"
SCHEMA_MARKER="$DATA_DIR/.schema-initialised"
# Address the local scripts use to reach the API: loopback when uvicorn listens
# on loopback or every interface, otherwise the one address it binds.
case "$APP_BIND_HOST" in
  127.0.0.1|0.0.0.0|localhost) APP_URL="http://127.0.0.1:$APP_PORT" ;;
  ::|::1) APP_URL="http://[::1]:$APP_PORT" ;;
  *:*) APP_URL="http://[$APP_BIND_HOST]:$APP_PORT" ;;
  *) APP_URL="http://$APP_BIND_HOST:$APP_PORT" ;;
esac
# letsencrypt/selfsigned: this host runs nginx. external: your own nginx outside
# this host/container terminates TLS for https://$DOMAIN. none: no proxy at all.
local_nginx() { [ "$TLS_MODE" = letsencrypt ] || [ "$TLS_MODE" = selfsigned ]; }
SERVICES=(tsi-cms-app tsi-cms-worker)

new_secret() { openssl rand -hex 32; }

# env_get KEY [DEFAULT] - value from the service env file.
env_get() {
  local key="$1" default="${2:-}" value=""
  if [ -f "$ENV_FILE" ]; then
    value="$(grep -E "^${key}=" "$ENV_FILE" | tail -n 1 | cut -d= -f2-)" || true
  fi
  if [ -n "$value" ]; then printf '%s' "$value"; else printf '%s' "$default"; fi
}

# env_set KEY VALUE - replace or append KEY in the service env file.
env_set() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  if grep -qE "^${key}=" "$ENV_FILE"; then
    awk -v k="$key" -v v="$value" 'BEGIN{FS=OFS="="} $1==k {print k "=" v; next} {print}' "$ENV_FILE" > "$tmp"
  else
    cat "$ENV_FILE" > "$tmp"; printf '%s=%s\n' "$key" "$value" >> "$tmp"
  fi
  cat "$tmp" > "$ENV_FILE"; rm -f "$tmp"
}

# env_set_default KEY VALUE - set KEY only when missing or empty (never rotates secrets).
env_set_default() { [ -n "$(env_get "$1")" ] || env_set "$1" "$2"; }

# Port of the Postgres cluster for PG_VERSION (5432 unless another cluster holds it).
pg_port() {
  pg_lsclusters --no-header 2>/dev/null | awk -v v="$PG_VERSION" '$1==v && $2=="main" {print $3; exit}'
}

# psql_super [psql args...] - superuser psql in the application database.
psql_super() { (cd / && sudo -u postgres psql -X -v ON_ERROR_STOP=1 -p "$(pg_port)" "$@"); }

# psql_q "SQL" - one statement as superuser, unaligned tuples-only output.
psql_q() { psql_super -d "$DB_NAME" -tA -c "$1"; }

# psql_owner [psql args...] - psql as the schema owner over TLS, with the
# encryption keys set for this session only (never stored in the database).
psql_owner() {
  local options="-c app.enc_key=$(env_get DB_ENCRYPTION_KEY)"
  local lookup; lookup="$(env_get PII_LOOKUP_KEY)"
  [ -z "$lookup" ] || options="$options -c app.lookup_key=$lookup"
  options="$options ${PSQL_EXTRA_OPTIONS:-}"
  PGPASSWORD="$(env_get POSTGRES_PASSWD)" PGOPTIONS="$options" PGSSLMODE=require \
    psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$(pg_port)" -U "$DB_USER" -d "$DB_NAME" "$@"
}

wait_healthy() {
  local timeout="${1:-120}" waited=0
  while [ "$waited" -lt "$timeout" ]; do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$APP_URL/healthz" || true)" = "200" ] && return 0
    sleep 3; waited=$((waited + 3))
  done
  return 1
}

# api_post PATH JSON [extra curl args...] - sets $API_STATUS and $API_BODY.
# Call it directly, not in $(...): a subshell would lose both variables.
API_STATUS=0; API_BODY=""
api_post() {
  local path="$1" body="$2"; shift 2
  local tmp; tmp="$(mktemp)"
  API_STATUS="$(curl -s -o "$tmp" -w '%{http_code}' --max-time 20 -X POST "$APP_URL$path" \
    -H 'Content-Type: application/json' "$@" --data "$body" || true)"
  API_BODY="$(cat "$tmp")"; rm -f "$tmp"
}

json_str() { sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -n 1; }
json_raw() { sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\([a-z0-9.]*\).*/\1/p" | head -n 1; }
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

is_ip() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$1" == *:* ]]; }
