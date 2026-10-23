#!/usr/bin/env bash
# Check the host and install.conf before anything is installed. Changes nothing.
. "$(dirname "$0")/lib.sh"
require_root

problems=0
bad() { fail "$1"; problems=$((problems + 1)); }

step 'Host'
. /etc/os-release
if [ "${ID:-}" = "ubuntu" ]; then
  case "${VERSION_ID:-}" in
    22.04|24.04) ok "Ubuntu $VERSION_ID" ;;
    *) warn "Ubuntu $VERSION_ID is untested (22.04 and 24.04 are supported)." ;;
  esac
else
  bad "Not Ubuntu (found ${PRETTY_NAME:-unknown})."
fi
case "$(uname -m)" in
  x86_64|aarch64) ok "Architecture $(uname -m)" ;;
  *) bad "Architecture $(uname -m) has no wheels in requirements.lock." ;;
esac
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
[ "$mem_mb" -ge 1800 ] && ok "Memory ${mem_mb} MB" || warn "Memory ${mem_mb} MB (2 GB or more recommended)."
disk_gb=$(df -Pm / | awk 'NR==2 {print int($4/1024)}')
[ "$disk_gb" -ge 10 ] && ok "Free disk ${disk_gb} GB" || warn "Free disk ${disk_gb} GB (10 GB or more recommended)."
systemctl --version >/dev/null 2>&1 && ok 'systemd present' || bad 'systemd is required.'

step 'install.conf'
case "$APP_ENV" in
  local|test|staging|production) ok "APP_ENV=$APP_ENV" ;;
  *) bad "APP_ENV must be local, test, staging or production (got '$APP_ENV')." ;;
esac
case "$TLS_MODE" in
  letsencrypt|selfsigned|external|none) ok "TLS_MODE=$TLS_MODE" ;;
  *) bad "TLS_MODE must be letsencrypt, selfsigned, external or none (got '$TLS_MODE')." ;;
esac
if [ "$TLS_MODE" != "none" ] && [ -z "$DOMAIN" ]; then bad 'DOMAIN is required unless TLS_MODE=none.'; fi
if [ "$TLS_MODE" = "external" ]; then
  [ -n "$EXTRA_TRUSTED_PROXY_IPS" ] \
    || bad 'EXTRA_TRUSTED_PROXY_IPS (the IP your nginx connects from) is required for TLS_MODE=external.'
  case "$APP_BIND_HOST" in
    127.0.0.1|::1|localhost) warn "APP_BIND_HOST=$APP_BIND_HOST: nginx outside this container cannot reach a loopback-only API." ;;
    *) ok "API will listen on $APP_BIND_HOST:$APP_PORT for your nginx (https://$DOMAIN)" ;;
  esac
fi
if [ "$TLS_MODE" = "letsencrypt" ]; then
  [ -n "$LETSENCRYPT_EMAIL" ] || bad 'LETSENCRYPT_EMAIL is required for TLS_MODE=letsencrypt.'
  is_ip "$DOMAIN" && bad "Let's Encrypt does not issue certificates for an IP address; use TLS_MODE=selfsigned."
  if ! is_ip "$DOMAIN"; then
    resolved="$(getent ahostsv4 "$DOMAIN" | awk 'NR==1 {print $1}')"
    if [ -z "$resolved" ]; then warn "$DOMAIN does not resolve yet; certificate issuance will fail until it does."
    else ok "$DOMAIN resolves to $resolved"; fi
  fi
fi
if [ "$APP_ENV" != "local" ]; then
  [ -n "$OUTBOUND_ALLOWED_HOSTS" ] || bad 'OUTBOUND_ALLOWED_HOSTS is required unless APP_ENV=local (Rule 14).'
fi
if [ "$APP_ENV" = "production" ] && [[ ",$OUTBOUND_ALLOWED_HOSTS," == *",*,"* ]]; then
  bad "OUTBOUND_ALLOWED_HOSTS='*' is refused in production."
fi
[ "${#BRAND_NAME}" -le 12 ] || bad 'BRAND_NAME is longer than 12 characters.'
[[ "$UVICORN_WORKERS" =~ ^[1-9][0-9]*$ ]] || bad 'UVICORN_WORKERS must be a positive integer.'
[[ "$BACKUP_KEEP_DAYS" =~ ^[1-9][0-9]*$ ]] || bad 'BACKUP_KEEP_DAYS must be a positive integer.'
[[ "$DB_NAME" =~ ^[a-z_][a-z0-9_]*$ && "$DB_USER" =~ ^[a-z_][a-z0-9_]*$ ]] \
  || bad 'DB_NAME and DB_USER must be lower-case identifiers.'

step 'Ports'
listening() { ss -Hltn "sport = :$1" 2>/dev/null | grep -q .; }
owner_of() { ss -Hltnp "sport = :$1" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -n 1; }
for port in "$APP_PORT" $(local_nginx && echo 80 443); do
  if listening "$port"; then
    who="$(owner_of "$port")"
    case "$who" in
      nginx|uvicorn|python*) ok "Port $port held by $who (ours, re-run)" ;;
      *) bad "Port $port is already in use by ${who:-another process}." ;;
    esac
  else
    ok "Port $port free"
  fi
done

step 'Existing installation'
if [ -f "$ENV_FILE" ]; then
  warn "$ENV_FILE exists: its secrets are kept. This run upgrades in place."
else
  ok 'Fresh host.'
fi

if [ "$problems" -gt 0 ]; then printf '\n%s%s problem(s) - fix install.conf or the host first.%s\n' "$C_RED" "$problems" "$C_OFF"; exit 1; fi
printf '\n%sPreflight passed.%s\n' "$C_GREEN" "$C_OFF"
