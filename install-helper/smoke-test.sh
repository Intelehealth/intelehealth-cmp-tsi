#!/usr/bin/env bash
# Verify an installed host. Exits 1 on any failure.
# Usage: sudo bash smoke-test.sh [admin email]   (with an email it also signs in; password prompted)
. "$(dirname "$0")/lib.sh"
require_root
set +e  # run every check, then report
failures=0
check() { if [ "$2" = "0" ]; then ok "$1"; else fail "$1 ${3:-}"; failures=$((failures + 1)); fi; }
email="${1:-}"

step 'Services'
for unit in "postgresql@$PG_VERSION-main" "${SERVICES[@]}" tsi-cms-backup.timer; do
  systemctl is-active --quiet "$unit"; check "$unit active" "$?"
done
if local_nginx; then systemctl is-active --quiet nginx; check 'nginx active' "$?"; fi

step 'HTTP (loopback)'
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$APP_URL/healthz")"
[ "$code" = "200" ]; check '/healthz returns 200' "$?" "(got $code)"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "X-Health-Token: $(env_get HEALTHZ_TOKEN)" "$APP_URL/healthz/worker")"
[ "$code" = "200" ]; check '/healthz/worker returns 200 (worker heartbeat fresh)' "$?" "(got $code)"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$APP_URL/")"
[ "$code" = "200" ]; check 'Console page served' "$?" "(got $code)"
# CF-01: validator schemas must not be public.
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$APP_URL/WEB-INF/validator/erasure_request.jschema")"
[ "$code" = "404" ]; check 'WEB-INF is not served (404)' "$?" "(got $code)"
# P4-02: a mixed-case _func is normalised, never a validation bypass.
api_post /api/v1/client/consent '{"_func":"Erasure_Request"}'
[ "$API_STATUS" = "401" ] || [ "$API_STATUS" = "403" ]; check 'Mixed-case _func without credentials is refused' "$?" "(got $API_STATUS)"
if [ "$APP_ENV" != "local" ]; then
  # /docs falls through to the console page; what matters is that Swagger UI is not served.
  curl -s --max-time 10 "$APP_URL/docs" | grep -qi swagger
  [ "$?" -ne 0 ]; check 'Swagger UI hidden outside local' "$?"
  # The app still serves /openapi.json (only docs_url is disabled); nginx blocks it.
  if curl -s --max-time 10 "$APP_URL/openapi.json" | grep -q '"openapi"'; then
    warn 'App serves /openapi.json on loopback; only the nginx block keeps it off the network.'
  fi
fi

if local_nginx; then
  step "HTTPS ($DOMAIN)"
  k=""; [ "$TLS_MODE" = "selfsigned" ] && k="-k"
  code="$(curl -s $k -o /dev/null -w '%{http_code}' --max-time 10 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/healthz")"
  [ "$code" = "200" ]; check "https://$DOMAIN/healthz returns 200" "$?" "(got $code)"
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 --resolve "$DOMAIN:80:127.0.0.1" "http://$DOMAIN/")"
  [ "$code" = "301" ]; check 'HTTP redirects to HTTPS' "$?" "(got $code)"
  code="$(curl -s $k -o /dev/null -w '%{http_code}' --max-time 10 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/openapi.json")"
  [ "$code" = "404" ]; check '/openapi.json blocked at nginx' "$?" "(got $code)"
  curl -s $k -o /dev/null --max-time 10 --tls-max 1.1 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/healthz"
  [ "$?" -ne 0 ]; check 'TLS 1.0/1.1 refused' "$?"
fi

step 'Network exposure'
ss -Hltn | awk '{print $4}' | grep -Eq "^(0\.0\.0\.0|\*|\[::\]):$(pg_port)$"
[ "$?" -ne 0 ]; check "Postgres listens on loopback only" "$?"
if [ "$TLS_MODE" = "external" ]; then
  ok "API listens on $APP_BIND_HOST:$APP_PORT for the external nginx (TLS_MODE=external)"
  if [ "$ENABLE_UFW" = "yes" ]; then
    ufw status | grep -Eq "^$APP_PORT/tcp +ALLOW +Anywhere"
    [ "$?" -ne 0 ]; check "ufw does not open $APP_PORT to everyone" "$?"
  else
    warn "ENABLE_UFW=no: restrict $APP_PORT to your nginx some other way."
  fi
else
  ss -Hltn | awk '{print $4}' | grep -Eq "^(0\.0\.0\.0|\*|\[::\]):$APP_PORT$"
  [ "$?" -ne 0 ]; check "API port listens on loopback only" "$?"
fi

step 'Database'
triggers="$(psql_q "SELECT count(*) FROM pg_trigger WHERE tgrelid = 'public.audit_logs'::regclass AND tgname IN ('trg_audit_logs_no_update_delete','trg_audit_logs_no_truncate')")"
[ "$triggers" = "2" ]; check 'audit_logs append-only triggers installed' "$?" "(found $triggers)"
# Inside a transaction that is rolled back either way, so nothing can be lost.
psql_q 'BEGIN; TRUNCATE audit_logs; ROLLBACK;' >/dev/null 2>&1
[ "$?" -ne 0 ]; check 'TRUNCATE audit_logs is rejected' "$?"
tables="$(psql_q "SELECT count(*) FROM information_schema.tables WHERE table_name IN ('grievance_attachments','revoked_tokens','retention_policies','purpose_lifecycle','webhook_deliveries')")"
[ "$tables" = "5" ]; check 'Tables from migrations 15-18 present' "$?" "(found $tables of 5)"
nossl="$(psql_q "SELECT count(*) FROM pg_stat_activity a JOIN pg_stat_ssl s USING (pid) WHERE a.usename = '$DB_USER' AND NOT s.ssl")"
[ "$nossl" = "0" ]; check 'Every app connection uses TLS' "$?" "($nossl without)"
stored="$(psql_q "SELECT count(*) FROM pg_db_role_setting WHERE array_to_string(setconfig, ',') LIKE '%app.enc_key%'")"
[ "$stored" = "0" ]; check 'Encryption key not stored in the database' "$?"

step 'Files'
[ "$(stat -c '%a %U' "$ENV_FILE")" = "640 root" ]; check "$ENV_FILE is 0640 root" "$?" "($(stat -c '%a %U' "$ENV_FILE"))"
sudo -u "$APP_USER" test -w "$INSTALL_DIR/python_port/dpdpcms_py/main.py"
[ "$?" -ne 0 ]; check 'Code is read-only to the service account' "$?"

if [ -n "$email" ]; then
  step 'Authenticated checks'
  read -rsp "Password for $email: " password; echo
  api_post /api/v1/admin/operator "{\"_func\":\"login\",\"identifier\":\"$(json_escape "$email")\",\"password\":\"$(json_escape "$password")\"}"
  login="$API_BODY"
  unset password
  token="$(printf '%s' "$login" | json_str token)"
  [ "$API_STATUS" = "200" ] && [ -n "$token" ]; check 'Operator login' "$?" "(HTTP $API_STATUS)"
  if [ "$(printf '%s' "$login" | json_raw mfa_required)" = "true" ]; then
    warn 'Account has MFA enabled - skipping calls that need an MFA-verified token.'
  elif [ -n "$token" ]; then
    api_post /api/v1/admin/audit '{"_func":"verify_audit_chain"}' -H "Authorization: Bearer $token"
    chain="$API_BODY"
    [ "$API_STATUS" = "200" ] && [ "$(printf '%s' "$chain" | json_raw intact)" = "true" ]
    check 'verify_audit_chain reports an intact ledger' "$?" "(HTTP $API_STATUS $chain)"
  fi
fi

step 'Worker'
journalctl -u tsi-cms-worker --since '-1h' --no-pager 2>/dev/null | grep -q Traceback
[ "$?" -ne 0 ]; check 'No traceback in the last hour of worker logs' "$?"

if [ "$failures" -gt 0 ]; then printf '\n%s%s check(s) FAILED.%s\n' "$C_RED" "$failures" "$C_OFF"; exit 1; fi
printf '\n%sAll smoke checks passed.%s\n' "$C_GREEN" "$C_OFF"
