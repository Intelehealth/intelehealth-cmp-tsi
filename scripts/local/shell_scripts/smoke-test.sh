#!/usr/bin/env bash
# Verify a running local stack, including this branch's fixes. Exits 1 on any failure.
# Usage: smoke-test.sh [admin email]   (with an email it also signs in; password prompted)
. "$(dirname "$0")/common.sh"
set +e  # run every check, then report
failures=0
check() { if [ "$2" = "0" ]; then ok "$1"; else fail "$1 ${3:-}"; failures=$((failures + 1)); fi; }
email="${1:-}"

step 'Containers'
running="$(compose ps --status running --services 2>/dev/null)"
for svc in postgres_db python_app python_worker; do
  printf '%s\n' "$running" | grep -qx "$svc"; check "$svc running" "$?"
done

step 'HTTP'
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$APP_URL/healthz")"
[ "$code" = "200" ]; check '/healthz returns 200' "$?" "(got $code)"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$APP_URL/")"
[ "$code" = "200" ]; check 'Console page served' "$?" "(got $code)"
# CF-01: validator schemas must not be public.
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$APP_URL/WEB-INF/validator/erasure_request.jschema")"
[ "$code" = "404" ]; check 'WEB-INF is not served (404)' "$?" "(got $code)"
# P4-02: a mixed-case _func is normalised, never a validation bypass.
api_post /api/v1/client/consent '{"_func":"Erasure_Request"}' >/dev/null
[ "$API_STATUS" = "401" ] || [ "$API_STATUS" = "403" ]; check 'Mixed-case _func without credentials is refused' "$?" "(got $API_STATUS)"

step 'Database'
triggers="$(psql_q "SELECT count(*) FROM pg_trigger WHERE tgname IN ('trg_audit_logs_no_update_delete','trg_audit_logs_no_truncate')")"
[ "$triggers" = "2" ]; check 'audit_logs append-only triggers installed' "$?" "(found $triggers)"
# Inside a transaction that is rolled back either way, so nothing can be lost.
psql_q 'BEGIN; TRUNCATE audit_logs; ROLLBACK;' >/dev/null 2>&1
[ "$?" -ne 0 ]; check 'TRUNCATE audit_logs is rejected' "$?"
tables="$(psql_q "SELECT count(*) FROM information_schema.tables WHERE table_name IN ('grievance_attachments','revoked_tokens','retention_policies','purpose_lifecycle','webhook_deliveries')")"
[ "$tables" = "5" ]; check 'Tables from migrations 15-18 present' "$?" "(found $tables of 5)"

if [ -n "$email" ]; then
  step 'Authenticated checks'
  read -rsp "Password for $email: " password; echo
  login="$(api_post /api/v1/admin/operator "{\"_func\":\"login\",\"identifier\":\"$(json_escape "$email")\",\"password\":\"$(json_escape "$password")\"}")"
  unset password
  token="$(printf '%s' "$login" | json_str token)"
  [ "$API_STATUS" = "200" ] && [ -n "$token" ]; check 'Operator login' "$?" "(HTTP $API_STATUS)"
  if [ "$(printf '%s' "$login" | json_raw mfa_required)" = "true" ]; then
    warn 'Account has MFA enabled - skipping calls that need an MFA-verified token.'
  elif [ -n "$token" ]; then
    chain="$(api_post /api/v1/admin/audit '{"_func":"verify_audit_chain"}' -H "Authorization: Bearer $token")"
    [ "$API_STATUS" = "200" ] && [ "$(printf '%s' "$chain" | json_raw intact)" = "true" ]
    check 'verify_audit_chain reports an intact ledger' "$?" "(HTTP $API_STATUS $chain)"
    printf '         rows checked: %s, legacy (linkage-only): %s\n' \
      "$(printf '%s' "$chain" | json_raw rows_checked)" "$(printf '%s' "$chain" | json_raw legacy_rows_linkage_only)"
  fi
fi

step 'Worker'
compose logs --tail 200 python_worker 2>&1 | grep -q Traceback
[ "$?" -ne 0 ]; check 'No traceback in recent worker logs' "$?"

if [ "$failures" -gt 0 ]; then printf '\n%s%s check(s) FAILED.%s\n' "$C_RED" "$failures" "$C_OFF"; exit 1; fi
printf '\n%sAll smoke checks passed.%s\n' "$C_GREEN" "$C_OFF"
