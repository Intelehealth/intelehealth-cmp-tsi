#!/usr/bin/env bash
# Create the first Super-Admin through /api/v1/bootstrap/setup (one-time).
# Usage: bootstrap-admin.sh <email> [name]
# The password is prompted without echo (min 12 chars) and never written to disk.
. "$(dirname "$0")/common.sh"

email="${1:?usage: bootstrap-admin.sh <email> [name]}"
name="${2:-Super Admin}"
token="$(env_get BOOTSTRAP_TOKEN)"
[ "${#token}" -ge 32 ] || { fail 'BOOTSTRAP_TOKEN missing from .env'; exit 1; }

if [ "$(psql_q "SELECT count(*) FROM operators WHERE role = 'ADMIN'")" != "0" ]; then
  ok 'A Super-Admin already exists - nothing to do.'; exit 0
fi

read -rsp 'Password for the Super-Admin (min 12 chars): ' password; echo
read -rsp 'Confirm password: ' confirm; echo
[ "$password" = "$confirm" ] || { fail 'Passwords do not match.'; exit 1; }
[ "${#password}" -ge 12 ] || { fail 'Password must be at least 12 characters.'; exit 1; }

step "Creating Super-Admin $email"
body="{\"_func\":\"initial_setup\",\"name\":\"$(json_escape "$name")\",\"email\":\"$(json_escape "$email")\",\"password\":\"$(json_escape "$password")\"}"
unset password confirm
response="$(api_post /api/v1/bootstrap/setup "$body" -H "X-Bootstrap-Token: $token")"
unset body
if [ "$API_STATUS" -ge 200 ] && [ "$API_STATUS" -lt 300 ]; then
  ok "Created (user_id $(printf '%s' "$response" | json_str user_id)). Sign in at $APP_URL/"
  warn 'Enrol MFA for this account from the console settings before adding real data.'
else
  fail "Setup failed: HTTP $API_STATUS $response"; exit 1
fi
