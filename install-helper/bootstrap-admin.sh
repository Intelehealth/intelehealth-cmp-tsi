#!/usr/bin/env bash
# Create the first Super-Admin through /api/v1/bootstrap/setup (one-time), then
# close the bootstrap path: BOOTSTRAP_TOKEN is rotated to a value nobody keeps
# and nginx answers 403 on /api/v1/bootstrap/.
# Usage: sudo bash bootstrap-admin.sh <email> [name]
# The password is prompted without echo (min 12 chars) and never written to disk.
. "$(dirname "$0")/lib.sh"
require_root

email="${1:?usage: bootstrap-admin.sh <email> [name]}"
name="${2:-Super Admin}"
token="$(env_get BOOTSTRAP_TOKEN)"
[ "${#token}" -ge 32 ] || die "BOOTSTRAP_TOKEN missing from $ENV_FILE"

close_bootstrap() {
  step 'Closing the bootstrap path'
  env_set BOOTSTRAP_TOKEN "$(new_secret)"
  systemctl restart "${SERVICES[@]}"
  wait_healthy 120 || die 'API unhealthy after restart.'
  ok 'BOOTSTRAP_TOKEN rotated to an unrecorded value; services restarted.'
  if [ "$TLS_MODE" = "external" ]; then
    warn "Add 'location ^~ /api/v1/bootstrap/ { return 403; }' to your nginx for $DOMAIN."
  elif [ -d /etc/nginx/snippets ] && local_nginx; then
    printf '# Super-Admin exists: bootstrap closed (install-helper/bootstrap-admin.sh).\nlocation ^~ /api/v1/bootstrap/ { return 403; }\n' \
      > /etc/nginx/snippets/tsi-cms-bootstrap.conf
    nginx -t && systemctl reload nginx
    ok 'nginx blocks /api/v1/bootstrap/.'
  fi
}

if [ "$(psql_q "SELECT count(*) FROM operators WHERE role = 'ADMIN'")" != "0" ]; then
  ok 'A Super-Admin already exists - nothing to create.'
  close_bootstrap
  exit 0
fi

read -rsp 'Password for the Super-Admin (min 12 chars): ' password; echo
read -rsp 'Confirm password: ' confirm; echo
[ "$password" = "$confirm" ] || die 'Passwords do not match.'
[ "${#password}" -ge 12 ] || die 'Password must be at least 12 characters.'

step "Creating Super-Admin $email"
body="{\"_func\":\"initial_setup\",\"name\":\"$(json_escape "$name")\",\"email\":\"$(json_escape "$email")\",\"password\":\"$(json_escape "$password")\"}"
unset password confirm
api_post /api/v1/bootstrap/setup "$body" -H "X-Bootstrap-Token: $token"
response="$API_BODY"
unset body
if [ "$API_STATUS" -ge 200 ] && [ "$API_STATUS" -lt 300 ]; then
  ok "Created (user_id $(printf '%s' "$response" | json_str user_id))."
else
  die "Setup failed: HTTP $API_STATUS $response"
fi
close_bootstrap
warn 'Sign in and enrol MFA for this account before adding real data.'
