#!/usr/bin/env bash
# Check that this machine is ready to run the stack locally. Exits 1 on any failure.
. "$(dirname "$0")/common.sh"
failed=0

step 'Docker'
server="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
if [ -n "$server" ]; then ok "Docker daemon is running (engine $server)."
else fail 'Docker daemon is not reachable. Start Docker Desktop / dockerd first.'; failed=1; fi
if docker compose version >/dev/null 2>&1; then ok 'docker compose available.'
else fail 'docker compose v2 not found.'; failed=1; fi
command -v curl >/dev/null 2>&1 && ok 'curl available.' || { fail 'curl not found.'; failed=1; }

step '.env'
if [ ! -f "$ENV_FILE" ]; then
  fail '.env missing. Run scripts/local/shell_scripts/init-env.sh'; failed=1
else
  for key in "${REQUIRED_SECRETS[@]}"; do
    value="$(env_get "$key")"
    if [ "${#value}" -lt 32 ]; then fail "$key must be at least 32 characters."; failed=1
    elif printf '%s' "$value" | grep -qE 'change-me|do-not-use'; then fail "$key still holds a placeholder."; failed=1
    else ok "$key set (${#value} chars)."; fi
  done
  [ -n "$(env_get POSTGRES_PASSWD)" ] || { fail 'POSTGRES_PASSWD is empty.'; failed=1; }
  env_name="$(env_get TSI_DPDP_CMS_ENV local)"
  [ "$env_name" = "local" ] || warn "TSI_DPDP_CMS_ENV=$env_name - DUMMY_OTP portal login is refused outside 'local'."
fi

step 'Container names'
# docker-compose.yml pins container_name, so a same-named container from ANOTHER
# compose project blocks `docker compose up` here.
project="$(project_name)"
for name in "${CONTAINER_NAMES[@]}"; do
  owner="$(docker ps -a --filter "name=^/${name}\$" --format '{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.project.working_dir"}}|{{.State}}' 2>/dev/null | head -n 1)"
  if [ -z "$owner" ]; then ok "$name free."; continue; fi
  IFS='|' read -r o_project o_dir o_state <<<"$owner"
  if [ "$o_project" = "$project" ]; then ok "$name belongs to this project ($o_state)."
  else
    fail "$name is taken by project '$o_project' ($o_dir, $o_state)."
    printf '         Remove it (data volumes are kept): docker rm -f %s\n' "$name"
    failed=1
  fi
done

step 'Ports'
port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for port in 8091 5434; do
  if port_in_use "$port"; then
    if docker ps --format '{{.Ports}}' | grep -q ":$port->"; then ok "Port $port published by a running container (stack already up?)."
    else fail "Port $port is in use by another program. Free it or change PY_APP_PORT_MAP / PY_DB_PORT_MAP in .env."; failed=1; fi
  else ok "Port $port free."; fi
done

step 'Source tree'
font_count="$(find "$REPO_ROOT/python_port/dpdpcms_py/fonts" -name '*.ttf' 2>/dev/null | wc -l | tr -d ' ')"
if [ "$font_count" -ge 13 ]; then ok "$font_count Noto fonts present (PDF export)."
else fail "Expected 13 fonts in python_port/dpdpcms_py/fonts, found $font_count."; failed=1; fi
[ -f "$REPO_ROOT/db/19_audit_ledger_integrity.sql" ] && ok 'Migration 19 present.' || { fail 'db/19_audit_ledger_integrity.sql missing.'; failed=1; }
[ -f "$REPO_ROOT/db/20_security_gaps.sql" ] && ok 'Migration 20 present.' || { fail 'db/20_security_gaps.sql missing.'; failed=1; }
[ -f "$REPO_ROOT/db/21_defect_remediation_p6.sql" ] && ok 'Migration 21 present.' || { fail 'db/21_defect_remediation_p6.sql missing.'; failed=1; }
[ -f "$REPO_ROOT/db/22_sec18_null_fiduciary_block.sql" ] && ok 'Migration 22 present.' || { fail 'db/22_sec18_null_fiduciary_block.sql missing.'; failed=1; }
[ -f "$REPO_ROOT/db/23_notification_delivery_floor.sql" ] && ok 'Migration 23 present.' || { fail 'db/23_notification_delivery_floor.sql missing.'; failed=1; }
if (cd "$REPO_ROOT" && git ls-files --others --exclude-standard -- python_port/dpdpcms_py/fonts 2>/dev/null | grep -q .); then
  warn 'fonts/ is not committed to git - fine locally, but commit it before sharing the branch.'
fi

if [ "$failed" -ne 0 ]; then printf '\n%sPreflight FAILED.%s\n' "$C_RED" "$C_OFF"; exit 1; fi
printf '\n%sPreflight passed.%s\n' "$C_GREEN" "$C_OFF"
