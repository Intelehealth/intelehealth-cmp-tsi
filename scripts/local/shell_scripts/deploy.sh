#!/usr/bin/env bash
# Build and start the full local stack (Postgres, API, worker), backing up and
# migrating an existing database when needed.
# Usage: deploy.sh [--skip-build] [--migrate] [--skip-preflight]
. "$(dirname "$0")/common.sh"

skip_build=0; force_migrate=0; skip_preflight=0
for arg in "$@"; do
  case "$arg" in
    --skip-build) skip_build=1 ;;
    --migrate) force_migrate=1 ;;
    --skip-preflight) skip_preflight=1 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

[ "$skip_preflight" -eq 1 ] || "$SCRIPT_DIR/preflight.sh"

step 'Inspecting database volume'
existing=0
if db_volume_exists; then
  existing=1
  warn 'Existing Postgres volume found - init scripts will NOT re-run; upgrade migrations will be applied.'
else
  ok 'No volume yet - Postgres will run every db/*.sql (01-23) on first start.'
fi

if [ "$skip_build" -eq 0 ]; then step 'Building image'; compose build; fi

step 'Starting containers'
compose up -d

step 'Waiting for /healthz'
if ! wait_healthy 240; then
  fail 'API did not become healthy. Recent logs:'
  compose logs --tail 60 postgres_db python_app
  exit 1
fi
ok "API healthy at $APP_URL"

if [ "$existing" -eq 1 ] || [ "$force_migrate" -eq 1 ]; then
  step 'Backing up the existing database before migrating'
  "$SCRIPT_DIR/manage.sh" backup
  "$SCRIPT_DIR/migrate.sh"
  step 'Restarting app and worker on the migrated schema'
  compose restart python_app python_worker
  wait_healthy 120 || { fail 'API unhealthy after restart.'; exit 1; }
else
  triggers="$(psql_q "SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'trg_audit_logs_%'")"
  [ "$triggers" = "2" ] || warn "audit_logs triggers: $triggers (expected 2). Run scripts/local/shell_scripts/migrate.sh 19_audit_ledger_integrity.sql"
fi

admins="$(psql_q "SELECT count(*) FROM operators WHERE role = 'ADMIN'")"
printf '\n%sStack is up.%s\n' "$C_GREEN" "$C_OFF"
printf '  Console:       %s/\n  Rights portal: %s/rights/\n  Postgres:      127.0.0.1:5434 (from the host)\n' "$APP_URL" "$APP_URL"
if [ "$admins" = "0" ]; then
  printf '\n%sNext: create the Super-Admin ->  scripts/local/shell_scripts/bootstrap-admin.sh <email>%s\n' "$C_YELLOW" "$C_OFF"
else
  printf '\n%sNext: verify ->  scripts/local/shell_scripts/smoke-test.sh <admin email>%s\n' "$C_YELLOW" "$C_OFF"
fi
