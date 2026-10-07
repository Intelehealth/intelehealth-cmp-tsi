#!/usr/bin/env bash
# Apply upgrade migrations 13-20 to an EXISTING database volume (each script is
# idempotent). A fresh volume runs every db/*.sql itself on first start.
# Usage: migrate.sh [file.sql ...]   (default: all of 13-20, in order)
. "$(dirname "$0")/common.sh"

user="$(env_get POSTGRES_USER tsi_admin)"
db="$(env_get POSTGRES_DB tsi_cms)"
if [ "$#" -gt 0 ]; then scripts=("$@"); else scripts=("${UPGRADE_MIGRATIONS[@]}"); fi

step "Applying ${#scripts[@]} migration(s) to $db"
for file in "${scripts[@]}"; do
  [ -f "$REPO_ROOT/db/$file" ] || { fail "db/$file not found"; exit 1; }
  printf '  - %s\n' "$file"
  compose exec -T postgres_db psql -v ON_ERROR_STOP=1 -q -U "$user" -d "$db" -f "/docker-entrypoint-initdb.d/$file"
done
ok 'Migrations applied.'

triggers="$(psql_q "SELECT count(*) FROM pg_trigger WHERE tgname IN ('trg_audit_logs_no_update_delete','trg_audit_logs_no_truncate')")"
if [ "$triggers" = "2" ]; then ok 'audit_logs append-only triggers installed.'
else fail "Expected 2 audit_logs triggers, found $triggers."; exit 1; fi
