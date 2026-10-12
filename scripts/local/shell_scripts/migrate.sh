#!/usr/bin/env bash
# Apply upgrade migrations 13-24 to an EXISTING database volume (each script is
# idempotent). A fresh volume runs every db/*.sql itself on first start.
# Usage: migrate.sh [file.sql ...]   (default: all of 13-24, in order)
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

# P7-04: a partial install must not report success. Verify every Rule 6(1)(e)
# floor trigger (db/23, db/24), and that the pre-rename db/23 trigger is gone.
FLOOR_TRIGGERS="'trg_notification_deliveries_floor','trg_notification_deliveries_no_truncate','trg_webhook_deliveries_floor','trg_webhook_deliveries_no_truncate','trg_notification_deliveries_update_floor','trg_webhook_deliveries_update_floor','trg_notifications_floor'"
floor="$(psql_q "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgname IN ($FLOOR_TRIGGERS)")"
if [ "$floor" = "7" ]; then ok 'Rule 6(1)(e) retention-floor triggers installed (7).'
else fail "Expected 7 retention-floor triggers, found $floor."; exit 1; fi
stale="$(psql_q "SELECT count(*) FROM pg_trigger WHERE tgname = 'notification_deliveries_floor'")"
if [ "$stale" = "0" ]; then ok 'No stale pre-rename floor trigger.'
else fail 'Stale trigger notification_deliveries_floor still present (re-run 23_notification_delivery_floor.sql).'; exit 1; fi
