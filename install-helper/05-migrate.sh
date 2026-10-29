#!/usr/bin/env bash
# Apply the database schema.
#   Fresh database   : every db/*.sql in lexical order (what docker-entrypoint-initdb.d does).
#   Existing database: a pg_dump backup first, then the idempotent upgrades 13 onwards.
# Usage: 05-migrate.sh [--upgrade] [file.sql ...]
# Every script runs as the schema owner over TLS, with app.enc_key and
# app.lookup_key set for that session only (db/03z_enc_key.sh is not used).
. "$(dirname "$0")/lib.sh"
require_root

force_upgrade=0; files=()
for arg in "$@"; do
  case "$arg" in
    --upgrade) force_upgrade=1 ;;
    *.sql) files+=("$arg") ;;
    *) die "Unknown option: $arg" ;;
  esac
done

db_dir="$INSTALL_DIR/db"
[ -d "$db_dir" ] || die "$db_dir missing - run 04-app.sh first."
has_schema="$(psql_q "SELECT to_regclass('public.operators') IS NOT NULL")"

if [ "${#files[@]}" -gt 0 ]; then
  mode=selected
elif [ -f "$SCHEMA_MARKER" ] || [ "$force_upgrade" = "1" ]; then
  mode=upgrade
elif [ "$has_schema" = "t" ]; then
  die "Database $DB_NAME already has a schema but $SCHEMA_MARKER is missing. If it came from an earlier deployment, re-run with --upgrade. If a fresh install failed half-way, drop and recreate the empty database (sudo -u postgres dropdb $DB_NAME; then 03-postgres.sh) and run this again."
else
  mode=fresh
fi

if [ "$mode" = "fresh" ]; then
  mapfile -t files < <(cd "$db_dir" && ls -1 [0-9]*.sql | LC_ALL=C sort)
else
  if [ "$mode" = "upgrade" ]; then
    # Upgrades are every numbered script from 13 on (01-12 are empty-database only).
    mapfile -t files < <(cd "$db_dir" && ls -1 [0-9]*.sql | LC_ALL=C sort | awk -F_ '($1 + 0) >= 13')
  fi
  step 'Backup before migrating'
  bash "$HELPER_DIR/08-backups.sh" --now
fi

step "Applying ${#files[@]} migration(s) to $DB_NAME ($mode)"
for file in "${files[@]}"; do
  [ -f "$db_dir/$file" ] || die "db/$file not found"
  printf '  - %s\n' "$file"
  # The scripts are idempotent and NOTICE about every no-op; show warnings and errors only.
  PSQL_EXTRA_OPTIONS='-c client_min_messages=warning' psql_owner -q -f "$db_dir/$file" >/dev/null
done
ok 'Migrations applied.'
# Later runs (upgrade.sh) then take the upgrade path automatically.
touch "$SCHEMA_MARKER"; chown "$APP_USER:$APP_USER" "$SCHEMA_MARKER"

step 'Verifying'
triggers="$(psql_q "SELECT count(*) FROM pg_trigger WHERE tgrelid = 'public.audit_logs'::regclass AND tgname IN ('trg_audit_logs_no_update_delete','trg_audit_logs_no_truncate')")"
[ "$triggers" = "2" ] && ok 'audit_logs append-only triggers installed.' || die "Expected 2 audit_logs triggers, found $triggers."
FLOOR_TRIGGERS="'trg_notification_deliveries_floor','trg_notification_deliveries_no_truncate','trg_webhook_deliveries_floor','trg_webhook_deliveries_no_truncate','trg_notification_deliveries_update_floor','trg_webhook_deliveries_update_floor','trg_notifications_floor'"
floor="$(psql_q "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgname IN ($FLOOR_TRIGGERS)")"
[ "$floor" = "7" ] && ok 'Rule 6(1)(e) retention-floor triggers installed (7).' || die "Expected 7 retention-floor triggers, found $floor."
stored="$(psql_q "SELECT count(*) FROM pg_db_role_setting WHERE array_to_string(setconfig, ',') LIKE '%app.enc_key%'")"
[ "$stored" = "0" ] && ok 'No encryption key stored in the database.' \
  || warn "app.enc_key is stored as a database/role default ($stored setting(s)) - backups carry the key. Remove with: ALTER DATABASE $DB_NAME RESET app.enc_key"
