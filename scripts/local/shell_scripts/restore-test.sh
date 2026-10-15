#!/usr/bin/env bash
# Rule 6(1)(d): prove a backup restores. Restores the newest (or the named)
# backups/*.dump into a throw-away database inside the Postgres container,
# checks the core tables came back and that the audit ledger's hash chain still
# verifies, then drops the scratch database. Nothing in the live database is
# touched.
#
# Usage: restore-test.sh [path/to/backup.dump]
. "$(dirname "$0")/common.sh"

user="$(env_get POSTGRES_USER tsi_admin)"
scratch="tsi_restore_test_$(date +%s)"
dump="${1:-$(ls -t "$REPO_ROOT"/backups/*.dump 2>/dev/null | head -1 || true)}"
[ -n "$dump" ] && [ -s "$dump" ] || { fail 'No backup found; run manage.sh backup first.'; exit 1; }
step "Restoring $dump into scratch database $scratch"

cleanup() { compose exec -T postgres_db psql -q -U "$user" -d postgres -c "DROP DATABASE IF EXISTS $scratch WITH (FORCE)" >/dev/null 2>&1 || true; }
trap cleanup EXIT

compose exec -T postgres_db psql -q -U "$user" -d postgres -c "CREATE DATABASE $scratch" >/dev/null
compose exec -T postgres_db pg_restore -U "$user" -d "$scratch" --no-owner < "$dump"

for table in consent_records consent_policies audit_logs purge_requests breach_incidents ropa_entries; do
  rows="$(compose exec -T postgres_db psql -tA -U "$user" -d "$scratch" -c "SELECT COUNT(*) FROM $table")"
  ok "$table: $rows rows restored"
done

# The ledger must still chain: every row's prev_log_hash is its predecessor's
# current_log_hash, in the order the verifier walks it.
broken="$(compose exec -T postgres_db psql -tA -U "$user" -d "$scratch" -c "
  SELECT COUNT(*) FROM (
    SELECT prev_log_hash, LAG(current_log_hash) OVER (ORDER BY timestamp, id) AS expected
    FROM audit_logs) t
  WHERE expected IS NOT NULL AND prev_log_hash IS NOT NULL AND prev_log_hash <> expected")"
if [ "$broken" = "0" ]; then
  ok 'Audit ledger chain links are intact in the restored copy.'
else
  fail "$broken audit ledger rows do not link to their predecessor in the restored copy."
  exit 1
fi
# Links alone would not catch a row edited in place that kept its links, so
# the application's own verifier recomputes every row hash against the copy.
verdict="$(compose exec -T -e POSTGRES_DB="$scratch" python_app python -c "
import json
from dpdpcms_py.audit import verify_chain
r = verify_chain(limit=10_000_000)
print(json.dumps({'intact': r['intact'], 'rows_checked': r['rows_checked'], 'broken_count': r['broken_count']}))
" | tail -1)"
case "$verdict" in
  *'"intact": true'*) ok "Audit ledger row hashes recompute in the restored copy: $verdict" ;;
  *) fail "Audit ledger hash verification failed in the restored copy: $verdict"; exit 1 ;;
esac
ok "Restore test passed for $dump. Record the date and result in docs/security/BACKUP_AND_CONTINUITY.md."
