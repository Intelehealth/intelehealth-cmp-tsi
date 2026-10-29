#!/usr/bin/env bash
# Install the TSI DPDP CMS natively on Ubuntu: Postgres, API, worker, nginx/TLS,
# firewall and backups. Safe to re-run; secrets and data are kept.
# Usage: sudo bash install-helper/install.sh [--skip-preflight]
. "$(dirname "$0")/lib.sh"
require_root

[ "${1:-}" = "--skip-preflight" ] || bash "$HELPER_DIR/00-preflight.sh"
for script in 01-system-packages 02-secrets 03-postgres 04-app 05-migrate 06-services 07-nginx 08-backups; do
  printf '\n%s######## %s ########%s\n' "$C_CYAN" "$script" "$C_OFF"
  bash "$HELPER_DIR/$script.sh"
done

admins="$(psql_q "SELECT count(*) FROM operators WHERE role = 'ADMIN'")"
if [ "$TLS_MODE" = "none" ]; then url="$APP_URL"; else url="https://$DOMAIN"; fi
printf '\n%sInstalled.%s\n' "$C_GREEN" "$C_OFF"
cat <<EOF
  Console:        $url/
  Rights portal:  $url/rights/
  Settings:       $ENV_FILE
  Logs:           journalctl -u tsi-cms-app -u tsi-cms-worker -f
  Backups:        $BACKUP_DIR (systemctl list-timers tsi-cms-backup.timer)
EOF
if [ "$admins" = "0" ]; then
  printf '\n%sNext: create the Super-Admin ->  sudo bash %s/bootstrap-admin.sh <email>%s\n' "$C_YELLOW" "$HELPER_DIR" "$C_OFF"
fi
printf '%sThen verify ->  sudo bash %s/smoke-test.sh [admin email]%s\n' "$C_YELLOW" "$HELPER_DIR" "$C_OFF"
printf '%sBack up %s OFFLINE now (see docs/security/KEY_MANAGEMENT.md).%s\n' "$C_YELLOW" "$ENV_FILE" "$C_OFF"
