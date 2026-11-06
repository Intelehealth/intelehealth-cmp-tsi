#!/usr/bin/env bash
# Deploy a new revision of this repository onto an installed host:
# backup -> stop -> sync code + dependencies -> migrate -> start -> health check.
# Usage: git pull (or copy the new tree), then: sudo bash install-helper/upgrade.sh
. "$(dirname "$0")/lib.sh"
require_root

[ -f "$ENV_FILE" ] && [ -f "$SCHEMA_MARKER" ] || die 'No existing installation found - run install.sh.'

step "Upgrading $(cat "$INSTALL_DIR/REVISION" 2>/dev/null || echo unknown) -> $(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo 'working tree')"
bash "$HELPER_DIR/02-secrets.sh"
step 'Stopping app and worker'
systemctl stop "${SERVICES[@]}"
ok 'Stopped.'
# On any failure from here on, the services stay stopped and the pre-migration
# backup in $BACKUP_DIR is the rollback point.
bash "$HELPER_DIR/04-app.sh"
bash "$HELPER_DIR/05-migrate.sh"   # takes the backup first
bash "$HELPER_DIR/06-services.sh"
bash "$HELPER_DIR/07-nginx.sh"
printf '\n%sUpgrade complete.%s Verify: sudo bash %s/smoke-test.sh\n' "$C_GREEN" "$C_OFF" "$HELPER_DIR"
