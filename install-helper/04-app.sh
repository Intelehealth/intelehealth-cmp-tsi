#!/usr/bin/env bash
# Copy the application into $INSTALL_DIR (root-owned, read-only to the service)
# and install the hash-pinned dependency set into a Python 3.12 venv.
. "$(dirname "$0")/lib.sh"
require_root

step "Application code -> $INSTALL_DIR"
install -d -m 0755 -o root -g root "$INSTALL_DIR"
# Only what the Dockerfile ships (python_port + web) plus db/ for migrations.
# --delete keeps removed files from lingering; venv and secrets are never touched.
for dir in python_port web db; do
  rsync -a --delete --chown=root:root --chmod=D0755,F0644 \
    --exclude '.env' --exclude '.env.*' --exclude '__pycache__' --exclude '*.pyc' \
    --exclude '.venv' --exclude 'venv' --exclude '.pytest_cache' --exclude 'exports' \
    "$REPO_ROOT/$dir/" "$INSTALL_DIR/$dir/"
done
git -C "$REPO_ROOT" rev-parse HEAD > "$INSTALL_DIR/REVISION" 2>/dev/null || date -u +%FT%TZ > "$INSTALL_DIR/REVISION"
ok "Code synced (revision $(cat "$INSTALL_DIR/REVISION"))."

step 'Python virtual environment'
if [ -x "$VENV/bin/python" ] && ! "$VENV/bin/python" -c 'import sys; sys.exit(sys.version_info[:2] != (3, 12))'; then
  warn 'Existing venv is not Python 3.12 - rebuilding it.'
  rm -rf "$VENV"
fi
[ -x "$VENV/bin/python" ] || python3.12 -m venv "$VENV"
"$VENV/bin/python" -m pip install -q --upgrade pip
# M-02: exactly the audited, hash-pinned set, as in the Dockerfile.
"$VENV/bin/python" -m pip install -q --no-cache-dir --require-hashes -r "$INSTALL_DIR/python_port/requirements.lock"
chown -R root:root "$VENV"
ok "Dependencies installed into $VENV."

step 'Import check'
# Settings are validated at import, so load the real service environment first.
(cd "$INSTALL_DIR/python_port" && sudo -u "$APP_USER" PYTHONDONTWRITEBYTECODE=1 "$VENV/bin/python" -c \
  "from dotenv import load_dotenv; load_dotenv('$ENV_FILE'); import dpdpcms_py.main, dpdpcms_py.worker") \
  || die "dpdpcms_py failed to import - check $ENV_FILE (secrets, OUTBOUND_ALLOWED_HOSTS)."
ok 'dpdpcms_py.main and dpdpcms_py.worker import cleanly.'
