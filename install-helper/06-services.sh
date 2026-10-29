#!/usr/bin/env bash
# systemd units for the API (uvicorn) and the background worker, sandboxed,
# running as $APP_USER with the env file as their only configuration.
. "$(dirname "$0")/lib.sh"
require_root

pg_unit="postgresql@$PG_VERSION-main.service"

# Shared [Service] hardening. The code is read-only; only the exports volume is writable.
sandbox() {
  cat <<EOF
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$INSTALL_DIR/python_port
EnvironmentFile=$ENV_FILE
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONUNBUFFERED=1
Environment=TZ=Asia/Kolkata
UMask=0027
Restart=always
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DATA_DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RemoveIPC=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
EOF
}

step 'Writing systemd units'
cat > /etc/systemd/system/tsi-cms-app.service <<EOF
[Unit]
Description=TSI DPDP CMS API (uvicorn)
After=network-online.target $pg_unit
Wants=network-online.target $pg_unit

[Service]
Type=exec
# --no-proxy-headers: the app resolves the client IP itself from
# X-Forwarded-For, trusting only TRUSTED_PROXY_IPS (main.py client_ip).
ExecStart=$VENV/bin/uvicorn dpdpcms_py.main:app --host $APP_BIND_HOST --port $APP_PORT --workers $UVICORN_WORKERS --no-proxy-headers --no-server-header
$(sandbox)

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/tsi-cms-worker.service <<EOF
[Unit]
Description=TSI DPDP CMS background worker (notifications, webhooks, retention, audit archive, exports)
After=network-online.target $pg_unit
Wants=network-online.target $pg_unit

[Service]
Type=exec
# Single instance: the worker is not known to be safe to run twice.
ExecStart=$VENV/bin/python -m dpdpcms_py.worker
$(sandbox)

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
ok 'tsi-cms-app.service and tsi-cms-worker.service written.'

step 'Starting services'
systemctl enable "${SERVICES[@]}" >/dev/null 2>&1
systemctl restart "${SERVICES[@]}"
if ! wait_healthy 120; then
  fail 'API did not become healthy. Recent logs:'
  journalctl -u tsi-cms-app -n 60 --no-pager
  exit 1
fi
ok "API healthy at $APP_URL (loopback only)."
sleep 5
systemctl is-active --quiet tsi-cms-worker && ok 'Worker running.' \
  || { fail 'Worker is not running:'; journalctl -u tsi-cms-worker -n 60 --no-pager; exit 1; }
