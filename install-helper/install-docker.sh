#!/usr/bin/env bash
# Alternative for a laptop or evaluation box: Docker Engine + Compose plugin from
# Docker's apt repository, then the repo's own Compose stack
# (scripts/local/shell_scripts/init-env.sh + deploy.sh).
# For a server, use install.sh (native, TLS, systemd, backups) instead.
# Usage: sudo bash install-helper/install-docker.sh [--add-user <name>]
LIB_CONF_OPTIONAL=1 . "$(dirname "$0")/lib.sh"
require_root
export DEBIAN_FRONTEND=noninteractive

add_user=""
if [ "${1:-}" = "--add-user" ]; then add_user="${2:?--add-user needs a user name}"; fi

step 'Docker Engine'
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  apt-get update -q
  apt-get install -y -q ca-certificates curl openssl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME:-$VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker >/dev/null 2>&1
ok "$(docker --version); $(docker compose version)"
if [ -n "$add_user" ]; then
  usermod -aG docker "$add_user"
  warn "$add_user added to the docker group (root-equivalent). Log out and back in for it to apply."
fi

step 'Compose environment'
bash "$REPO_ROOT/scripts/local/shell_scripts/init-env.sh"
env_file="$REPO_ROOT/.env"
chmod 600 "$env_file"
# Docker-published ports bypass ufw: keep the app on loopback unless told otherwise.
if grep -q '^PY_APP_PORT_MAP=8091:8080$' "$env_file"; then
  sed -i 's/^PY_APP_PORT_MAP=8091:8080$/PY_APP_PORT_MAP=127.0.0.1:8091:8080/' "$env_file"
  ok 'App published on 127.0.0.1:8091 only (Docker ports bypass ufw).'
fi

step 'Building and starting the stack'
bash "$REPO_ROOT/scripts/local/shell_scripts/deploy.sh"
cat <<EOF

  Console: http://localhost:8091/   (loopback only; tunnel with ssh -L 8091:127.0.0.1:8091)
  Manage:  bash scripts/local/shell_scripts/manage.sh status|logs|backup|psql
  Admin:   bash scripts/local/shell_scripts/bootstrap-admin.sh <email>
  This stack runs with TSI_DPDP_CMS_ENV=local and stores app.enc_key in the
  database (db/03z_enc_key.sh). Do not put real personal data in it.
EOF
