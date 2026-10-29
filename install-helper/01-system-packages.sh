#!/usr/bin/env bash
# OS packages: Python 3.12 (the version requirements.lock is compiled for),
# nginx, certbot, firewall, time sync and automatic security updates.
. "$(dirname "$0")/lib.sh"
require_root
export DEBIAN_FRONTEND=noninteractive

step 'Base packages'
apt-get update -q
apt-get install -y -q ca-certificates curl gnupg lsb-release openssl rsync sudo acl iproute2 ssl-cert \
  software-properties-common unattended-upgrades
ok 'Base packages installed.'

step 'Python 3.12'
if ! apt-cache policy python3.12 | grep -q 'Candidate: [0-9]'; then
  warn 'python3.12 not in the Ubuntu archive for this release - adding the deadsnakes PPA.'
  add-apt-repository -y ppa:deadsnakes/ppa
  apt-get update -q
fi
apt-get install -y -q python3.12 python3.12-venv
python3.12 --version
ok 'Python 3.12 installed.'

if local_nginx; then
  step 'nginx'
  apt-get install -y -q nginx
  [ "$TLS_MODE" != "letsencrypt" ] || apt-get install -y -q certbot
  ok 'nginx installed.'
fi

step 'Time sync'
# TOTP MFA, token expiry and the audit chain all rely on an accurate clock.
timedatectl set-ntp true 2>/dev/null || warn 'Could not enable NTP via timedatectl; check time sync manually.'
ok "NTP: $(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"

step 'Automatic security updates'
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
ok 'unattended-upgrades enabled (security pocket).'

if [ "$ENABLE_UFW" = "yes" ]; then
  step 'Firewall (ufw)'
  apt-get install -y -q ufw
  # Allow SSH before enabling so the current session is not cut off.
  ufw allow "$SSH_PORT/tcp" comment 'ssh' >/dev/null
  opened=""
  if local_nginx; then
    ufw allow 80/tcp comment 'http (redirect + ACME)' >/dev/null
    ufw allow 443/tcp comment 'https' >/dev/null
    opened=', 80, 443'
  elif [ "$TLS_MODE" = "external" ]; then
    # Only the external nginx may reach the API port.
    IFS=',' read -ra proxy_ips <<< "$EXTRA_TRUSTED_PROXY_IPS"
    for ip in "${proxy_ips[@]}"; do
      ip="${ip// /}"; [ -n "$ip" ] || continue
      ufw allow from "$ip" to any port "$APP_PORT" proto tcp comment 'tsi-cms api (external nginx)' >/dev/null
    done
    opened=", $APP_PORT from $EXTRA_TRUSTED_PROXY_IPS"
  fi
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  ufw --force enable >/dev/null
  ok "ufw active: ssh/$SSH_PORT$opened open; Postgres stays closed."
fi
