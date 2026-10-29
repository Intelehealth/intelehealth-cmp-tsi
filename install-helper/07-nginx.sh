#!/usr/bin/env bash
# nginx reverse proxy: TLS 1.2/1.3 termination in front of the loopback API,
# HTTP -> HTTPS redirect, /docs and /openapi.json blocked as a backstop.
. "$(dirname "$0")/lib.sh"
require_root

if [ "$TLS_MODE" = "none" ]; then
  ok "TLS_MODE=none - skipping nginx. The API listens on $APP_URL only; put a TLS proxy in front of it."
  exit 0
fi
if [ "$TLS_MODE" = "external" ]; then
  ok "TLS_MODE=external - nginx for https://$DOMAIN is managed outside this host; nothing installed."
  cat <<EOF
  Make sure your nginx server block for $DOMAIN has, at minimum:
    server_tokens off;
    client_max_body_size 12m;
    location ~ ^/(docs|redoc|openapi\.json)(/|\$) { return 404; }
    location / {
        proxy_pass http://<this container's IP>:$APP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 120s;
    }
  and, once bootstrap-admin.sh has run:  location ^~ /api/v1/bootstrap/ { return 403; }
EOF
  exit 0
fi

site=/etc/nginx/sites-available/tsi-cms
acme_root=/var/www/letsencrypt
snippet_dir=/etc/nginx/snippets
bootstrap_snippet="$snippet_dir/tsi-cms-bootstrap.conf"
install -d -m 0755 "$acme_root" "$snippet_dir"
# bootstrap-admin.sh replaces this with a 403 once the first Super-Admin exists.
[ -f "$bootstrap_snippet" ] || echo '# /api/v1/bootstrap/ open until the first Super-Admin is created.' > "$bootstrap_snippet"

http_block() {
  cat <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    server_tokens off;

    location ^~ /.well-known/acme-challenge/ {
        root $acme_root;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF
}

step 'Certificate'
case "$TLS_MODE" in
  letsencrypt)
    cert="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    key="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    if [ ! -f "$cert" ]; then
      # Serve the ACME challenge over plain HTTP first.
      http_block > "$site"
      ln -sf "$site" /etc/nginx/sites-enabled/tsi-cms
      rm -f /etc/nginx/sites-enabled/default
      nginx -t && systemctl reload nginx
      certbot certonly --webroot -w "$acme_root" -d "$DOMAIN" \
        --email "$LETSENCRYPT_EMAIL" --agree-tos --non-interactive \
        --deploy-hook 'systemctl reload nginx'
    fi
    ok "Let's Encrypt certificate for $DOMAIN (renewed by certbot.timer)."
    ;;
  selfsigned)
    cert=/etc/ssl/certs/tsi-cms-selfsigned.pem
    key=/etc/ssl/private/tsi-cms-selfsigned.key
    if [ ! -f "$cert" ]; then
      if is_ip "$DOMAIN"; then san="IP:$DOMAIN"; else san="DNS:$DOMAIN"; fi
      openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes \
        -keyout "$key" -out "$cert" -subj "/CN=$DOMAIN" -addext "subjectAltName=$san" 2>/dev/null
      chmod 600 "$key"
    fi
    warn "Self-signed certificate for $DOMAIN - browsers will warn. Not for production."
    ;;
esac

step 'nginx site'
{
  http_block
  cat <<EOF

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $DOMAIN;
    server_tokens off;

    ssl_certificate     $cert;
    ssl_certificate_key $key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:tsi_ssl:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Grievance attachments arrive in JSON bodies (ATTACHMENT_MAX_BYTES, 5 MB by default).
    client_max_body_size 12m;

    # The app sends HSTS, CSP and the other security headers itself (main.py).

    # Backstop for TSI_DPDP_CMS_ENV != local, which already disables these.
    location ~ ^/(docs|redoc|openapi\.json)(/|\$) { return 404; }
    include $bootstrap_snippet;

    location / {
        proxy_pass http://127.0.0.1:$APP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 120s;
    }
}
EOF
} > "$site"
ln -sf "$site" /etc/nginx/sites-enabled/tsi-cms
rm -f /etc/nginx/sites-enabled/default
# 'http2 on' needs nginx >= 1.25.1; older nginx (Ubuntu 22.04/24.04) uses 'listen ... ssl http2'.
if ! nginx -t >/dev/null 2>&1; then
  sed -i -e '/^    http2 on;$/d' -e 's/listen 443 ssl;/listen 443 ssl http2;/' -e 's/listen \[::\]:443 ssl;/listen [::]:443 ssl http2;/' "$site"
fi
nginx -t
systemctl enable nginx >/dev/null 2>&1
systemctl reload nginx || systemctl restart nginx
ok "nginx serving https://$DOMAIN -> $APP_URL"

code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/healthz" || true)"
[ "$code" = "200" ] && ok "https://$DOMAIN/healthz -> 200" || warn "https://$DOMAIN/healthz returned $code"
