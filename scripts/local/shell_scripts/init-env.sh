#!/usr/bin/env bash
# Create .env from .env.example with freshly generated secrets.
# Never overwrites an existing .env unless --force (then keeps a timestamped backup).
. "$(dirname "$0")/common.sh"

force=0
[ "${1:-}" = "--force" ] && force=1

new_secret() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32
  else od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; fi
}

step 'Preparing .env'
if [ -f "$ENV_FILE" ] && [ "$force" -eq 0 ]; then
  ok '.env already exists - leaving it untouched (use --force to regenerate).'
  exit 0
fi
if [ -f "$ENV_FILE" ]; then
  backup="$ENV_FILE.bak-$(date +%Y%m%d-%H%M%S)"
  cp "$ENV_FILE" "$backup"
  warn "Existing .env backed up to $backup"
fi

pg_pass="$(new_secret | cut -c1-24)"
jwt="$(new_secret)"; enc="$(new_secret)"; salt="$(new_secret)"; boot="$(new_secret)"
sed -e "s|^POSTGRES_PASSWD=.*|POSTGRES_PASSWD=$pg_pass|" \
    -e "s|^JWT_SECRET=.*|JWT_SECRET=$jwt|" \
    -e "s|^DB_ENCRYPTION_KEY=.*|DB_ENCRYPTION_KEY=$enc|" \
    -e "s|^TSI_LOOKUP_SALT=.*|TSI_LOOKUP_SALT=$salt|" \
    -e "s|^BOOTSTRAP_TOKEN=.*|BOOTSTRAP_TOKEN=$boot|" \
    "$REPO_ROOT/.env.example" > "$ENV_FILE"
chmod 600 "$ENV_FILE" 2>/dev/null || true
ok '.env written with generated secrets.'
warn 'Keep DB_ENCRYPTION_KEY and TSI_LOOKUP_SALT stable: changing them after data exists makes encrypted columns and pseudonyms unreadable.'
