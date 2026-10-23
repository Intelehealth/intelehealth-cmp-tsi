#!/usr/bin/env bash
# PostgreSQL $PG_VERSION from the PGDG archive, TLS on, loopback only, plus the
# owner role, database, extensions and the tsi_tenant_reader role the schema needs.
. "$(dirname "$0")/lib.sh"
require_root
export DEBIAN_FRONTEND=noninteractive
[ -f "$ENV_FILE" ] || die "$ENV_FILE missing - run 02-secrets.sh first."

step "PostgreSQL $PG_VERSION"
if ! dpkg -s "postgresql-$PG_VERSION" >/dev/null 2>&1; then
  apt-get install -y -q postgresql-common ssl-cert
  /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
  apt-get install -y -q "postgresql-$PG_VERSION" "postgresql-client-$PG_VERSION"
fi
[ -n "$(pg_port)" ] || pg_createcluster "$PG_VERSION" main --start
pg_ctlcluster "$PG_VERSION" main start 2>/dev/null || true
port="$(pg_port)"
env_set POSTGRES_HOST "postgresql://127.0.0.1:$port"
ok "Cluster $PG_VERSION/main on port $port"

step 'Server settings'
conf_dir="/etc/postgresql/$PG_VERSION/main"
# The app connects with sslmode=require outside APP_ENV=local. Ubuntu clusters
# ship with the snakeoil certificate; make sure one is configured.
if [ ! -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]; then make-ssl-cert generate-default-snakeoil --force-overwrite; fi
cat > "$conf_dir/conf.d/50-tsi-cms.conf" <<'EOF'
# Managed by install-helper/03-postgres.sh
listen_addresses = 'localhost'
ssl = on
password_encryption = 'scram-sha-256'
# The app sends DB_ENCRYPTION_KEY as a bind parameter on every connection:
# never log statements or their parameters.
log_statement = 'none'
log_min_duration_statement = -1
log_parameter_max_length = 0
log_parameter_max_length_on_error = 0
log_connections = on
log_disconnections = on
log_line_prefix = '%m [%p] %q%u@%d '
EOF
grep -q "^include_dir = 'conf.d'" "$conf_dir/postgresql.conf" \
  || echo "include_dir = 'conf.d'" >> "$conf_dir/postgresql.conf"
# Only TLS + SCRAM over TCP for the app role; local socket stays peer-only.
hba="$conf_dir/pg_hba.conf"
if ! grep -q 'tsi-cms' "$hba"; then
  tmp="$(mktemp)"
  { echo "# tsi-cms: app role over TLS only (install-helper/03-postgres.sh)"
    echo "hostssl $DB_NAME $DB_USER 127.0.0.1/32 scram-sha-256"
    echo "hostssl $DB_NAME $DB_USER ::1/128      scram-sha-256"
    echo "hostnossl $DB_NAME $DB_USER all       reject"
    cat "$hba"; } > "$tmp"
  cat "$tmp" > "$hba"; rm -f "$tmp"
fi
systemctl enable --now "postgresql@$PG_VERSION-main" >/dev/null 2>&1 || true
pg_ctlcluster "$PG_VERSION" main restart
[ "$(psql_super -d postgres -tA -c 'SHOW ssl')" = "on" ] || die 'ssl is not on after restart.'
ok 'TLS on, loopback only, statement/parameter logging off.'

step 'Role and database'
password="$(env_get POSTGRES_PASSWD)"
[ -n "$password" ] || die "POSTGRES_PASSWD missing from $ENV_FILE"
# Fed on stdin so the password never shows in the process list.
psql_super -d postgres -q <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$DB_USER') THEN
    CREATE ROLE $DB_USER LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tsi_tenant_reader') THEN
    CREATE ROLE tsi_tenant_reader NOLOGIN;
  END IF;
END
\$\$;
ALTER ROLE $DB_USER WITH LOGIN PASSWORD '$password';
SQL
if [ "$(psql_super -d postgres -tA -c "SELECT count(*) FROM pg_database WHERE datname = '$DB_NAME'")" = "0" ]; then
  psql_super -d postgres -q -c "CREATE DATABASE $DB_NAME OWNER $DB_USER ENCODING 'UTF8' TEMPLATE template0"
  ok "Database $DB_NAME created (owner $DB_USER)."
else
  ok "Database $DB_NAME exists."
fi
# uuid-ossp is not a trusted extension, so the owner cannot create it; the
# migrations' CREATE EXTENSION IF NOT EXISTS then becomes a no-op.
psql_super -d "$DB_NAME" -q -c 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"; CREATE EXTENSION IF NOT EXISTS pgcrypto;'
# The Docker init (db/03z_enc_key.sh) stores the key as a database default;
# here it is set per session instead, so dumps and backups never carry it.
psql_super -d postgres -q -c "ALTER DATABASE $DB_NAME RESET app.enc_key"
ok 'Extensions uuid-ossp and pgcrypto present; no database-level app.enc_key.'

step 'Connection check (app role, TLS)'
ssl="$(psql_owner -tA -c 'SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()')"
[ "$ssl" = "t" ] || die "App role connection is not using TLS (got '$ssl')."
ok "$DB_USER connects over TLS on 127.0.0.1:$port"
