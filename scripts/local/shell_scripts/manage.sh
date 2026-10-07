#!/usr/bin/env bash
# Day-to-day operations for the local stack.
# Usage: manage.sh status | logs [service] | stop | start | restart | backup | psql | test | reset
. "$(dirname "$0")/common.sh"

action="${1:-}"; service="${2:-}"
user="$(env_get POSTGRES_USER tsi_admin)"
db="$(env_get POSTGRES_DB tsi_cms)"

case "$action" in
  status) compose ps ;;
  logs) if [ -n "$service" ]; then compose logs -f --tail 200 "$service"; else compose logs -f --tail 100; fi ;;
  stop) compose stop ;;
  start) compose start; wait_healthy 120 && ok "Healthy at $APP_URL" ;;
  restart) compose restart; wait_healthy 120 && ok "Healthy at $APP_URL" ;;
  backup)
    mkdir -p "$REPO_ROOT/backups"
    file="$REPO_ROOT/backups/tsi_cms-$(date +%Y%m%d-%H%M%S).dump"
    # Custom-format dump streamed out of the container; restore with pg_restore.
    compose exec -T postgres_db pg_dump -U "$user" -d "$db" -Fc > "$file"
    [ -s "$file" ] || { fail 'pg_dump produced an empty file'; exit 1; }
    ok "Backup written: $file"
    ;;
  psql) compose exec postgres_db psql -U "$user" -d "$db" ;;
  test)
    cd "$REPO_ROOT/python_port"
    py="$(command -v python3 || command -v python)"
    "$py" -m pip install -q -r requirements.txt pytest
    "$py" -m pytest -q tests
    ;;
  reset)
    project="$(project_name)"
    printf '%sThis permanently deletes the %s database and exports volumes.%s\n' "$C_RED" "$project" "$C_OFF"
    read -rp "Type the project name ($project) to confirm: " answer
    [ "$answer" = "$project" ] || { warn 'Cancelled.'; exit 0; }
    compose down -v
    ok 'Stack removed with its volumes. Run deploy.sh for a fresh database.'
    ;;
  *) echo "Usage: $0 status | logs [service] | stop | start | restart | backup | psql | test | reset" >&2; exit 2 ;;
esac
