#!/bin/sh
# Database backups for the Docker deployment (19 Oct 2026 audit, F-07).
#
# Runs in the `backup` service of docker-compose.yml: one pg_dump at start-up,
# then one every BACKUP_INTERVAL_SECONDS, keeping the newest BACKUP_KEEP dumps
# in ./backups on the host. `sh /backup.sh once` takes a single backup and exits.
# Restore procedure: docs/DOCUMENTATION.md, "Backups and restore".
set -eu

: "${PGHOST:=db}" "${PGUSER:=nightowl}" "${PGDATABASE:=nightowl}"
: "${BACKUP_INTERVAL_SECONDS:=86400}" "${BACKUP_KEEP:=7}"
export PGHOST PGUSER PGDATABASE

backup_once() {
  stamp=$(date -u +%Y%m%d-%H%M%S)
  tmp="/backups/.nightowl-$stamp.dump.partial"
  # Custom format: compressed, restorable table by table with pg_restore.
  if pg_dump --format=custom --no-owner --file="$tmp"; then
    mv "$tmp" "/backups/nightowl-$stamp.dump"
    echo "[backup] wrote nightowl-$stamp.dump ($(du -h "/backups/nightowl-$stamp.dump" | cut -f1))"
  else
    rm -f "$tmp"
    echo "[backup] pg_dump FAILED at $stamp" >&2
    return 1
  fi
  # Keep the newest BACKUP_KEEP dumps.
  ls -1t /backups/nightowl-*.dump 2>/dev/null | tail -n +"$((BACKUP_KEEP + 1))" | while read -r old; do
    rm -f "$old" && echo "[backup] removed old $(basename "$old")"
  done
}

if [ "${1:-}" = "once" ]; then
  backup_once
  exit $?
fi

while true; do
  backup_once || true
  sleep "$BACKUP_INTERVAL_SECONDS"
done
