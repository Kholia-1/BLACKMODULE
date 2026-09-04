#!/bin/sh
set -eu

umask 077

fail() {
    printf '%s\n' "BACKUP_ERROR: $1" >&2
    exit 1
}

[ -n "${PGHOST:-}" ] || fail "PGHOST is required."
[ -n "${PGPORT:-}" ] || fail "PGPORT is required."
[ -n "${PGDATABASE:-}" ] || fail "PGDATABASE is required."
[ -n "${PGUSER:-}" ] || fail "PGUSER is required."
[ -n "${PGPASSWORD:-}" ] || fail "PGPASSWORD is required."
[ -n "${BACKUP_DIR:-}" ] || fail "BACKUP_DIR is required."

case "$PGPORT" in
    *[!0-9]*|'') fail "PGPORT must be numeric." ;;
esac
case "$PGDATABASE" in
    *[!A-Za-z0-9_]*) fail "PGDATABASE contains unsupported characters." ;;
esac
case "$BACKUP_DIR" in
    /*) ;;
    *) fail "BACKUP_DIR must be an absolute path." ;;
esac
case "$BACKUP_DIR" in
    /|/var/lib/postgresql/data|/var/lib/postgresql/data/*)
        fail "BACKUP_DIR must be outside the PostgreSQL data directory."
        ;;
esac

retention_days="${BACKUP_RETENTION_DAYS:-14}"
case "$retention_days" in
    *[!0-9]*|'') fail "BACKUP_RETENTION_DAYS must be a positive integer." ;;
esac
[ "$retention_days" -gt 0 ] || fail "BACKUP_RETENTION_DAYS must be greater than zero."

mkdir -p "$BACKUP_DIR"
[ -d "$BACKUP_DIR" ] || fail "Backup directory is unavailable."
[ -w "$BACKUP_DIR" ] || fail "Backup directory is not writable."

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
filename="${PGDATABASE}_${timestamp}.dump"
final_file="$BACKUP_DIR/$filename"
partial_file="${final_file}.partial"
toc_file="${final_file}.toc.partial"

cleanup_partial() {
    rm -f -- "$partial_file" "$toc_file"
}
trap cleanup_partial EXIT HUP INT TERM

[ ! -e "$final_file" ] || fail "A backup with the same timestamp already exists."

pg_dump \
    --host="$PGHOST" \
    --port="$PGPORT" \
    --username="$PGUSER" \
    --dbname="$PGDATABASE" \
    --format=custom \
    --compress=9 \
    --no-owner \
    --no-privileges \
    --file="$partial_file"

[ -s "$partial_file" ] || fail "pg_dump produced an empty backup."
pg_restore --list "$partial_file" > "$toc_file"
[ -s "$toc_file" ] || fail "The backup catalog is empty or unreadable."

mv "$partial_file" "$final_file"
(
    cd "$BACKUP_DIR"
    sha256sum "$filename" > "${filename}.sha256"
)
chmod 600 "$final_file" "${final_file}.sha256"

# Retention applies only to dated backups for this database in the validated
# backup directory. Partial files are never considered successful backups.
find "$BACKUP_DIR" -maxdepth 1 -type f \
    \( -name "${PGDATABASE}_*.dump" -o -name "${PGDATABASE}_*.dump.sha256" \) \
    -mtime "+$retention_days" -delete

trap - EXIT HUP INT TERM
rm -f -- "$toc_file"

printf '%s\n' "BACKUP_OK"
printf '%s\n' "BACKUP_FILE=$final_file"
printf '%s\n' "BACKUP_CHECKSUM_FILE=${final_file}.sha256"
