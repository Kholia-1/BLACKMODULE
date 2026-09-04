#!/bin/sh
set -eu

umask 077

fail() {
    printf '%s\n' "RESTORE_ERROR: $1" >&2
    exit 1
}

[ -n "${PGHOST:-}" ] || fail "PGHOST is required."
[ -n "${PGPORT:-}" ] || fail "PGPORT is required."
[ -n "${PGDATABASE:-}" ] || fail "PGDATABASE is required."
[ -n "${PGUSER:-}" ] || fail "PGUSER is required."
[ -n "${PGPASSWORD:-}" ] || fail "PGPASSWORD is required."
[ -n "${BACKUP_DIR:-}" ] || fail "BACKUP_DIR is required."
[ -n "${BACKUP_FILE:-}" ] || fail "BACKUP_FILE is required."
[ -n "${RESTORE_TARGET_DATABASE:-}" ] || fail "RESTORE_TARGET_DATABASE is required."

case "$RESTORE_TARGET_DATABASE" in
    *[!A-Za-z0-9_]*) fail "RESTORE_TARGET_DATABASE contains unsupported characters." ;;
esac
case "$RESTORE_TARGET_DATABASE" in
    *_restore_test|*_restore_test_[A-Za-z0-9]*) ;;
    *) fail "The target database name must contain the _restore_test safety suffix." ;;
esac
[ "$RESTORE_TARGET_DATABASE" != "$PGDATABASE" ] || fail "The source database cannot be the restore target."

case "$BACKUP_DIR" in
    /*) ;;
    *) fail "BACKUP_DIR must be an absolute path." ;;
esac
case "$BACKUP_FILE" in
    "$BACKUP_DIR"/*.dump) ;;
    *) fail "BACKUP_FILE must be a .dump file located directly in BACKUP_DIR." ;;
esac

[ -s "$BACKUP_FILE" ] || fail "Backup file is missing or empty."
[ -s "${BACKUP_FILE}.sha256" ] || fail "Backup checksum file is missing."

backup_name="$(basename "$BACKUP_FILE")"
(
    cd "$BACKUP_DIR"
    sha256sum --check --status "${backup_name}.sha256"
) || fail "Backup checksum verification failed."
pg_restore --list "$BACKUP_FILE" > /dev/null || fail "Backup catalog verification failed."

target_exists="$(psql --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
    --dbname=postgres --tuples-only --no-align \
    --command="SELECT 1 FROM pg_database WHERE datname = '$RESTORE_TARGET_DATABASE';")"
[ -z "$target_exists" ] || fail "The restore target database already exists."

created_target=0
cleanup_failed_restore() {
    if [ "$created_target" -eq 1 ]; then
        dropdb --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
            --if-exists "$RESTORE_TARGET_DATABASE" >/dev/null 2>&1 || true
    fi
}
trap cleanup_failed_restore HUP INT TERM

createdb --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" "$RESTORE_TARGET_DATABASE"
created_target=1
if ! pg_restore \
    --host="$PGHOST" \
    --port="$PGPORT" \
    --username="$PGUSER" \
    --dbname="$RESTORE_TARGET_DATABASE" \
    --exit-on-error \
    --no-owner \
    --no-privileges \
    "$BACKUP_FILE"; then
    cleanup_failed_restore
    fail "pg_restore failed; the incomplete test database was removed."
fi

verify_tables="${RESTORE_VERIFY_TABLES:-users sanction_entries alerts import_batches approval_requests}"
for table_name in $verify_tables; do
    case "$table_name" in
        *[!A-Za-z0-9_]*) fail "RESTORE_VERIFY_TABLES contains an invalid table name." ;;
    esac
    source_exists="$(psql --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
        --dbname="$PGDATABASE" --tuples-only --no-align \
        --command="SELECT to_regclass('public.$table_name') IS NOT NULL;")"
    target_exists="$(psql --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
        --dbname="$RESTORE_TARGET_DATABASE" --tuples-only --no-align \
        --command="SELECT to_regclass('public.$table_name') IS NOT NULL;")"
    [ "$source_exists" = "t" ] || fail "Critical source table $table_name is missing."
    [ "$target_exists" = "t" ] || fail "Critical restored table $table_name is missing."

    source_count="$(psql --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
        --dbname="$PGDATABASE" --tuples-only --no-align \
        --command="SELECT count(*) FROM public.$table_name;")"
    target_count="$(psql --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
        --dbname="$RESTORE_TARGET_DATABASE" --tuples-only --no-align \
        --command="SELECT count(*) FROM public.$table_name;")"
    [ "$source_count" = "$target_count" ] || fail "Critical row count mismatch for $table_name."
    printf '%s\n' "RESTORE_COUNT_OK $table_name=$target_count"
done

trap - HUP INT TERM
printf '%s\n' "RESTORE_OK"
printf '%s\n' "RESTORE_DATABASE=$RESTORE_TARGET_DATABASE"
