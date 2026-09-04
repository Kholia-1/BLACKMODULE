from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class PreproductionP2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backup_script = (REPOSITORY_ROOT / "scripts" / "postgres_backup.sh").read_text(encoding="utf-8")
        cls.restore_script = (REPOSITORY_ROOT / "scripts" / "postgres_restore_test.sh").read_text(encoding="utf-8")
        cls.compose = (REPOSITORY_ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")

    def test_backup_is_dated_atomic_and_uses_custom_pg_dump(self):
        self.assertIn("date -u +%Y%m%dT%H%M%SZ", self.backup_script)
        self.assertIn("--format=custom", self.backup_script)
        self.assertIn(".partial", self.backup_script)
        self.assertIn('mv "$partial_file" "$final_file"', self.backup_script)

    def test_backup_integrity_and_retention_are_enforced(self):
        self.assertIn("pg_restore --list", self.backup_script)
        self.assertIn("sha256sum", self.backup_script)
        self.assertIn('BACKUP_RETENTION_DAYS', self.backup_script)
        self.assertIn('-mtime "+$retention_days" -delete', self.backup_script)

    def test_restore_verifies_checksum_catalog_and_critical_counts(self):
        self.assertIn("sha256sum --check --status", self.restore_script)
        self.assertIn("pg_restore --list", self.restore_script)
        self.assertIn("--exit-on-error", self.restore_script)
        for table_name in ("users", "sanction_entries", "alerts", "import_batches", "approval_requests"):
            self.assertIn(table_name, self.restore_script)

    def test_restore_is_restricted_to_new_test_database(self):
        self.assertIn("_restore_test safety suffix", self.restore_script)
        self.assertIn("The restore target database already exists", self.restore_script)
        self.assertIn("The source database cannot be the restore target", self.restore_script)
        self.assertIn("dropdb", self.restore_script)

    def test_backup_storage_is_external_and_separate_from_database_volume(self):
        self.assertIn("blackmodule_postgres_backups:/backups", self.compose)
        self.assertIn("blackmodule_postgres_data:/var/lib/postgresql/data", self.compose)
        self.assertIn("external: true", self.compose)
        self.assertIn('profiles: ["database-tools"]', self.compose)

    def test_no_password_value_is_embedded_in_scripts(self):
        combined = self.backup_script + self.restore_script
        self.assertNotIn("blackmodule_password", combined)
        self.assertNotIn("CHANGE_ME", combined)
        self.assertNotIn("PGPASSWORD=", combined)

    def test_missing_configuration_has_explicit_safe_failure(self):
        for name in ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "BACKUP_DIR"):
            self.assertIn(f'{name} is required', self.backup_script)
        self.assertIn("BACKUP_FILE is required", self.restore_script)
        self.assertIn("RESTORE_TARGET_DATABASE is required", self.restore_script)


if __name__ == "__main__":
    unittest.main()
