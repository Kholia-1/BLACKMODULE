import os
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "blackmodule" / "app" / "main.py").read_text(encoding="utf-8")
MIGRATION = (
    ROOT
    / "blackmodule"
    / "alembic"
    / "versions"
    / "p3_0001_current_schema.py"
).read_text(encoding="utf-8")


class PreproductionP3Tests(unittest.TestCase):
    def test_01_alembic_scaffold_and_dependency_exist(self):
        self.assertTrue((ROOT / "alembic.ini").is_file())
        self.assertTrue((ROOT / "blackmodule" / "alembic" / "env.py").is_file())
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("alembic==1.18.4", requirements)

    def test_02_baseline_is_current_and_non_destructive(self):
        self.assertIn('revision = "p3_0001_current_schema"', MIGRATION)
        self.assertIn("Base.metadata.create_all", MIGRATION)
        self.assertNotIn("DROP TABLE", MIGRATION.upper())
        self.assertNotIn("TRUNCATE", MIGRATION.upper())
        downgrade = MIGRATION.split("def downgrade()", 1)[1]
        self.assertNotIn("op.drop_", downgrade)
        self.assertNotIn("DELETE FROM", downgrade.upper())

    def test_03_baseline_preserves_extensions_indexes_constraints_and_triggers(self):
        for marker in (
            "CREATE EXTENSION IF NOT EXISTS pg_trgm",
            "CREATE EXTENSION IF NOT EXISTS unaccent",
            "idx_sanction_entries_nom_trgm",
            "ix_alerts_queue",
            "fk_alerts_assigned_to_user_id",
            "trg_alert_quality_review_immutable",
            "trg_corrective_action_history_immutable",
            "trg_user_notification_history_immutable",
            "trg_external_notification_attempt_immutable",
        ):
            self.assertIn(marker, MIGRATION)
        self.assertIn("ALTER COLUMN role TYPE VARCHAR(50)", MIGRATION)

    def test_04_production_requires_revision_and_skips_local_bootstrap(self):
        self.assertIn("if IS_PRODUCTION:", MAIN)
        self.assertIn("_verify_managed_schema()", MAIN)
        self.assertIn("else:\n        _initialize_local_schema()", MAIN)
        production_branch = MAIN.split("def startup():", 1)[1].split(
            "def _initialize_local_schema", 1
        )[0]
        self.assertNotIn("Base.metadata.create_all", production_branch)

    def test_05_local_bootstrap_remains_available(self):
        local_bootstrap = MAIN.split("def _initialize_local_schema():", 1)[1]
        self.assertIn("Base.metadata.create_all(bind=engine)", local_bootstrap)
        self.assertIn("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS", local_bootstrap)

    def test_06_compose_exposes_explicit_migration_job(self):
        compose = yaml.safe_load((ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8"))
        migrate = compose["services"]["migrate"]
        self.assertEqual(["database-migration"], migrate["profiles"])
        self.assertEqual(["alembic", "-c", "/code/alembic.ini"], migrate["entrypoint"])
        self.assertEqual(["upgrade", "head"], migrate["command"])
        self.assertEqual("service_healthy", migrate["depends_on"]["db"]["condition"])

    def test_07_docker_image_contains_migration_assets(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("alembic.ini /code/alembic.ini", dockerfile)
        self.assertIn("blackmodule/alembic /code/blackmodule/alembic", dockerfile)

    def test_08_alembic_resolves_repository_and_container_app_paths(self):
        environment = (ROOT / "blackmodule" / "alembic" / "env.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('if (candidate / "app").is_dir()', environment)
        self.assertIn("sys.path.insert(0, str(candidate))", environment)


if __name__ == "__main__":
    unittest.main()
