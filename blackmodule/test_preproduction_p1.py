import os
from pathlib import Path
import subprocess
import sys
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class PreproductionP1Tests(unittest.TestCase):
    def _import_config(self, **overrides):
        environment = os.environ.copy()
        environment.update(
            {
                "BLACKMODULE_ENV": "production",
                "DATABASE_URL": "postgresql://pilot_user:strong-pilot-db-passphrase@db:5432/blackmodule",
                "SECRET_KEY": "pilot-session-secret-with-at-least-32-characters",
                "BLACKMODULE_API_KEY": "pilot-api-key-with-at-least-32-characters",
                "INITIAL_ADMIN_PASSWORD": "",
            }
        )
        environment.update(overrides)
        return subprocess.run(
            [sys.executable, "-c", "import app.config"],
            cwd=REPOSITORY_ROOT / "blackmodule",
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_production_configuration_accepts_strong_required_values(self):
        result = self._import_config()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_production_configuration_rejects_empty_secret(self):
        result = self._import_config(SECRET_KEY="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SECRET_KEY doit être défini et non vide", result.stderr)

    def test_production_configuration_rejects_change_me_secret(self):
        result = self._import_config(BLACKMODULE_API_KEY="CHANGE_ME_API_KEY")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("valeur d'exemple interdite", result.stderr)

    def test_production_configuration_rejects_development_database_password(self):
        result = self._import_config(
            DATABASE_URL="postgresql://blackmodule_user:blackmodule_password@db:5432/blackmodule"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DATABASE_URL contient une valeur d'exemple interdite", result.stderr)

    def test_development_keeps_existing_placeholder_compatibility(self):
        result = self._import_config(
            BLACKMODULE_ENV="development",
            DATABASE_URL="postgresql://blackmodule_user:blackmodule_password@db:5432/blackmodule",
            SECRET_KEY="CHANGE_ME_SECRET_KEY",
            BLACKMODULE_API_KEY="CHANGE_ME_API_KEY",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_production_compose_contains_runtime_safeguards(self):
        compose = (REPOSITORY_ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
        self.assertIn("condition: service_healthy", compose)
        self.assertIn("pg_isready", compose)
        self.assertIn("pids_limit: 256", compose)
        self.assertIn("mem_limit: 2g", compose)
        self.assertIn('cpus: "2.0"', compose)
        self.assertIn("BLACKMODULE_ENV: production", compose)
        self.assertIn("@sha256:", compose)

    def test_application_image_runs_as_non_root(self):
        dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn("COPY --chown=10001:10001", dockerfile)
        self.assertIn("@sha256:", dockerfile)


if __name__ == "__main__":
    unittest.main()
