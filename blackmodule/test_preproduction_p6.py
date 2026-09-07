from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _requirement_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


class PreproductionP6Tests(unittest.TestCase):
    def test_01_canonical_lock_contains_only_exact_versions(self):
        lines = _requirement_lines(ROOT / "requirements.txt")
        self.assertGreater(len(lines), 40)
        for line in lines:
            requirement = line.split(";", 1)[0].strip()
            self.assertRegex(
                requirement,
                r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^=<>!~\s]+$",
                line,
            )
            self.assertNotRegex(requirement, r">=|<=|~=|!=")

    def test_02_lock_has_no_duplicate_projects(self):
        names = []
        for line in _requirement_lines(ROOT / "requirements.txt"):
            name = re.split(r"\[|==", line, maxsplit=1)[0]
            names.append(name.lower().replace("_", "-"))
        self.assertEqual(len(names), len(set(names)))

    def test_03_nested_requirements_is_only_a_canonical_forwarder(self):
        self.assertEqual(
            ["-r ../requirements.txt"],
            _requirement_lines(ROOT / "blackmodule" / "requirements.txt"),
        )

    def test_04_runtime_and_format_dependencies_are_explicitly_locked(self):
        lock = "\n".join(_requirement_lines(ROOT / "requirements.txt")).lower()
        for project in (
            "fastapi==", "uvicorn[standard]==", "sqlalchemy==",
            "psycopg2-binary==", "alembic==", "defusedxml==",
            "openpyxl==", "pandas==", "xlrd==", "rapidfuzz==",
        ):
            self.assertIn(project, lock)
        self.assertIn("bcrypt==4.0.1", lock)
        self.assertIn("numpy==2.4.6", lock)

    def test_05_docker_uses_canonical_lock_and_pinned_installer(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("COPY requirements.txt /code/requirements.txt", dockerfile)
        self.assertIn("pip==26.1.2", dockerfile)
        self.assertIn("--requirement /code/requirements.txt", dockerfile)
        self.assertIn("python -m pip check", dockerfile)
        self.assertNotIn("pip install --upgrade pip", dockerfile)

    def test_06_runtime_images_remain_digest_pinned(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
        self.assertRegex(dockerfile, r"FROM python:[^\s]+@sha256:[a-f0-9]{64}")
        postgres_images = re.findall(
            r"image:\s*postgres:[^\s]+@sha256:[a-f0-9]{64}", compose
        )
        self.assertEqual(2, len(postgres_images))


if __name__ == "__main__":
    unittest.main()
