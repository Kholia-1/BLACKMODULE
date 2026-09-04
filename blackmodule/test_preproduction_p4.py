import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timedelta
import unittest
from unittest.mock import patch

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

from app.models import User
from app.routers import external_api
from app.services.auth_service import authenticate_user, create_default_admin, hash_password
from app.services.password_policy_service import validate_password_policy
from app.security import (
    ForcedPasswordChangeMiddleware,
    SecurityRateLimitMiddleware,
    SlidingWindowRateLimiter,
    security_rate_limiter,
)


ROOT = Path(__file__).resolve().parents[1]


class _Query:
    def __init__(self, user):
        self.user = user

    def filter(self, *_args):
        return self

    def first(self):
        return self.user


class _Db:
    def __init__(self, user=None):
        self.user = user
        self.added = []

    def query(self, _model):
        return _Query(self.user)

    def add(self, item):
        self.added.append(item)
        if isinstance(item, User):
            self.user = item

    def commit(self):
        pass

    def refresh(self, _item):
        pass


def _request(path: str = "/api/external/status") -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )


class PreproductionP4Tests(unittest.TestCase):
    def tearDown(self):
        security_rate_limiter.clear()

    def test_01_production_password_policy_is_strong_but_local_remains_compatible(self):
        self.assertIsNone(validate_password_policy("local1", production=False))
        self.assertIsNotNone(validate_password_policy("short", production=True))
        self.assertIsNotNone(validate_password_policy("alllowercase123!", production=True))
        self.assertIsNotNone(
            validate_password_policy("Admin-Secure-2026!", username="admin", production=True)
        )
        self.assertIsNone(
            validate_password_policy("Pilot-Secure-2026!", username="admin", production=True)
        )

    def test_02_production_bootstrap_requires_change_and_has_an_expiry(self):
        before = datetime.utcnow()
        db = _Db()
        user = create_default_admin(
            db, "Pilot-Secure-2026!", production=True
        )
        self.assertTrue(user.must_change_password)
        self.assertIsNotNone(user.bootstrap_credential_expires_at)
        self.assertGreater(user.bootstrap_credential_expires_at, before)
        self.assertNotIn("Pilot-Secure-2026!", user.password_hash)

    def test_03_expired_bootstrap_secret_is_rejected(self):
        user = User(
            username="admin",
            statut="ACTIF",
            password_hash=hash_password("Pilot-Secure-2026!"),
            must_change_password=True,
            bootstrap_credential_expires_at=datetime.utcnow() - timedelta(seconds=1),
        )
        result = authenticate_user(_Db(user), "admin", "Pilot-Secure-2026!")
        self.assertIsNone(result.user)
        self.assertEqual("BOOTSTRAP_EXPIRED", result.reason)

    def test_04_forced_change_blocks_application_but_allows_change_page(self):
        test_app = FastAPI()
        test_app.add_middleware(ForcedPasswordChangeMiddleware)
        test_app.add_middleware(SessionMiddleware, secret_key="test-session-key")

        @test_app.get("/set-session")
        def set_session(request: Request):
            request.session["user"] = {
                "username": "admin", "must_change_password": True
            }
            return {"ok": True}

        @test_app.get("/web/dashboard")
        def dashboard():
            return {"ok": True}

        @test_app.get("/web/change-password")
        def change_password():
            return {"ok": True}

        client = TestClient(test_app)
        self.assertEqual(200, client.get("/set-session").status_code)
        blocked = client.get("/web/dashboard", follow_redirects=False)
        self.assertEqual(303, blocked.status_code)
        self.assertEqual("/web/change-password", blocked.headers["location"])
        self.assertEqual(200, client.get("/web/change-password").status_code)

    def test_04b_expired_bootstrap_session_is_invalidated(self):
        test_app = FastAPI()
        test_app.add_middleware(ForcedPasswordChangeMiddleware)
        test_app.add_middleware(SessionMiddleware, secret_key="test-session-key")

        @test_app.get("/set-session")
        def set_session(request: Request):
            request.session["user"] = {
                "id": "bootstrap-id",
                "username": "admin",
                "must_change_password": True,
                "bootstrap_credential_expires_at": (
                    datetime.utcnow() - timedelta(seconds=1)
                ).isoformat(),
            }
            return {"ok": True}

        @test_app.get("/web/dashboard")
        def dashboard():
            return {"ok": True}

        client = TestClient(test_app)
        client.get("/set-session")
        with patch.object(ForcedPasswordChangeMiddleware, "_audit_expiration"):
            response = client.get("/web/dashboard", follow_redirects=False)
        self.assertEqual(303, response.status_code)
        self.assertIn("bootstrap_expired", response.headers["location"])

    def test_05_docs_and_openapi_are_disabled_only_in_production(self):
        environment = os.environ.copy()
        environment.update(
            {
                "BLACKMODULE_ENV": "production",
                "DATABASE_URL": "postgresql://pilot_user:strong-pilot-pass@db:5432/blackmodule",
                "SECRET_KEY": "pilot-session-secret-with-at-least-32-characters",
                "BLACKMODULE_API_KEY": "pilot-api-key-with-at-least-32-characters",
                "INITIAL_ADMIN_PASSWORD": "",
            }
        )
        command = (
            "import json; from app.main import app; "
            "print(json.dumps([app.docs_url, app.redoc_url, app.openapi_url]))"
        )
        result = subprocess.run(
            [sys.executable, "-c", command],
            cwd=ROOT / "blackmodule",
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([None, None, None], json.loads(result.stdout.strip()))

    def test_06_db_check_never_exposes_database_exception(self):
        from app import main

        class BrokenDb:
            def execute(self, _statement):
                raise RuntimeError("password=TOP-SECRET database internals")

        with patch.object(main, "IS_PRODUCTION", True):
            with self.assertRaises(HTTPException) as production_error:
                main.db_check(BrokenDb())
        self.assertEqual(404, production_error.exception.status_code)

        with patch.object(main, "IS_PRODUCTION", False):
            with self.assertRaises(HTTPException) as local_error:
                main.db_check(BrokenDb())
        self.assertEqual(503, local_error.exception.status_code)
        self.assertNotIn("TOP-SECRET", str(local_error.exception.detail))

    def test_07_api_key_uses_constant_time_comparison_and_logs_no_key(self):
        db = _Db()
        with patch.object(
            external_api.secrets,
            "compare_digest",
            wraps=external_api.secrets.compare_digest,
        ) as compare:
            self.assertTrue(
                external_api.verify_api_key(
                    _request(), x_api_key=external_api.EXTERNAL_API_KEY, db=db
                )
            )
            compare.assert_called_once()

        submitted_secret = "invalid-api-key-that-must-not-be-logged"
        with self.assertRaises(HTTPException):
            external_api.verify_api_key(
                _request(), x_api_key=submitted_secret, db=db
            )
        rendered_audit = " ".join(
            str(item.description) for item in db.added if hasattr(item, "description")
        )
        self.assertNotIn(submitted_secret, rendered_audit)

    def test_08_sliding_window_limiter_refuses_after_limit(self):
        limiter = SlidingWindowRateLimiter()
        self.assertTrue(limiter.consume("key", 2, 60).allowed)
        self.assertTrue(limiter.consume("key", 2, 60).allowed)
        rejected = limiter.consume("key", 2, 60)
        self.assertFalse(rejected.allowed)
        self.assertGreaterEqual(rejected.retry_after, 1)
        self.assertTrue(rejected.should_log)

    def test_09_login_rate_limit_returns_429_and_retry_after(self):
        test_app = FastAPI()
        test_app.add_middleware(SecurityRateLimitMiddleware)
        test_app.add_middleware(SessionMiddleware, secret_key="test-session-key")

        @test_app.post("/web/login")
        def login():
            return JSONResponse({"ok": True})

        client = TestClient(test_app)
        with patch.object(SecurityRateLimitMiddleware, "_audit_rejection"):
            for _ in range(10):
                self.assertEqual(200, client.post("/web/login").status_code)
            rejected = client.post("/web/login")
        self.assertEqual(429, rejected.status_code)
        self.assertIn("Retry-After", rejected.headers)

    def test_10_p4_migration_is_additive_idempotent_and_non_destructive(self):
        migration = (
            ROOT
            / "blackmodule"
            / "alembic"
            / "versions"
            / "p4_0002_security_hardening.py"
        ).read_text(encoding="utf-8")
        self.assertIn('revision = "p4_0002_security_hardening"', migration)
        self.assertIn('down_revision = "p3_0001_current_schema"', migration)
        self.assertIn("ADD COLUMN IF NOT EXISTS", migration)
        self.assertNotIn("DROP TABLE", migration.upper())
        self.assertNotIn("TRUNCATE", migration.upper())

    def test_11_password_change_failures_are_audited_without_submitted_values(self):
        web_source = (ROOT / "blackmodule" / "app" / "routers" / "web.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('action="PASSWORD_CHANGE_FAILED"', web_source)
        generic_description = (
            "Changement de mot de passe refusé par un contrôle de sécurité."
        )
        self.assertIn(generic_description, web_source)


if __name__ == "__main__":
    unittest.main()
