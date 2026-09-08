"""A04 regression tests for technical-admin temporary password resets."""

import re
import unittest
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from app.config import BOOTSTRAP_PASSWORD_TTL_HOURS
from app.database import Base, get_db
from app.models import AuditLog, User
from app.routers import web
from app.security import CSRFMiddleware, ForcedPasswordChangeMiddleware, get_csrf_token
from app.services.auth_service import hash_password, verify_password
from app.services.authorization_service import (
    ROLE_ADMIN_TECHNIQUE,
    ROLE_ANALYSTE_CONFORMITE,
    ROLE_AUDITEUR,
    ROLE_CONSULTATION,
    ROLE_GESTIONNAIRE_LISTES,
    ROLE_SUPERVISEUR_CONFORMITE,
    session_user_payload,
)
from app.services.session_security_service import (
    SESSION_DEACTIVATION_REVISION_KEY,
    USER_PASSWORD_RESET_ACTION,
    SessionActivityMiddleware,
    account_deactivation_revision,
)


def _test_app(db, session_factory) -> FastAPI:
    app = FastAPI()
    app.add_middleware(CSRFMiddleware)
    app.add_middleware(SessionActivityMiddleware, session_factory=session_factory)
    app.add_middleware(ForcedPasswordChangeMiddleware)
    app.add_middleware(SessionMiddleware, secret_key="a04-local-test-session-key")

    @app.get("/_test/session/{user_id}")
    def set_session(user_id: UUID, request: Request):
        user = db.query(User).filter(User.id == user_id).first()
        request.session["user"] = session_user_payload(user)
        request.session[SESSION_DEACTIVATION_REVISION_KEY] = (
            account_deactivation_revision(db, user.id)
        )
        now = datetime.utcnow().isoformat()
        request.session["last_activity_at"] = now
        request.session["last_activity_persisted_at"] = now
        return {"csrf_token": get_csrf_token(request)}

    app.dependency_overrides[get_db] = lambda: db
    app.include_router(web.router)
    return app


class A04UserPasswordResetTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.db = self.session_factory()
        self.admin = self._user(
            "a04-admin", ROLE_ADMIN_TECHNIQUE, "A04-Admin-Initial!"
        )
        self.target = self._user(
            "a04-analyst", ROLE_ANALYSTE_CONFORMITE, "A04-Analyst-Initial!"
        )
        self.db.commit()
        self.client = TestClient(_test_app(self.db, self.session_factory))

    def tearDown(self):
        self.client.close()
        self.db.close()
        self.engine.dispose()

    def _user(self, username: str, role: str, password: str) -> User:
        user = User(
            username=username,
            full_name=f"Compte {username}",
            email=f"{username}@example.test",
            password_hash=hash_password(password),
            role=role,
            statut="ACTIF",
        )
        self.db.add(user)
        self.db.flush()
        return user

    def _session(self, user: User) -> str:
        response = self.client.get(f"/_test/session/{user.id}")
        self.assertEqual(response.status_code, 200)
        return response.json()["csrf_token"]

    def _reset(self, password: str, confirmation: str | None = None, *, token=None):
        return self.client.post(
            f"/web/users/{self.target.id}/reset-password",
            data={
                "csrf_token": token or self._session(self.admin),
                "temporary_password": password,
                "confirm_password": confirmation if confirmation is not None else password,
            },
            follow_redirects=False,
        )

    def _login(self, username: str, password: str):
        page = self.client.get("/web/login")
        token_match = re.search(
            r'name="csrf_token" value="([^"]+)"', page.text
        )
        self.assertIsNotNone(token_match)
        return self.client.post(
            "/web/login",
            data={
                "csrf_token": token_match.group(1),
                "username": username,
                "password": password,
            },
            follow_redirects=False,
        )

    def test_01_admin_sets_a_temporary_password_and_unlocks_the_account(self):
        old_hash = self.target.password_hash
        self.target.failed_login_attempts = 5
        self.target.locked_at = datetime.utcnow() - timedelta(minutes=10)
        self.target.password_changed_at = datetime.utcnow() - timedelta(days=30)
        self.db.commit()
        reset_started_at = datetime.utcnow()
        temporary_password = "A04-Temporary-2026!"

        response = self._reset(temporary_password)

        self.assertEqual(response.status_code, 303)
        self.db.refresh(self.target)
        self.assertNotEqual(self.target.password_hash, old_hash)
        self.assertTrue(verify_password(temporary_password, self.target.password_hash))
        self.assertEqual(self.target.failed_login_attempts, 0)
        self.assertIsNone(self.target.locked_at)
        self.assertTrue(self.target.must_change_password)
        self.assertIsNone(self.target.password_changed_at)
        expected_expiry = reset_started_at + timedelta(
            hours=BOOTSTRAP_PASSWORD_TTL_HOURS
        )
        self.assertLess(
            abs((self.target.bootstrap_credential_expires_at - expected_expiry).total_seconds()),
            5,
        )

        audit = self.db.query(AuditLog).filter(
            AuditLog.action == USER_PASSWORD_RESET_ACTION
        ).one()
        self.assertEqual(audit.user_identifier, self.admin.username)
        self.assertEqual(audit.entity_id, str(self.target.id))
        self.assertEqual(
            audit.description,
            "Mot de passe temporaire défini par un administrateur technique.",
        )
        audit_text = " ".join(
            str(value)
            for value in (audit.action, audit.description, audit.user_identifier)
        )
        self.assertNotIn(temporary_password, audit_text)
        self.assertNotIn(self.target.password_hash, audit_text)

    def test_02_invalid_or_unconfirmed_password_is_not_persisted_or_audited(self):
        original_hash = self.target.password_hash

        mismatch = self._reset("A04-Temporary-2026!", "A04-Different-2026!")
        self.assertEqual(mismatch.status_code, 303)
        self.assertIn("correspondent", mismatch.headers["location"])
        weak = self._reset("short")
        self.assertEqual(weak.status_code, 303)

        self.db.refresh(self.target)
        self.assertEqual(self.target.password_hash, original_hash)
        self.assertFalse(self.target.must_change_password)
        self.assertIsNone(self.target.bootstrap_credential_expires_at)
        self.assertEqual(
            self.db.query(AuditLog).filter(
                AuditLog.action == USER_PASSWORD_RESET_ACTION
            ).count(),
            0,
        )

    def test_03_backend_rbac_and_csrf_protect_the_reset(self):
        original_hash = self.target.password_hash
        non_admins = [self.target]
        for role in (
            ROLE_SUPERVISEUR_CONFORMITE,
            ROLE_GESTIONNAIRE_LISTES,
            ROLE_AUDITEUR,
            ROLE_CONSULTATION,
        ):
            non_admins.append(
                self._user(f"a04-{role.lower()}", role, "A04-Forbidden-Initial!")
            )
        self.db.commit()

        for user in non_admins:
            with self.subTest(role=user.role):
                denied = self._reset(
                    "A04-Forbidden-2026!", token=self._session(user)
                )
                self.assertEqual(denied.status_code, 403)
        self._session(self.admin)
        missing_csrf = self.client.post(
            f"/web/users/{self.target.id}/reset-password",
            data={
                "temporary_password": "A04-No-Csrf-2026!",
                "confirm_password": "A04-No-Csrf-2026!",
            },
        )
        self.assertEqual(missing_csrf.status_code, 403)

        self.db.refresh(self.target)
        self.assertEqual(self.target.password_hash, original_hash)
        self.assertEqual(
            self.db.query(AuditLog).filter(
                AuditLog.action == USER_PASSWORD_RESET_ACTION
            ).count(),
            0,
        )

    def test_04_reset_revokes_old_session_and_forces_change_after_new_login(self):
        target_client = TestClient(_test_app(self.db, self.session_factory))
        target_client.get("/web/login")
        login_page = target_client.get("/web/login")
        login_token = re.search(
            r'name="csrf_token" value="([^"]+)"', login_page.text
        ).group(1)
        old_login = target_client.post(
            "/web/login",
            data={
                "csrf_token": login_token,
                "username": self.target.username,
                "password": "A04-Analyst-Initial!",
            },
            follow_redirects=False,
        )
        self.assertEqual(old_login.headers["location"], "/web/dashboard")

        temporary_password = "A04-New-Temporary-2026!"
        self.assertEqual(self._reset(temporary_password).status_code, 303)
        revoked = target_client.get("/web/dashboard", follow_redirects=False)
        self.assertEqual(revoked.status_code, 303)
        self.assertEqual(revoked.headers["location"], "/web/login?message=session_revoked")
        target_client.close()

        login = self._login(self.target.username, temporary_password)
        self.assertEqual(login.status_code, 303)
        self.assertEqual(login.headers["location"], "/web/change-password")
        blocked = self.client.get("/web/dashboard", follow_redirects=False)
        self.assertEqual(blocked.status_code, 303)
        self.assertEqual(blocked.headers["location"], "/web/change-password")

        session_cookie_page = self.client.get("/web/change-password")
        csrf_token = re.search(
            r'name="csrf_token" value="([^"]+)"', session_cookie_page.text
        ).group(1)
        permanent_password = "A04-Permanent-2026!"
        changed = self.client.post(
            "/web/change-password",
            data={
                "csrf_token": csrf_token,
                "old_password": temporary_password,
                "new_password": permanent_password,
                "confirm_password": permanent_password,
            },
        )
        self.assertEqual(changed.status_code, 200)

        self.db.refresh(self.target)
        self.assertTrue(verify_password(permanent_password, self.target.password_hash))
        self.assertFalse(self.target.must_change_password)
        self.assertIsNone(self.target.bootstrap_credential_expires_at)
        self.assertIsNotNone(self.target.password_changed_at)
        self.assertEqual(self.client.get("/web/dashboard").status_code, 200)

    def test_05_user_screen_exposes_only_a_masked_csrf_protected_reset_form(self):
        self._session(self.admin)
        page = self.client.get("/web/users")

        self.assertEqual(page.status_code, 200)
        self.assertIn("Réinitialiser le mot de passe", page.text)
        self.assertIn('name="temporary_password"', page.text)
        self.assertIn('name="confirm_password"', page.text)
        self.assertIn('type="password"', page.text)
        self.assertIn('name="csrf_token"', page.text)
        self.assertNotIn(self.target.password_hash, page.text)


if __name__ == "__main__":
    unittest.main()
