"""Regression tests for the technical-admin user edit screen."""

import unittest
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from app.database import Base, get_db
from app.models import AuditLog, User
from app.routers import web
from app.services.authorization_service import (
    ALL_ROLES,
    ROLE_ADMIN_TECHNIQUE,
    ROLE_ANALYSTE_CONFORMITE,
    ROLE_CONSULTATION,
)


def _test_app(db) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="user-edit-local-test")

    @app.get("/_test/login/{role}")
    def login(request: Request, role: str):
        user = db.query(User).filter(User.role == role).first()
        request.session["user"] = {
            "id": str(user.id),
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
        }
        return {"status": "ok"}

    app.dependency_overrides[get_db] = lambda: db
    app.include_router(web.router)
    return app


class UserManagementEditTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine, expire_on_commit=False)()
        self.admin = self.user("admin-user-edit", ROLE_ADMIN_TECHNIQUE)
        self.analyst = self.user("analyst-user-edit", ROLE_ANALYSTE_CONFORMITE)
        self.viewer = self.user("viewer-user-edit", ROLE_CONSULTATION)
        self.target = self.user(
            "fixed-username",
            ROLE_CONSULTATION,
            full_name="Ancien nom",
            email="target@example.test",
            role_assigned_at=datetime(2025, 1, 15, 10, 30),
        )
        self.other = self.user("other-user-edit", ROLE_CONSULTATION, email="other@example.test")
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def user(self, username, role, *, full_name=None, email=None, role_assigned_at=None):
        user = User(
            username=username,
            full_name=full_name or username,
            email=email or f"{username}@example.test",
            password_hash="unchanged-password-hash",
            role=role,
            statut="ACTIF",
            role_assigned_at=role_assigned_at,
        )
        self.db.add(user)
        self.db.flush()
        return user

    def login(self, role):
        client = TestClient(_test_app(self.db))
        self.assertEqual(client.get(f"/_test/login/{role}").status_code, 200)
        return client

    def edit_url(self):
        return f"/web/users/{self.target.id}/edit"

    def test_01_technical_admin_can_view_the_edit_form_with_username_read_only(self):
        page = self.login(ROLE_ADMIN_TECHNIQUE).get(self.edit_url())

        self.assertEqual(page.status_code, 200)
        self.assertIn('value="fixed-username" disabled', page.text)
        self.assertNotIn('name="username"', page.text)
        self.assertNotIn('name="password"', page.text)
        for role in ALL_ROLES:
            self.assertIn(f'value="{role}"', page.text)

    def test_02_edit_persists_allowed_fields_keeps_username_and_password_and_writes_safe_audit(self):
        client = self.login(ROLE_ADMIN_TECHNIQUE)
        original_hash = self.target.password_hash
        previous_role_assigned_at = self.target.role_assigned_at

        response = client.post(
            self.edit_url(),
            data={
                "username": "attempted-change-is-ignored",
                "full_name": "  Nouveau nom  ",
                "email": "NEW.EMAIL@EXAMPLE.TEST",
                "role": "analyste_conformite",
                "statut": "inactif",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.db.refresh(self.target)
        self.assertEqual(self.target.username, "fixed-username")
        self.assertEqual(self.target.password_hash, original_hash)
        self.assertEqual(self.target.full_name, "Nouveau nom")
        self.assertEqual(self.target.email, "new.email@example.test")
        self.assertEqual(self.target.role, ROLE_ANALYSTE_CONFORMITE)
        self.assertEqual(self.target.statut, "INACTIF")
        self.assertGreater(self.target.role_assigned_at, previous_role_assigned_at)

        audit = self.db.query(AuditLog).filter(AuditLog.action == "UPDATE_USER").one()
        self.assertEqual(audit.entity_id, str(self.target.id))
        self.assertIn("fixed-username", audit.description)
        self.assertIn("nom complet", audit.description)
        self.assertIn("email", audit.description)
        self.assertIn("rôle", audit.description)
        self.assertIn("statut", audit.description)
        self.assertNotIn("Nouveau nom", audit.description)
        self.assertNotIn("new.email@example.test", audit.description)

    def test_03_same_role_keeps_role_assigned_at_and_email_must_remain_unique_case_insensitively(self):
        client = self.login(ROLE_ADMIN_TECHNIQUE)
        assigned_at = self.target.role_assigned_at
        self.assertEqual(
            client.post(
                self.edit_url(),
                data={
                    "full_name": "Nom actualise",
                    "email": "target-updated@example.test",
                    "role": ROLE_CONSULTATION,
                    "statut": "ACTIF",
                },
                follow_redirects=False,
            ).status_code,
            303,
        )
        self.db.refresh(self.target)
        self.assertEqual(self.target.role_assigned_at, assigned_at)

        response = client.post(
            self.edit_url(),
            data={
                "full_name": "Ne doit pas etre ecrit",
                "email": "OTHER@EXAMPLE.TEST",
                "role": ROLE_ANALYSTE_CONFORMITE,
                "statut": "INACTIF",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn("Email", response.headers["location"])
        self.db.refresh(self.target)
        self.assertEqual(self.target.full_name, "Nom actualise")
        self.assertEqual(self.target.email, "target-updated@example.test")
        self.assertEqual(self.target.role, ROLE_CONSULTATION)

    def test_04_invalid_role_or_status_is_rejected_and_non_admin_roles_cannot_edit(self):
        admin_client = self.login(ROLE_ADMIN_TECHNIQUE)
        for payload in (
            {"role": "NOT_A_BLACKMODULE_ROLE", "statut": "ACTIF"},
            {"role": ROLE_CONSULTATION, "statut": "SUSPENDU"},
        ):
            with self.subTest(payload=payload):
                response = admin_client.post(self.edit_url(), data=payload)
                self.assertEqual(response.status_code, 400)

        for role in (ROLE_ANALYSTE_CONFORMITE, ROLE_CONSULTATION):
            with self.subTest(role=role):
                client = self.login(role)
                self.assertEqual(client.get(self.edit_url()).status_code, 403)
                response = client.post(
                    self.edit_url(),
                    data={
                        "full_name": "Interdit",
                        "email": "forbidden@example.test",
                        "role": ROLE_ANALYSTE_CONFORMITE,
                        "statut": "ACTIF",
                    },
                )
                self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
