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
from app.models import Alert, AlertAssignmentHistory, AlertDecisionHistory, AuditLog, User
from app.routers import alerts, web
from app.services.auth_service import authenticate_user, hash_password
from app.services.authorization_service import (
    ALL_ROLES,
    ROLE_ADMIN_TECHNIQUE,
    ROLE_ANALYSTE_CONFORMITE,
    ROLE_AUDITEUR,
    ROLE_CONSULTATION,
    ROLE_GESTIONNAIRE_LISTES,
    ROLE_SUPERVISEUR_CONFORMITE,
)
from app.services.session_security_service import SessionActivityMiddleware


def _test_app(db, *, session_factory=None, include_alerts=False) -> FastAPI:
    app = FastAPI()
    if session_factory:
        app.add_middleware(SessionActivityMiddleware, session_factory=session_factory)
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
    if include_alerts:
        app.include_router(alerts.router)
    return app


class UserManagementEditTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.db = self.session_factory()
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

    def toggle_url(self, user=None):
        return f"/web/users/{(user or self.target).id}/toggle-status"

    def session_validated_client(self, *, include_alerts=False):
        return TestClient(_test_app(
            self.db,
            session_factory=self.session_factory,
            include_alerts=include_alerts,
        ))

    def authenticate_client(self, client, user, password):
        user.password_hash = hash_password(password)
        self.db.commit()
        response = client.post(
            "/web/login",
            data={"username": user.username, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        return response

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

    def test_05_deactivation_preserves_account_password_and_historical_references(self):
        alert = Alert(
            client_reference="USER-LIFECYCLE-HISTORY",
            client_nom="Client historique",
            statut="EN_COURS",
            assigned_to_user_id=self.target.id,
            assigned_to=self.target.username,
        )
        self.db.add(alert)
        self.db.flush()
        assignment = AlertAssignmentHistory(
            alert_id=alert.id,
            action="ASSIGNATION",
            to_user_id=self.target.id,
            to_username=self.target.username,
            changed_by_user_id=self.admin.id,
            changed_by_username=self.admin.username,
        )
        self.db.add(assignment)
        self.db.commit()
        original_hash = self.target.password_hash
        user_count = self.db.query(User).count()

        response = self.login(ROLE_ADMIN_TECHNIQUE).post(
            self.toggle_url(), follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.db.refresh(self.target)
        self.assertEqual(self.target.statut, "INACTIF")
        self.assertEqual(self.target.password_hash, original_hash)
        self.assertEqual(self.db.query(User).count(), user_count)
        self.assertIsNotNone(self.db.get(Alert, alert.id))
        persisted_assignment = self.db.get(AlertAssignmentHistory, assignment.id)
        self.assertIsNotNone(persisted_assignment)
        self.assertEqual(persisted_assignment.to_user_id, self.target.id)

        authentication = authenticate_user(self.db, self.target.username, "any-password")
        self.assertIsNone(authentication.user)
        self.assertEqual(authentication.reason, "INVALID")

        audit = self.db.query(AuditLog).filter(AuditLog.action == "USER_DEACTIVATED").one()
        self.assertEqual(audit.entity_id, str(self.target.id))
        self.assertEqual(audit.user_identifier, self.admin.username)
        self.assertEqual(audit.description, "Compte utilisateur désactivé.")
        for sensitive_value in (self.target.full_name, self.target.email, original_hash):
            self.assertNotIn(sensitive_value, audit.description)

    def test_06_inactive_account_can_be_reactivated_without_password_change(self):
        self.target.statut = "INACTIF"
        self.db.commit()
        original_hash = self.target.password_hash

        response = self.login(ROLE_ADMIN_TECHNIQUE).post(
            self.toggle_url(), follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.db.refresh(self.target)
        self.assertEqual(self.target.statut, "ACTIF")
        self.assertEqual(self.target.password_hash, original_hash)
        audit = self.db.query(AuditLog).filter(AuditLog.action == "USER_REACTIVATED").one()
        self.assertEqual(audit.entity_id, str(self.target.id))
        self.assertEqual(audit.description, "Compte utilisateur réactivé.")

    def test_07_technical_admin_cannot_deactivate_own_account(self):
        response = self.login(ROLE_ADMIN_TECHNIQUE).post(
            self.toggle_url(self.admin), follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.db.refresh(self.admin)
        self.assertEqual(self.admin.statut, "ACTIF")
        self.assertEqual(
            self.db.query(AuditLog).filter(
                AuditLog.action == "USER_DEACTIVATED",
                AuditLog.entity_id == str(self.admin.id),
            ).count(),
            0,
        )

    def test_08_last_active_technical_admin_cannot_be_deactivated(self):
        last_admin = self.user("last-active-admin", ROLE_ADMIN_TECHNIQUE)
        self.admin.statut = "INACTIF"
        self.db.commit()

        response = self.login(ROLE_ADMIN_TECHNIQUE).post(
            self.toggle_url(last_admin), follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertIn("Conservez", response.headers["location"])
        self.db.refresh(last_admin)
        self.assertEqual(last_admin.statut, "ACTIF")
        self.assertEqual(
            self.db.query(AuditLog).filter(
                AuditLog.action == "USER_DEACTIVATED",
                AuditLog.entity_id == str(last_admin.id),
            ).count(),
            0,
        )

    def test_09_non_admin_roles_cannot_toggle_an_account(self):
        for role in (
            ROLE_SUPERVISEUR_CONFORMITE,
            ROLE_ANALYSTE_CONFORMITE,
            ROLE_GESTIONNAIRE_LISTES,
            ROLE_AUDITEUR,
            ROLE_CONSULTATION,
        ):
            if not self.db.query(User).filter(User.role == role).first():
                self.user(f"lifecycle-{role.lower()}", role)
        self.db.commit()

        for role in (
            ROLE_SUPERVISEUR_CONFORMITE,
            ROLE_ANALYSTE_CONFORMITE,
            ROLE_GESTIONNAIRE_LISTES,
            ROLE_AUDITEUR,
            ROLE_CONSULTATION,
        ):
            with self.subTest(role=role):
                response = self.login(role).post(self.toggle_url())
                self.assertEqual(response.status_code, 403)
                self.db.refresh(self.target)
                self.assertEqual(self.target.statut, "ACTIF")

        self.assertEqual(
            self.db.query(AuditLog).filter(AuditLog.action == "USER_DEACTIVATED").count(),
            0,
        )

    def test_10_user_list_uses_explicit_actions_and_confirmation_only_for_deactivation(self):
        client = self.login(ROLE_ADMIN_TECHNIQUE)
        active_page = client.get("/web/users")
        self.assertEqual(active_page.status_code, 200)
        active_form_start = active_page.text.index(f'action="{self.toggle_url()}"')
        active_form = active_page.text[active_form_start:active_form_start + 400]
        self.assertIn("data-confirm=", active_form)
        self.assertIn("Désactiver", active_form)

        self.target.statut = "INACTIF"
        self.db.commit()
        inactive_page = client.get("/web/users")
        inactive_form_start = inactive_page.text.index(f'action="{self.toggle_url()}"')
        inactive_form = inactive_page.text[inactive_form_start:inactive_form_start + 400]
        self.assertNotIn("data-confirm=", inactive_form)
        self.assertIn("Réactiver", inactive_form)

    def test_11_unexpected_stored_status_is_not_silently_toggled(self):
        self.target.statut = "STATUT_INCONNU"
        self.db.commit()

        response = self.login(ROLE_ADMIN_TECHNIQUE).post(self.toggle_url())

        self.assertEqual(response.status_code, 409)
        self.db.refresh(self.target)
        self.assertEqual(self.target.statut, "STATUT_INCONNU")

    def test_12_open_session_is_cleared_on_first_request_after_deactivation(self):
        password = "Local-A03-Password!"
        user_client = self.session_validated_client()
        self.authenticate_client(user_client, self.analyst, password)
        self.assertEqual(user_client.get("/web/dashboard").status_code, 200)

        admin_client = self.session_validated_client()
        self.authenticate_client(admin_client, self.admin, "Local-Admin-A03!")
        self.assertEqual(
            admin_client.post(
                self.toggle_url(self.analyst), follow_redirects=False,
            ).status_code,
            303,
        )

        refused = user_client.get("/web/dashboard", follow_redirects=False)
        self.assertEqual(refused.status_code, 303)
        self.assertEqual(refused.headers["location"], "/web/login?message=account_inactive")

        self.assertEqual(
            admin_client.post(
                self.toggle_url(self.analyst), follow_redirects=False,
            ).status_code,
            303,
        )
        still_logged_out = user_client.get("/web/dashboard", follow_redirects=False)
        self.assertEqual(still_logged_out.status_code, 303)
        self.assertEqual(still_logged_out.headers["location"], "/web/login")

        self.authenticate_client(user_client, self.analyst, password)
        self.assertEqual(user_client.get("/web/dashboard").status_code, 200)
        self.assertEqual(
            self.db.query(AuditLog).filter(AuditLog.action == "USER_DEACTIVATED").count(),
            1,
        )
        self.assertEqual(
            self.db.query(AuditLog).filter(AuditLog.action == "USER_REACTIVATED").count(),
            1,
        )

    def test_13_reactivation_before_next_request_does_not_revive_old_session(self):
        password = "Local-A03-Reactivation!"
        user_client = self.session_validated_client()
        self.authenticate_client(user_client, self.analyst, password)

        admin_client = self.session_validated_client()
        self.authenticate_client(admin_client, self.admin, "Local-Admin-Reactivation!")
        admin_client.post(self.toggle_url(self.analyst), follow_redirects=False)
        admin_client.post(self.toggle_url(self.analyst), follow_redirects=False)
        self.db.refresh(self.analyst)
        self.assertEqual(self.analyst.statut, "ACTIF")

        refused = user_client.get("/web/dashboard", follow_redirects=False)
        self.assertEqual(refused.status_code, 303)
        self.assertEqual(refused.headers["location"], "/web/login?message=session_revoked")

        self.authenticate_client(user_client, self.analyst, password)
        self.assertEqual(user_client.get("/web/dashboard").status_code, 200)

    def test_14_deactivated_session_cannot_execute_a_business_action(self):
        alert = Alert(
            client_reference="A03-BUSINESS-ACTION",
            client_nom="Client A03",
            statut="GENEREE",
            niveau_alerte="ALERTE_PROBABLE",
        )
        self.db.add(alert)
        self.db.commit()

        analyst_client = self.session_validated_client(include_alerts=True)
        self.authenticate_client(analyst_client, self.analyst, "Local-A03-Action!")
        admin_client = self.session_validated_client()
        self.authenticate_client(admin_client, self.admin, "Local-Admin-Action!")
        admin_client.post(self.toggle_url(self.analyst), follow_redirects=False)

        response = analyst_client.put(
            f"/api/alerts/{alert.id}/treat",
            json={"statut": "EN_COURS", "treatment_comment": "must not be applied"},
        )

        self.assertEqual(response.status_code, 401)
        self.db.refresh(alert)
        self.assertEqual(alert.statut, "GENEREE")
        self.assertEqual(
            self.db.query(AlertDecisionHistory).filter(
                AlertDecisionHistory.alert_id == alert.id,
            ).count(),
            0,
        )

    def test_15_active_account_keeps_its_existing_session(self):
        client = self.session_validated_client()
        self.authenticate_client(client, self.viewer, "Local-A03-Active!")

        self.assertEqual(client.get("/web/dashboard").status_code, 200)
        self.assertEqual(client.get("/web/dashboard").status_code, 200)
        self.db.refresh(self.viewer)
        self.assertEqual(self.viewer.statut, "ACTIF")


if __name__ == "__main__":
    unittest.main()
