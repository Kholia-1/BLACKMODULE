"""LOT 4C regression tests for alert decisions and closure."""

import json
import re
import unittest
from datetime import datetime, timedelta

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from app.database import Base, get_db
from app.models import Alert, AlertDecisionHistory, ApprovalRequest, AuditLog, User
from app.routers import alerts, web
from app.services.alert_decision_service import (
    APPLIED_DECISION,
    APPROVED_DECISION,
    PENDING_DECISION,
    REJECTED_DECISION,
    AlertDecisionConflict,
    available_alert_decisions,
    decision_history_view,
    request_alert_decision,
)
from app.services.alert_queue_service import (
    SLA_COMPLETED,
    build_supervision_dashboard,
    calculate_alert_sla,
)
from app.services.approval_service import APPROVED, REJECTED, review_approval_request
from app.services.authorization_service import (
    ROLE_ANALYSTE_CONFORMITE,
    ROLE_SUPERVISEUR_CONFORMITE,
    role_label,
)


def _test_app(db) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="lot-4c-local-test")

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
    app.include_router(alerts.router)
    app.include_router(web.router)
    return app


class Lot4CAlertDecisionTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine, expire_on_commit=False)()
        self.analyst = self.user("analyste-4c", ROLE_ANALYSTE_CONFORMITE)
        self.supervisor = self.user("superviseur-4c", ROLE_SUPERVISEUR_CONFORMITE)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def user(self, username, role):
        user = User(
            username=username,
            full_name=role_label(role),
            email=f"{username}@example.test",
            password_hash="local-test",
            role=role,
        )
        self.db.add(user)
        self.db.flush()
        return user

    def alert(self, reference, *, status="GENEREE", age_hours=2):
        alert = Alert(
            client_reference=reference,
            client_nom="CLIENT",
            source_liste="OFAC_SDN",
            matching_score=96,
            matching_type="EXACT_NAME",
            niveau_alerte="ALERTE_EXACTE",
            statut=status,
            created_at=datetime.utcnow() - timedelta(hours=age_hours),
        )
        self.db.add(alert)
        self.db.flush()
        return alert

    @staticmethod
    def actor(user):
        return {"id": str(user.id), "username": user.username, "role": user.role}

    def review(self, approval, *, approved, comment="Revue superviseur"):
        review_approval_request(
            self.db,
            approval=approval,
            reviewer=self.actor(self.supervisor),
            approved=approved,
            comment=comment,
            ip_address="127.0.0.1",
        )
        self.db.flush()

    def test_01_generated_alert_can_enter_in_progress_with_history(self):
        alert = self.alert("START")
        reason = "Analyse commencée avec pièces complémentaires"

        outcome, approval = request_alert_decision(
            self.db,
            alert=alert,
            new_status="EN_COURS",
            reason=reason,
            actor=self.actor(self.analyst),
            ip_address="127.0.0.1",
        )
        self.db.flush()

        self.assertEqual(outcome, APPLIED_DECISION)
        self.assertIsNone(approval)
        self.assertEqual(alert.statut, "EN_COURS")
        history = self.db.query(AlertDecisionHistory).one()
        self.assertEqual((history.old_status, history.requested_status), ("GENEREE", "EN_COURS"))
        self.assertEqual(history.initiated_by, self.analyst.username)
        self.assertEqual(history.reason, reason)
        timeline = decision_history_view(alert, [history])
        self.assertIsNone(timeline[0]["reviewed_by"])
        self.assertIsNotNone(timeline[0]["decision_at"])
        audit = self.db.query(AuditLog).filter_by(action="ALERT_STATUS_CHANGED").one()
        self.assertNotIn(reason, audit.description)

    def test_02_false_positive_requires_reason_and_waits_for_review(self):
        alert = self.alert("FALSE-POSITIVE", status="EN_COURS")
        with self.assertRaisesRegex(ValueError, "motif est obligatoire"):
            request_alert_decision(
                self.db,
                alert=alert,
                new_status="FAUX_POSITIF",
                reason="  ",
                actor=self.actor(self.analyst),
                ip_address=None,
            )

        reason = "Identité et date de naissance différentes"
        outcome, approval = request_alert_decision(
            self.db,
            alert=alert,
            new_status="FAUX_POSITIF",
            reason=reason,
            actor=self.actor(self.analyst),
            ip_address=None,
        )
        self.db.flush()

        self.assertEqual(outcome, PENDING_DECISION)
        self.assertIsNotNone(approval)
        self.assertEqual(alert.statut, "EN_COURS")
        self.assertEqual(json.loads(approval.new_values)["statut"], "FAUX_POSITIF")
        self.assertTrue(all(
            reason not in (audit.description or "")
            for audit in self.db.query(AuditLog).all()
        ))

    def test_03_confirmation_uses_four_eyes_and_forbids_self_review(self):
        alert = self.alert("CONFIRM", status="EN_COURS")
        _, approval = request_alert_decision(
            self.db,
            alert=alert,
            new_status="CONFIRMEE",
            reason="Correspondance confirmée par les justificatifs",
            actor=self.actor(self.analyst),
            ip_address=None,
        )
        with self.assertRaisesRegex(PermissionError, "ne peut pas la valider"):
            review_approval_request(
                self.db,
                approval=approval,
                reviewer=self.actor(self.analyst),
                approved=True,
                comment=None,
                ip_address=None,
            )

        self.review(approval, approved=True)
        history = self.db.query(AlertDecisionHistory).one()
        self.assertEqual(approval.status, APPROVED)
        self.assertEqual(alert.statut, "CONFIRMEE")
        self.assertEqual(history.decision_status, APPROVED_DECISION)
        self.assertEqual(history.initiated_by, self.analyst.username)
        self.assertEqual(history.reviewed_by, self.supervisor.username)
        self.assertIsNotNone(history.reviewed_at)
        self.assertIsNotNone(history.applied_at)

    def test_04_rejection_preserves_alert_and_allows_new_proposal(self):
        alert = self.alert("RETRY", status="EN_COURS")
        _, rejected_approval = request_alert_decision(
            self.db,
            alert=alert,
            new_status="FAUX_POSITIF",
            reason="Première analyse",
            actor=self.actor(self.analyst),
            ip_address=None,
        )
        self.review(rejected_approval, approved=False, comment="Preuves insuffisantes")

        self.assertEqual(alert.statut, "EN_COURS")
        rejected_history = self.db.query(AlertDecisionHistory).one()
        self.assertEqual(rejected_approval.status, REJECTED)
        self.assertEqual(rejected_history.decision_status, REJECTED_DECISION)
        self.assertEqual(rejected_history.reviewer_comment, "Preuves insuffisantes")
        self.assertTrue(all(
            "Preuves insuffisantes" not in (audit.description or "")
            for audit in self.db.query(AuditLog).all()
        ))

        outcome, next_approval = request_alert_decision(
            self.db,
            alert=alert,
            new_status="CONFIRMEE",
            reason="Nouvelle analyse documentée",
            actor=self.actor(self.analyst),
            ip_address=None,
        )
        self.db.flush()
        self.assertEqual(outcome, PENDING_DECISION)
        self.assertNotEqual(next_approval.id, rejected_approval.id)
        self.assertEqual(self.db.query(AlertDecisionHistory).count(), 2)
        self.assertEqual(rejected_history.decision_status, REJECTED_DECISION)

    def test_05_confirmed_alert_can_close_then_becomes_immutable(self):
        alert = self.alert("CLOSE", status="CONFIRMEE")
        _, approval = request_alert_decision(
            self.db,
            alert=alert,
            new_status="CLOTUREE",
            reason="Dossier finalisé",
            actor=self.actor(self.analyst),
            ip_address=None,
        )
        self.review(approval, approved=True)

        self.assertEqual(alert.statut, "CLOTUREE")
        self.assertEqual(available_alert_decisions(alert), ())
        with self.assertRaisesRegex(AlertDecisionConflict, "Transition.*interdite"):
            request_alert_decision(
                self.db,
                alert=alert,
                new_status="EN_COURS",
                reason="Tentative de réouverture",
                actor=self.actor(self.supervisor),
                ip_address=None,
            )

    def test_06_terminal_web_page_is_read_only_with_readable_timeline(self):
        alert = self.alert("READ-ONLY", status="CONFIRMEE")
        _, approval = request_alert_decision(
            self.db,
            alert=alert,
            new_status="CLOTUREE",
            reason="Clôture documentée",
            actor=self.actor(self.analyst),
            ip_address=None,
        )
        self.review(approval, approved=True)
        self.db.commit()

        client = TestClient(_test_app(self.db))
        client.get(f"/_test/login/{ROLE_ANALYSTE_CONFORMITE}")
        response = client.get(f"/web/alerts/{alert.id}/treat")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Validée et appliquée", response.text)
        self.assertIn("Décideur", response.text)
        self.assertIn("Validateur", response.text)
        self.assertIn("Délai", response.text)
        self.assertIn("verrouillée et ne peut plus être modifiée", response.text)
        self.assertNotIn('id="treatForm"', response.text)
        self.assertNotIn(f'/web/alerts/{alert.id}/assign', response.text)
        self.assertNotIn(f'/web/alerts/{alert.id}/reassign', response.text)
        self.assertNotIn(f'/web/alerts/{alert.id}/escalate', response.text)

    def test_07_api_and_web_filters_support_closed_alerts(self):
        closed = self.alert("FILTER-CLOSED", status="CLOTUREE")
        self.alert("FILTER-ACTIVE", status="EN_COURS")
        self.db.commit()
        client = TestClient(_test_app(self.db))
        client.get(f"/_test/login/{ROLE_ANALYSTE_CONFORMITE}")

        api_response = client.get("/api/alerts/?statut=CLOTUREE")
        self.assertEqual(api_response.status_code, 200)
        self.assertEqual([item["id"] for item in api_response.json()], [str(closed.id)])
        web_response = client.get("/web/alerts?statut=CLOTUREE")
        self.assertEqual(web_response.status_code, 200)
        self.assertIn("FILTER-CLOSED", web_response.text)
        self.assertNotIn("FILTER-ACTIVE", web_response.text)

    def test_08_supervision_and_sla_behaviour_are_unchanged(self):
        active = self.alert("SLA-ACTIVE", status="EN_COURS", age_hours=1)
        closed = self.alert("SLA-CLOSED", status="CLOTUREE", age_hours=1)

        self.assertNotEqual(calculate_alert_sla(active)["sla_status"], SLA_COMPLETED)
        self.assertEqual(calculate_alert_sla(closed)["sla_status"], SLA_COMPLETED)
        dashboard = build_supervision_dashboard(self.db)
        self.assertIn(active, dashboard["alerts"])
        self.assertNotIn(closed, dashboard["alerts"])

    def test_09_web_review_requires_supervisor_permission(self):
        alert = self.alert("REVIEW-RBAC", status="EN_COURS")
        _, approval = request_alert_decision(
            self.db,
            alert=alert,
            new_status="CONFIRMEE",
            reason="Décision proposée",
            actor=self.actor(self.analyst),
            ip_address=None,
        )
        self.db.commit()
        client = TestClient(_test_app(self.db))

        client.get(f"/_test/login/{ROLE_ANALYSTE_CONFORMITE}")
        denied = client.post(
            f"/web/approvals/{approval.id}/review",
            data={"decision": "APPROVE", "comment": "Auto-validation"},
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(alert.statut, "EN_COURS")

        client.get(f"/_test/login/{ROLE_SUPERVISEUR_CONFORMITE}")
        allowed = client.post(
            f"/web/approvals/{approval.id}/review",
            data={"decision": "APPROVE", "comment": "Validation indépendante"},
            follow_redirects=False,
        )
        self.assertEqual(allowed.status_code, 303)
        self.assertEqual(alert.statut, "CONFIRMEE")

    def test_10_list_quick_actions_only_expose_allowed_transitions(self):
        alert = self.alert("CONFIRMED-UI", status="CONFIRMEE")
        self.db.commit()
        client = TestClient(_test_app(self.db))
        client.get(f"/_test/login/{ROLE_SUPERVISEUR_CONFORMITE}")

        for url in ("/web/alerts?statut=CONFIRMEE", "/web/critical-alerts?statut=CONFIRMEE"):
            response = client.get(url)
            self.assertEqual(response.status_code, 200)
            form = re.search(
                rf'<form[^>]+action="/web/alerts/{alert.id}/treat".*?</form>',
                response.text,
                re.DOTALL,
            )
            self.assertIsNotNone(form)
            self.assertIn('option value="CLOTUREE"', form.group(0))
            for forbidden in ("EN_COURS", "FAUX_POSITIF", "CONFIRMEE", "ESCALADEE"):
                self.assertNotIn(f'option value="{forbidden}"', form.group(0))


if __name__ == "__main__":
    unittest.main()
