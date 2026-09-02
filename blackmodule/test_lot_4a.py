"""LOT 4A regression tests for alert queue assignment and SLA."""

import unittest
from datetime import datetime, timedelta

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from app.database import Base, get_db
from app.models import Alert, AlertAssignmentHistory, AlertDecisionHistory, AuditLog, User
from app.routers import alerts, web
from app.services.alert_decision_service import request_alert_decision
from app.services.alert_queue_service import (
    AlertAssignmentConflict, SLA_BREACHED, SLA_NEAR, SLA_OK,
    annotate_alerts, apply_queue_filters, assign_alert, assignment_history,
    calculate_alert_sla, escalate_to_supervisor, reassign_alert,
)
from app.services.authorization_service import (
    ROLE_ADMIN_TECHNIQUE, ROLE_ANALYSTE_CONFORMITE,
    ROLE_SUPERVISEUR_CONFORMITE, role_label,
)


def _test_app(db) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="lot-4a-local-test")

    @app.get("/_test/login/{role}")
    def login(request: Request, role: str):
        user = db.query(User).filter(User.role == role).first()
        request.session["user"] = {
            "id": str(user.id), "username": user.username,
            "full_name": user.full_name, "role": role,
        }
        return {"status": "ok"}

    app.dependency_overrides[get_db] = lambda: db
    app.include_router(alerts.router)
    app.include_router(web.router)
    return app


class Lot4AAlertQueueTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False}, poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.db = self.Session()
        self.analyst = self.user("analyste", ROLE_ANALYSTE_CONFORMITE)
        self.other_analyst = self.user("analyste2", ROLE_ANALYSTE_CONFORMITE)
        self.supervisor = self.user("superviseur", ROLE_SUPERVISEUR_CONFORMITE)
        self.admin = self.user("admin-tech", ROLE_ADMIN_TECHNIQUE)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def user(self, username, role):
        user = User(
            username=username, full_name=role_label(role),
            email=f"{username}@example.test", password_hash="local-test", role=role,
        )
        self.db.add(user)
        self.db.flush()
        return user

    def alert(
        self, *, status="GENEREE", level="ALERTE_EXACTE", source="OFAC_SDN",
        age_hours=1, reference="CLIENT-4A",
    ):
        alert = Alert(
            client_reference=reference, client_nom="TEST", source_liste=source,
            matching_score=95, matching_type="EXACT_NAME", niveau_alerte=level,
            statut=status, created_at=datetime.utcnow() - timedelta(hours=age_hours),
        )
        self.db.add(alert)
        self.db.flush()
        return alert

    @staticmethod
    def actor(user):
        return {"id": str(user.id), "username": user.username, "role": user.role}

    def test_01_analyst_can_claim_unassigned_alert_with_history_and_audit(self):
        alert = self.alert()
        assign_alert(
            self.db, alert_id=alert.id, assignee_user_id=self.analyst.id,
            actor=self.actor(self.analyst), reason="Prise en charge", ip_address=None,
        )
        self.db.flush()

        self.assertEqual(alert.assigned_to_user_id, self.analyst.id)
        self.assertEqual(alert.assigned_to, "analyste")
        self.assertIsNotNone(alert.assigned_at)
        history = self.db.query(AlertAssignmentHistory).one()
        self.assertEqual((history.action, history.to_username), ("ASSIGNATION", "analyste"))
        self.assertEqual(self.db.query(AuditLog).one().action, "ALERT_ASSIGNED")

    def test_02_stale_concurrent_claim_cannot_overwrite_first_analyst(self):
        alert = self.alert()
        self.db.commit()
        second_session = self.Session()
        second_session.query(Alert).filter(Alert.id == alert.id).first()
        try:
            assign_alert(
                self.db, alert_id=alert.id, assignee_user_id=self.analyst.id,
                actor=self.actor(self.analyst), ip_address=None,
            )
            self.db.commit()
            with self.assertRaises(AlertAssignmentConflict):
                assign_alert(
                    second_session, alert_id=alert.id,
                    assignee_user_id=self.other_analyst.id,
                    actor=self.actor(self.other_analyst), ip_address=None,
                )
            second_session.rollback()
        finally:
            second_session.close()

        self.db.expire_all()
        current = self.db.query(Alert).filter(Alert.id == alert.id).one()
        self.assertEqual(current.assigned_to, "analyste")
        self.assertEqual(self.db.query(AlertAssignmentHistory).count(), 1)

    def test_03_supervisor_reassignment_is_historized(self):
        alert = self.alert()
        reason = "Répartition confidentielle entre analystes"
        assign_alert(
            self.db, alert_id=alert.id, assignee_user_id=self.analyst.id,
            actor=self.actor(self.analyst), ip_address=None,
        )
        reassign_alert(
            self.db, alert_id=alert.id, assignee_user_id=self.other_analyst.id,
            actor=self.actor(self.supervisor), reason=reason, ip_address=None,
        )
        self.db.flush()

        self.assertEqual(alert.assigned_to, "analyste2")
        history = assignment_history(self.db, alert.id)
        self.assertEqual({item.action for item in history}, {"ASSIGNATION", "REASSIGNATION"})
        reassignment = next(item for item in history if item.action == "REASSIGNATION")
        self.assertEqual((reassignment.from_username, reassignment.to_username), ("analyste", "analyste2"))
        self.assertEqual(reassignment.reason, reason)
        audit = self.db.query(AuditLog).filter(AuditLog.action == "ALERT_REASSIGNED").one()
        self.assertNotIn(reason, audit.description)

    def test_04_sla_is_fresh_near_or_breached_from_central_threshold(self):
        fresh = self.alert(age_hours=1, reference="FRESH")
        near = self.alert(age_hours=3.5, reference="NEAR")
        breached = self.alert(age_hours=5, reference="BREACHED")

        self.assertEqual(calculate_alert_sla(fresh)["sla_status"], SLA_OK)
        self.assertEqual(calculate_alert_sla(near)["sla_status"], SLA_NEAR)
        self.assertEqual(calculate_alert_sla(breached)["sla_status"], SLA_BREACHED)
        self.assertEqual(calculate_alert_sla(fresh)["sla_hours"], 4)

    def test_05_queue_filters_status_source_criticality_and_analyst(self):
        owned = self.alert(reference="OWNED")
        assign_alert(
            self.db, alert_id=owned.id, assignee_user_id=self.analyst.id,
            actor=self.actor(self.analyst), ip_address=None,
        )
        self.alert(status="EN_COURS", level="ALERTE_PROBABLE", source="ONU", reference="OTHER")
        self.db.flush()

        query = apply_queue_filters(
            self.db.query(Alert), statut="GENEREE", criticite="ALERTE_EXACTE",
            source="OFAC_SDN", analyste=str(self.analyst.id),
        )
        self.assertEqual([item.client_reference for item in query.all()], ["OWNED"])
        unassigned = apply_queue_filters(self.db.query(Alert), analyste="NON_ASSIGNEE").all()
        self.assertEqual([item.client_reference for item in unassigned], ["OTHER"])

    def test_05b_escalation_filter_distinguishes_escalated_and_non_escalated(self):
        escalated = self.alert(reference="ESCALATED")
        self.alert(reference="NOT-ESCALATED")
        escalate_to_supervisor(
            self.db, alert_id=escalated.id, actor=self.actor(self.analyst),
            reason="Revue superviseur requise", ip_address=None,
        )
        self.db.flush()

        escalated_rows = apply_queue_filters(self.db.query(Alert), escaladee=True).all()
        regular_rows = apply_queue_filters(self.db.query(Alert), escaladee=False).all()
        self.assertEqual([item.client_reference for item in escalated_rows], ["ESCALATED"])
        self.assertEqual([item.client_reference for item in regular_rows], ["NOT-ESCALATED"])

    def test_06_escalation_alerts_supervisor_without_changing_business_status(self):
        alert = self.alert()
        reason = "SLA proche et dossier complexe"
        escalate_to_supervisor(
            self.db, alert_id=alert.id, actor=self.actor(self.analyst),
            reason=reason, ip_address="127.0.0.44",
        )
        self.db.flush()

        self.assertEqual(alert.statut, "GENEREE")
        self.assertIsNotNone(alert.supervisor_escalated_at)
        self.assertEqual(alert.supervisor_escalated_by, "analyste")
        history = self.db.query(AlertAssignmentHistory).one()
        self.assertEqual(history.action, "ESCALADE_SUPERVISEUR")
        self.assertEqual(history.reason, reason)
        audit = self.db.query(AuditLog).filter(
            AuditLog.action == "ALERT_ESCALATED_TO_SUPERVISOR"
        ).one()
        self.assertEqual(audit.description, "Alerte escaladée vers le superviseur.")
        self.assertEqual(audit.user_identifier, "analyste")
        self.assertEqual(audit.entity_id, str(alert.id))
        self.assertEqual(audit.ip_address, "127.0.0.44")
        with self.assertRaises(AlertAssignmentConflict):
            escalate_to_supervisor(
                self.db, alert_id=alert.id, actor=self.actor(self.analyst),
                reason="Double clic", ip_address=None,
            )

    def test_07_api_rbac_refuses_technical_admin_and_analyst_reassignment(self):
        alert = self.alert()
        self.db.commit()
        client = TestClient(_test_app(self.db))

        client.get(f"/_test/login/{ROLE_ADMIN_TECHNIQUE}")
        denied = client.post(f"/api/alerts/{alert.id}/assign", json={})
        self.assertEqual(denied.status_code, 403)

        client.get(f"/_test/login/{ROLE_ANALYSTE_CONFORMITE}")
        claimed = client.post(f"/api/alerts/{alert.id}/assign", json={})
        self.assertEqual(claimed.status_code, 200)
        denied_reassign = client.post(
            f"/api/alerts/{alert.id}/reassign",
            json={"assignee_user_id": str(self.other_analyst.id)},
        )
        self.assertEqual(denied_reassign.status_code, 403)

        client.get(f"/_test/login/{ROLE_SUPERVISEUR_CONFORMITE}")
        reassigned = client.post(
            f"/api/alerts/{alert.id}/reassign",
            json={"assignee_user_id": str(self.other_analyst.id), "reason": "Supervision"},
        )
        self.assertEqual(reassigned.status_code, 200)
        self.assertEqual(reassigned.json()["assigned_to"], "analyste2")

    def test_08_api_queue_and_history_are_consultable(self):
        alert = self.alert(age_hours=5)
        assign_alert(
            self.db, alert_id=alert.id, assignee_user_id=self.analyst.id,
            actor=self.actor(self.analyst), ip_address=None,
        )
        self.db.commit()
        client = TestClient(_test_app(self.db))
        client.get(f"/_test/login/{ROLE_ANALYSTE_CONFORMITE}")

        queue = client.get("/api/alerts/?analyste=MOI&sla_status=HORS_SLA")
        self.assertEqual(queue.status_code, 200)
        self.assertEqual(len(queue.json()), 1)
        self.assertEqual(queue.json()[0]["sla_status"], "HORS_SLA")
        history = client.get(f"/api/alerts/{alert.id}/assignments")
        self.assertEqual(history.status_code, 200)
        self.assertEqual(history.json()[0]["action"], "ASSIGNATION")

    def test_09_web_queue_exposes_filters_sla_and_assignment_controls(self):
        self.alert(age_hours=5)
        self.db.commit()
        client = TestClient(_test_app(self.db))
        client.get(f"/_test/login/{ROLE_ANALYSTE_CONFORMITE}")
        response = client.get("/web/alerts?sla_status=HORS_SLA")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Hors SLA", response.text)
        self.assertIn("Prendre", response.text)
        self.assertIn("Mes alertes", response.text)
        self.assertNotIn("Réassigner", response.text)

    def test_09b_reassignment_select_shows_name_identifier_and_role(self):
        alert = self.alert()
        assign_alert(
            self.db, alert_id=alert.id, assignee_user_id=self.analyst.id,
            actor=self.actor(self.analyst), ip_address=None,
        )
        self.db.commit()
        client = TestClient(_test_app(self.db))
        client.get(f"/_test/login/{ROLE_SUPERVISEUR_CONFORMITE}")
        response = client.get("/web/alerts")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Analyste conformité (analyste) — Analyste conformité", response.text)
        self.assertIn("Superviseur conformité (superviseur) — Superviseur conformité", response.text)

    def test_09c_web_filter_can_select_non_escalated_alerts(self):
        escalated = self.alert(reference="ESCALATED-WEB")
        self.alert(reference="REGULAR-WEB")
        escalate_to_supervisor(
            self.db, alert_id=escalated.id, actor=self.actor(self.analyst),
            reason="Revue superviseur requise", ip_address=None,
        )
        self.db.commit()
        client = TestClient(_test_app(self.db))
        client.get(f"/_test/login/{ROLE_ANALYSTE_CONFORMITE}")
        response = client.get("/web/alerts?escaladee=0")

        self.assertEqual(response.status_code, 200)
        self.assertIn("REGULAR-WEB", response.text)
        self.assertNotIn("ESCALATED-WEB", response.text)
        self.assertIn('<option value="0" selected>Non signalées</option>', response.text)

    def test_10_terminal_alert_cannot_be_assigned(self):
        alert = self.alert(status="CLOTUREE")
        with self.assertRaises(AlertAssignmentConflict):
            assign_alert(
                self.db, alert_id=alert.id, assignee_user_id=self.analyst.id,
                actor=self.actor(self.analyst), ip_address=None,
            )

    def test_11_assignment_schema_creation_is_idempotent(self):
        Base.metadata.create_all(self.engine)
        Base.metadata.create_all(self.engine)
        tables = set(Base.metadata.tables)
        self.assertIn("alert_assignment_history", tables)
        self.assertIn("assigned_to_user_id", Base.metadata.tables["alerts"].columns)

    def test_12_existing_false_positive_decision_rules_are_unchanged(self):
        alert = self.alert()
        with self.assertRaisesRegex(ValueError, "motif est obligatoire"):
            request_alert_decision(
                self.db, alert=alert, new_status="FAUX_POSITIF", reason=" ",
                actor=self.actor(self.analyst), ip_address=None,
            )
        self.assertEqual(alert.statut, "GENEREE")

    def test_13_treatment_reason_stays_in_business_history_not_technical_audit(self):
        alert = self.alert()
        reason = "Information de traitement confidentielle"
        outcome, _ = request_alert_decision(
            self.db, alert=alert, new_status="EN_COURS", reason=reason,
            actor=self.actor(self.analyst), ip_address="127.0.0.45",
        )
        self.db.flush()

        self.assertEqual(outcome, "APPLIQUEE")
        self.assertEqual(alert.treatment_comment, reason)
        self.assertEqual(self.db.query(AlertDecisionHistory).one().reason, reason)
        audit = self.db.query(AuditLog).filter(AuditLog.action == "ALERT_STATUS_CHANGED").one()
        self.assertNotIn(reason, audit.description)
        self.assertEqual(audit.entity_id, str(alert.id))
        self.assertEqual(audit.ip_address, "127.0.0.45")


if __name__ == "__main__":
    unittest.main()
