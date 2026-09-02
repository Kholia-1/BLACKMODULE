"""LOT 4B regression tests for operational alert supervision."""

import unittest
from datetime import datetime, timedelta

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from app.database import Base, get_db
from app.models import Alert, AlertAssignmentHistory, AlertDecisionHistory, ApprovalRequest, AuditLog, User
from app.routers import alerts, web
from app.services.alert_decision_service import request_alert_decision
from app.services.alert_queue_service import build_supervision_dashboard, eligible_assignees
from app.services.authorization_service import (
    ROLE_ADMIN_TECHNIQUE, ROLE_ANALYSTE_CONFORMITE,
    ROLE_SUPERVISEUR_CONFORMITE, role_label,
)


def _test_app(db) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="lot-4b-local-test")

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


class Lot4BAlertSupervisionTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False}, poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.db = self.Session()
        self.now = datetime(2026, 9, 2, 12, 0)
        self.analyst = self.user("analyste-4b", ROLE_ANALYSTE_CONFORMITE)
        self.other_analyst = self.user("analyste-4b-2", ROLE_ANALYSTE_CONFORMITE)
        self.supervisor = self.user("superviseur-4b", ROLE_SUPERVISEUR_CONFORMITE)
        self.admin = self.user("admin-4b", ROLE_ADMIN_TECHNIQUE)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def user(self, username, role):
        item = User(
            username=username, full_name=role_label(role),
            email=f"{username}@example.test", password_hash="local-test", role=role,
        )
        self.db.add(item)
        self.db.flush()
        return item

    def alert(
        self, reference, *, level="ALERTE_EXACTE", age_hours=1,
        status="GENEREE", source="OFAC_SDN", assignee=None,
    ):
        item = Alert(
            client_reference=reference, client_nom="CLIENT", source_liste=source,
            matching_score=95, matching_type="EXACT_NAME", niveau_alerte=level,
            statut=status, created_at=self.now - timedelta(hours=age_hours),
            assigned_to_user_id=assignee.id if assignee else None,
            assigned_to=assignee.username if assignee else None,
            assigned_at=self.now - timedelta(hours=1) if assignee else None,
        )
        self.db.add(item)
        self.db.flush()
        return item

    @staticmethod
    def actor(user):
        return {"id": str(user.id), "username": user.username, "role": user.role}

    def test_01_supervisor_view_is_available_and_rbac_protected(self):
        self.alert("SUPERVISION-VISIBLE")
        self.db.commit()
        client = TestClient(_test_app(self.db))

        client.get(f"/_test/login/{ROLE_SUPERVISEUR_CONFORMITE}")
        allowed = client.get("/web/alert-supervision")
        self.assertEqual(allowed.status_code, 200)
        self.assertIn("Supervision opérationnelle des alertes", allowed.text)
        self.assertIn("SUPERVISION-VISIBLE", allowed.text)

        for role in (ROLE_ANALYSTE_CONFORMITE, ROLE_ADMIN_TECHNIQUE):
            client.get(f"/_test/login/{role}")
            self.assertEqual(client.get("/web/alert-supervision").status_code, 403)

    def test_02_priority_follows_operational_business_order(self):
        self.alert("STANDARD-PROBABLE", level="ALERTE_PROBABLE", assignee=self.analyst)
        self.alert("STANDARD-CRITICAL", level="ALERTE_EXACTE", assignee=self.analyst)
        self.alert("NEAR-SLA", level="ALERTE_PROBABLE", age_hours=20, assignee=self.analyst)
        escalated = self.alert(
            "ESCALATED", level="ALERTE_PROBABLE", age_hours=2,
            assignee=self.analyst,
        )
        escalated.supervisor_escalated_at = self.now - timedelta(minutes=30)
        self.alert("OUT-SLA", level="ALERTE_PROBABLE", age_hours=30, assignee=self.analyst)
        self.alert("CRITICAL-UNASSIGNED", level="ALERTE_EXACTE", age_hours=1)

        dashboard = build_supervision_dashboard(self.db, now=self.now)
        self.assertEqual(
            [item.client_reference for item in dashboard["alerts"]],
            [
                "CRITICAL-UNASSIGNED", "OUT-SLA", "ESCALATED", "NEAR-SLA",
                "STANDARD-CRITICAL", "STANDARD-PROBABLE",
            ],
        )
        self.assertEqual(
            [item.operational_priority for item in dashboard["alerts"]],
            [
                "Critique non assignée", "Hors SLA", "Escaladée", "Proche SLA",
                "Critique", "Standard",
            ],
        )

    def test_03_unassigned_critical_alerts_are_counted_and_filterable(self):
        self.alert("CRITICAL-FREE")
        self.alert("PROBABLE-FREE", level="ALERTE_PROBABLE")

        dashboard = build_supervision_dashboard(
            self.db, focus="CRITICAL_UNASSIGNED", now=self.now,
        )
        self.assertEqual(dashboard["metrics"]["critical_unassigned"], 1)
        self.assertEqual([item.client_reference for item in dashboard["alerts"]], ["CRITICAL-FREE"])

    def test_04_analyst_workload_preserves_individual_counts(self):
        self.alert("A1", assignee=self.analyst)
        self.alert("A2", level="ALERTE_PROBABLE", age_hours=30, assignee=self.analyst)
        self.alert("B1", assignee=self.other_analyst)

        dashboard = build_supervision_dashboard(self.db, now=self.now)
        workloads = {item["user"].username: item for item in dashboard["workloads"]}
        self.assertEqual(workloads["analyste-4b"]["total"], 2)
        self.assertEqual(workloads["analyste-4b"]["out_sla"], 1)
        self.assertEqual(workloads["analyste-4b-2"]["total"], 1)
        self.assertNotIn("superviseur-4b", workloads)

    def test_05_alert_without_recent_activity_is_flagged(self):
        inactive = self.alert("INACTIVE", age_hours=30)
        refreshed = self.alert("REFRESHED", age_hours=30)
        self.db.add(AlertAssignmentHistory(
            alert_id=refreshed.id, action="ASSIGNATION", to_user_id=self.analyst.id,
            to_username=self.analyst.username, changed_by_user_id=self.supervisor.id,
            changed_by_username=self.supervisor.username,
            created_at=self.now - timedelta(hours=1),
        ))
        self.db.flush()

        dashboard = build_supervision_dashboard(self.db, focus="INACTIVE", now=self.now)
        self.assertEqual([item.client_reference for item in dashboard["alerts"]], ["INACTIVE"])
        self.assertTrue(inactive.is_inactive)
        self.assertFalse(refreshed.is_inactive)

    def test_06_quick_filters_support_source_status_escalation_and_analyst(self):
        escalated = self.alert(
            "ESCALATED-ONU", level="ALERTE_PROBABLE", source="ONU",
            status="EN_COURS", assignee=self.analyst,
        )
        escalated.supervisor_escalated_at = self.now - timedelta(minutes=20)
        self.alert("OTHER-OFAC", source="OFAC_SDN", assignee=self.other_analyst)

        dashboard = build_supervision_dashboard(
            self.db, focus="ESCALATED", analyst=str(self.analyst.id),
            statut="EN_COURS", source="ONU", now=self.now,
        )
        self.assertEqual([item.client_reference for item in dashboard["alerts"]], ["ESCALATED-ONU"])

    def test_07_view_is_audited_and_history_is_readable_without_sensitive_reason(self):
        alert = self.alert("HISTORY")
        secret_reason = "Motif opérationnel confidentiel"
        self.db.add(AlertAssignmentHistory(
            alert_id=alert.id, action="ASSIGNATION", to_user_id=self.analyst.id,
            to_username=self.analyst.username, changed_by_user_id=self.supervisor.id,
            changed_by_username=self.supervisor.username, reason=secret_reason,
            created_at=self.now,
        ))
        self.db.commit()
        client = TestClient(_test_app(self.db))
        client.get(f"/_test/login/{ROLE_SUPERVISEUR_CONFORMITE}")
        response = client.get("/web/alert-supervision")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Assignée à analyste-4b", response.text)
        self.assertIn(">HISTORY</a>", response.text)
        audit = self.db.query(AuditLog).filter(AuditLog.action == "VIEW_ALERT_SUPERVISION").one()
        self.assertEqual(audit.user_identifier, "superviseur-4b")
        self.assertEqual(audit.description, "Consultation de la supervision opérationnelle des alertes.")
        self.assertNotIn(secret_reason, audit.description)
        history = self.db.query(AlertAssignmentHistory).filter_by(alert_id=alert.id).one()
        self.assertEqual(history.reason, secret_reason)

    def test_08_supervision_does_not_change_status_or_four_eyes_workflow(self):
        alert = self.alert("FOUR-EYES")
        outcome, approval = request_alert_decision(
            self.db, alert=alert, new_status="FAUX_POSITIF", reason="Homonyme vérifié",
            actor=self.actor(self.analyst), ip_address=None,
        )
        self.db.flush()
        build_supervision_dashboard(self.db, now=self.now)

        self.assertEqual(outcome, "EN_ATTENTE_VALIDATION")
        self.assertIsNotNone(approval)
        self.assertEqual(alert.statut, "GENEREE")
        self.assertEqual(self.db.query(ApprovalRequest).count(), 1)
        self.assertEqual(self.db.query(AlertDecisionHistory).one().decision_status, "EN_ATTENTE_VALIDATION")

    def test_09_only_analysts_are_assignable_in_ui_and_backend(self):
        alert = self.alert("ANALYST-ONLY")
        self.db.commit()
        client = TestClient(_test_app(self.db))
        client.get(f"/_test/login/{ROLE_SUPERVISEUR_CONFORMITE}")

        assignees = eligible_assignees(self.db)
        self.assertEqual(
            {item.username for item in assignees},
            {"analyste-4b", "analyste-4b-2"},
        )
        page = client.get("/web/alert-supervision")
        self.assertEqual(page.status_code, 200)
        self.assertIn(
            "Analyste conformité (analyste-4b) — Analyste conformité", page.text,
        )
        self.assertNotIn(
            "Superviseur conformité (superviseur-4b) — Superviseur conformité", page.text,
        )

        denied = client.post(
            f"/api/alerts/{alert.id}/assign",
            json={"assignee_user_id": str(self.supervisor.id)},
        )
        self.assertEqual(denied.status_code, 400)

        assigned = client.post(
            f"/api/alerts/{alert.id}/assign",
            json={"assignee_user_id": str(self.analyst.id)},
        )
        self.assertEqual(assigned.status_code, 200)
        reassigned = client.post(
            f"/api/alerts/{alert.id}/reassign",
            json={"assignee_user_id": str(self.other_analyst.id), "reason": "Rééquilibrage"},
        )
        self.assertEqual(reassigned.status_code, 200)
        self.assertEqual(reassigned.json()["assigned_to"], "analyste-4b-2")


if __name__ == "__main__":
    unittest.main()
