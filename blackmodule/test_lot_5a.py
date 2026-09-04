"""LOT 5A regression tests for compliance reporting."""

import unittest
from datetime import datetime, timedelta

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from app.database import Base, get_db
from app.models import Alert, AlertDecisionHistory, AuditLog, User
from app.routers import web
from app.services.alert_decision_service import APPROVED_DECISION
from app.services.alert_queue_service import SLA_BREACHED, SLA_NEAR, SLA_OK, calculate_alert_sla
from app.services.authorization_service import (
    ROLE_ANALYSTE_CONFORMITE,
    ROLE_AUDITEUR,
    ROLE_SUPERVISEUR_CONFORMITE,
    role_label,
)
from app.services.reporting_service import build_compliance_report, resolve_reporting_filters


def _test_app(db) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="lot-5a-local-test")

    @app.get("/_test/login/{role}")
    def login(request: Request, role: str):
        user = db.query(User).filter(User.role == role).first()
        request.session["user"] = {
            "id": str(user.id), "username": user.username,
            "full_name": user.full_name, "role": user.role,
        }
        return {"status": "ok"}

    app.dependency_overrides[get_db] = lambda: db
    app.include_router(web.router)
    return app


class Lot5AComplianceReportingTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False}, poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine, expire_on_commit=False)()
        # Keep fixture timestamps relative to the same current reference used
        # by the Web reporting route.  A fixed calendar date made the seven-day
        # export assertion fail as time passed.
        self.now = datetime.utcnow().replace(microsecond=0)
        self.analyst1 = self.user("analyste-report-1", ROLE_ANALYSTE_CONFORMITE, "Alice Analyste")
        self.analyst2 = self.user("analyste-report-2", ROLE_ANALYSTE_CONFORMITE, "Bruno Analyste")
        self.supervisor = self.user("superviseur-report", ROLE_SUPERVISEUR_CONFORMITE, "Sophie Superviseur")
        self.auditor = self.user("auditeur-report", ROLE_AUDITEUR, "Arthur Auditeur")
        self.alerts = self.seed_alerts()
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.clear_compiled_cache()
        self.engine.dispose()

    def user(self, username, role, full_name):
        user = User(
            username=username, full_name=full_name,
            email=f"{username}@example.test", password_hash="local-test",
            role=role, statut="ACTIF",
        )
        self.db.add(user)
        self.db.flush()
        return user

    def alert(
        self, reference, *, status, level, age_hours, analyst=None,
        source="OFAC_SDN", matching_type="EXACT_NAME", treated_hours_ago=None,
        escalated=False,
    ):
        created_at = self.now - timedelta(hours=age_hours)
        item = Alert(
            client_reference=reference,
            client_nom="DONNEE CLIENT TRES SENSIBLE",
            source_liste=source,
            matching_score=95,
            matching_type=matching_type,
            niveau_alerte=level,
            statut=status,
            created_at=created_at,
            assigned_to_user_id=analyst.id if analyst else None,
            assigned_to=analyst.username if analyst else None,
            assigned_at=created_at if analyst else None,
            treated_at=(self.now - timedelta(hours=treated_hours_ago)) if treated_hours_ago is not None else None,
            treated_by=analyst.username if analyst and treated_hours_ago is not None else None,
            treatment_comment="COMMENTAIRE METIER CONFIDENTIEL" if treated_hours_ago is not None else None,
            supervisor_escalated_at=(self.now - timedelta(hours=1)) if escalated else None,
            supervisor_escalated_by=self.supervisor.username if escalated else None,
        )
        self.db.add(item)
        self.db.flush()
        return item

    def decision(self, alert, status, applied_hours_ago):
        row = AlertDecisionHistory(
            alert_id=alert.id,
            old_status="EN_COURS",
            requested_status=status,
            decision_status=APPROVED_DECISION,
            initiated_by=alert.assigned_to or self.analyst1.username,
            initiated_at=self.now - timedelta(hours=applied_hours_ago + 1),
            reason="MOTIF CONFIDENTIEL",
            reviewed_by=self.supervisor.username,
            reviewed_at=self.now - timedelta(hours=applied_hours_ago),
            applied_at=self.now - timedelta(hours=applied_hours_ago),
        )
        self.db.add(row)

    def seed_alerts(self):
        generated = self.alert(
            "GENERATED", status="GENEREE", level="ALERTE_EXACTE", age_hours=1,
        )
        in_progress = self.alert(
            "IN-PROGRESS", status="EN_COURS", level="ALERTE_PROBABLE",
            age_hours=25, analyst=self.analyst1,
        )
        confirmed = self.alert(
            "CONFIRMED", status="CONFIRMEE", level="ALERTE_EXACTE",
            age_hours=10, analyst=self.analyst1, treated_hours_ago=2,
        )
        false_positive = self.alert(
            "FALSE-POSITIVE", status="FAUX_POSITIF", level="ALERTE_POSSIBLE",
            age_hours=72, analyst=self.analyst2, source="ONU", treated_hours_ago=24,
            matching_type="FUZZY_NAME",
        )
        closed = self.alert(
            "CLOSED", status="CLOTUREE", level="ALERTE_PROBABLE",
            age_hours=120, analyst=self.analyst2, source="ONU", treated_hours_ago=1,
            matching_type="NAME_ABBREVIATION",
        )
        escalated = self.alert(
            "ESCALATED", status="ESCALADEE", level="ALERTE_PROBABLE",
            age_hours=20, analyst=self.analyst1, escalated=True,
        )
        old = self.alert(
            "OLD", status="GENEREE", level="ALERTE_POSSIBLE",
            age_hours=20 * 24, source="UE", matching_type="FUZZY_NAME",
        )
        self.decision(confirmed, "CONFIRMEE", 2)
        self.decision(false_positive, "FAUX_POSITIF", 24)
        self.decision(closed, "CONFIRMEE", 96)
        self.decision(closed, "CLOTUREE", 1)
        return [generated, in_progress, confirmed, false_positive, closed, escalated, old]

    def report(self, **kwargs):
        filters = resolve_reporting_filters(now=self.now, **kwargs)
        return build_compliance_report(self.db, filters, now=self.now)

    def test_01_kpis_and_performance_are_exact(self):
        report = self.report(period="7")
        self.assertEqual(report["kpis"], {
            "total": 6, "generated": 1, "in_progress": 1, "confirmed": 1,
            "false_positive": 1, "closed": 1, "critical": 2,
            "unassigned": 1, "escalated": 1, "within_sla": 1,
            "near_sla": 1, "out_sla": 2, "inactive": 1,
        })
        self.assertEqual(report["performance"]["average_hours"], 58.33)
        self.assertEqual(report["performance"]["median_hours"], 48.0)
        self.assertEqual(report["performance"]["closed_volume"], 1)
        self.assertEqual(report["performance"]["false_positive_rate"], 33.3)
        self.assertEqual(report["performance"]["confirmation_rate"], 66.7)

    def test_02_periods_and_dimension_filters_are_coherent(self):
        self.assertEqual(self.report(period="7")["kpis"]["total"], 6)
        self.assertEqual(self.report(period="30")["kpis"]["total"], 7)
        custom = self.report(
            period="custom",
            date_from=(self.now.date() - timedelta(days=1)).isoformat(),
            date_to=self.now.date().isoformat(),
        )
        self.assertEqual(custom["kpis"]["total"], 4)
        onu = self.report(period="7", source="ONU")
        self.assertEqual(onu["kpis"]["total"], 2)
        self.assertEqual(onu["kpis"]["closed"], 1)
        confirmed = self.report(period="7", status="CONFIRMEE")
        self.assertEqual((confirmed["kpis"]["total"], confirmed["kpis"]["confirmed"]), (1, 1))
        alice = self.report(period="7", analyst=str(self.analyst1.id))
        self.assertEqual(alice["kpis"]["total"], 3)
        self.assertEqual(
            {item["username"] for item in alice["options"]["analysts"]},
            {"analyste-report-1", "analyste-report-2"},
        )

    def test_03_distributions_and_trends_use_aggregated_data(self):
        report = self.report(period="7")
        source_counts = {item["label"]: item["count"] for item in report["distributions"]["sources"]}
        status_counts = {item["label"]: item["count"] for item in report["distributions"]["statuses"]}
        self.assertEqual(source_counts, {"OFAC_SDN": 4, "ONU": 2})
        self.assertEqual(status_counts["GENEREE"], 1)
        self.assertEqual(len(report["trends"]), 7)
        totals = {
            key: sum(item[key] for item in report["trends"])
            for key in ("created", "closed", "false_positive", "confirmed")
        }
        self.assertEqual(totals, {"created": 6, "closed": 1, "false_positive": 1, "confirmed": 2})

    def test_04_analyst_workload_is_correct_and_contains_no_supervisor(self):
        report = self.report(period="7")
        analysts = {item["username"]: item for item in report["analysts"]}
        self.assertEqual(analysts["analyste-report-1"]["active"], 3)
        self.assertEqual(analysts["analyste-report-1"]["out_sla"], 2)
        self.assertEqual(analysts["analyste-report-2"]["active"], 0)
        self.assertEqual(analysts["analyste-report-2"]["closed"], 1)
        self.assertNotIn("superviseur-report", analysts)

        self.alert(
            "OLD-BUT-RECENTLY-CLOSED", status="CLOTUREE", level="ALERTE_PROBABLE",
            age_hours=10 * 24, analyst=self.analyst1, treated_hours_ago=1,
        )
        self.db.commit()
        refreshed = self.report(period="7")
        refreshed_analysts = {item["username"]: item for item in refreshed["analysts"]}
        self.assertEqual(refreshed["kpis"]["total"], 6)
        self.assertEqual(refreshed_analysts["analyste-report-1"]["closed"], 1)

    def test_05_sql_sla_counts_match_existing_sla_engine(self):
        report = self.report(period="7")
        expected = {SLA_OK: 0, SLA_NEAR: 0, SLA_BREACHED: 0}
        for alert in self.alerts[:6]:
            status = calculate_alert_sla(alert, now=self.now)["sla_status"]
            if status in expected:
                expected[status] += 1
        self.assertEqual(report["kpis"]["within_sla"], expected[SLA_OK])
        self.assertEqual(report["kpis"]["near_sla"], expected[SLA_NEAR])
        self.assertEqual(report["kpis"]["out_sla"], expected[SLA_BREACHED])

    def test_06_backend_rbac_allows_supervisor_and_auditor_only(self):
        with TestClient(_test_app(self.db)) as client:
            for role in (ROLE_SUPERVISEUR_CONFORMITE, ROLE_AUDITEUR):
                client.get(f"/_test/login/{role}")
                response = client.get("/web/compliance-reporting?period=7")
                self.assertEqual(response.status_code, 200)
                self.assertIn("Dashboard conformité", response.text)
                self.assertIn("Volume clôturé", response.text)
                self.assertNotIn("DONNEE CLIENT TRES SENSIBLE", response.text)
            client.get(f"/_test/login/{ROLE_ANALYSTE_CONFORMITE}")
            self.assertEqual(client.get("/web/compliance-reporting?period=7").status_code, 403)
            self.assertEqual(client.get("/web/compliance-reporting/export.csv?period=7").status_code, 403)

    def test_07_export_respects_filters_and_exposes_only_aggregates(self):
        with TestClient(_test_app(self.db)) as client:
            client.get(f"/_test/login/{ROLE_SUPERVISEUR_CONFORMITE}")
            response = client.get("/web/compliance-reporting/export.csv?period=7&source=ONU")
            self.assertEqual(response.status_code, 200)
            self.assertIn("text/csv", response.headers["content-type"])
            self.assertIn("Total alertes;2", response.text)
            self.assertNotIn("DONNEE CLIENT TRES SENSIBLE", response.text)
            self.assertNotIn("COMMENTAIRE METIER CONFIDENTIEL", response.text)
            self.assertNotIn("MOTIF CONFIDENTIEL", response.text)
            self.assertIsNotNone(self.db.query(AuditLog).filter_by(action="EXPORT_COMPLIANCE_REPORT").first())

    def test_08_reporting_uses_constant_queries_and_never_mutates_workflow(self):
        statuses_before = {str(alert.id): alert.statut for alert in self.alerts}
        history_before = self.db.query(AlertDecisionHistory).count()
        query_count = 0

        def count_query(*_args, **_kwargs):
            nonlocal query_count
            query_count += 1

        event.listen(self.engine, "before_cursor_execute", count_query)
        try:
            self.report(period="7")
        finally:
            event.remove(self.engine, "before_cursor_execute", count_query)

        self.assertLessEqual(query_count, 13)
        self.assertEqual({str(alert.id): alert.statut for alert in self.alerts}, statuses_before)
        self.assertEqual(self.db.query(AlertDecisionHistory).count(), history_before)


if __name__ == "__main__":
    unittest.main()
