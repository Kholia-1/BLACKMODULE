"""LOT 3B regression tests for alert analysis and conformity decisions."""

import json
import unittest
from datetime import date
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from app.database import Base, get_db
from app.models import (
    Alert, AlertDecisionHistory, ApprovalRequest, AuditLog, SanctionEntry,
)
from app.routers import alerts, web
from app.services.alert_analysis_service import build_alert_analysis
from app.services.alert_decision_service import (
    APPLIED_DECISION, APPROVED_DECISION, OBSOLETE_DECISION, PENDING_DECISION,
    REJECTED_DECISION, AlertDecisionConflict, request_alert_decision,
)
from app.services.approval_service import APPROVED, OBSOLETE, PENDING, REJECTED, review_approval_request
from app.services.authorization_service import (
    ROLE_ADMIN_TECHNIQUE, ROLE_ANALYSTE_CONFORMITE, ROLE_CONSULTATION,
    ROLE_SUPERVISEUR_CONFORMITE, role_label,
)


def _test_app(db) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="lot-3b-local-test")

    @app.get("/_test/login/{role}")
    def login(request: Request, role: str):
        request.session["user"] = {
            "id": f"test-{role.lower()}",
            "username": role.lower(),
            "full_name": role_label(role),
            "role": role,
        }
        return {"status": "ok"}

    app.dependency_overrides[get_db] = lambda: db
    app.include_router(alerts.router)
    app.include_router(web.router)
    return app


class Lot3BAlertDecisionTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine, expire_on_commit=False)()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def entry(self, source, *, name="PAUL MALONG AWAN", birthdate=date(1962, 1, 2), passport=None):
        entry = SanctionEntry(
            source_liste=source,
            type_entite="PERSONNE",
            nom="AWAN",
            prenom="PAUL MALONG",
            nom_complet=name,
            date_naissance=birthdate,
            num_passeport=passport,
            statut="ACTIF",
        )
        self.db.add(entry)
        self.db.flush()
        return entry

    def alert(self, entry, *, score=95.0, reference="CLIENT-3B", status="GENEREE"):
        alert = Alert(
            client_reference=reference,
            client_nom="AWAN",
            client_prenom="PAUL MALONG",
            client_date_naissance=date(1962, 1, 2),
            sanction_entry_id=entry.id,
            source_liste=entry.source_liste,
            matching_score=score,
            matching_type="NAME_AND_BIRTHDATE",
            niveau_alerte="ALERTE_PROBABLE",
            statut=status,
            action_recommandee="REVUE_CONFORMITE",
        )
        self.db.add(alert)
        self.db.flush()
        return alert

    @staticmethod
    def actor(username="analyste", identifier="analyst-id"):
        return {"id": identifier, "username": username}

    def test_01_same_person_in_two_sources_is_grouped_without_fusion(self):
        first = self.alert(self.entry("OFAC_SDN"), score=97.0)
        second = self.alert(self.entry("ONU"), score=92.5)
        self.db.commit()

        analysis = build_alert_analysis(self.db, first)

        self.assertEqual(analysis["classification"], "MULTI_SOURCE_PROBABLE")
        self.assertEqual({item["source"] for item in analysis["sources"]}, {"OFAC_SDN", "ONU"})
        self.assertEqual({item["score"] for item in analysis["sources"]}, {97.0, 92.5})
        self.assertEqual(self.db.query(Alert).count(), 2)
        self.assertEqual(self.db.query(SanctionEntry).count(), 2)

    def test_02_homonyms_with_different_birthdates_are_not_grouped(self):
        first = self.alert(self.entry("OFAC_SDN", birthdate=date(1962, 1, 2)))
        self.alert(self.entry("ONU", birthdate=date(1980, 5, 6)))
        self.db.commit()

        analysis = build_alert_analysis(self.db, first)

        self.assertEqual(analysis["classification"], "INDIVIDUAL")
        self.assertEqual([item["source"] for item in analysis["sources"]], ["OFAC_SDN"])

    def test_03_false_positive_with_reason_uses_four_eyes_and_complete_history(self):
        alert = self.alert(self.entry("OFAC_SDN"))
        outcome, approval = request_alert_decision(
            self.db, alert=alert, new_status="FAUX_POSITIF",
            reason="Date et document distincts", actor=self.actor(), ip_address=None,
        )
        self.db.flush()

        self.assertEqual(outcome, PENDING_DECISION)
        self.assertEqual(approval.status, PENDING)
        self.assertEqual(alert.statut, "GENEREE")
        history = self.db.query(AlertDecisionHistory).one()
        self.assertEqual((history.old_status, history.requested_status), ("GENEREE", "FAUX_POSITIF"))
        self.assertEqual(history.reason, "Date et document distincts")

        review_approval_request(
            self.db, approval=approval,
            reviewer=self.actor("superviseur", "supervisor-id"),
            approved=True, comment="Vérification effectuée", ip_address=None,
        )
        self.db.flush()

        self.assertEqual(approval.status, APPROVED)
        self.assertEqual(alert.statut, "FAUX_POSITIF")
        self.assertEqual(alert.treatment_comment, "Date et document distincts")
        self.assertEqual(history.decision_status, APPROVED_DECISION)
        self.assertEqual(history.reviewed_by, "superviseur")
        self.assertIsNotNone(history.reviewed_at)
        self.assertIsNotNone(history.applied_at)

    def test_04_false_positive_without_reason_is_refused(self):
        alert = self.alert(self.entry("OFAC_SDN"))
        with self.assertRaisesRegex(ValueError, "motif est obligatoire"):
            request_alert_decision(
                self.db, alert=alert, new_status="FAUX_POSITIF",
                reason="  ", actor=self.actor(), ip_address=None,
            )
        self.assertEqual(self.db.query(ApprovalRequest).count(), 0)
        self.assertEqual(self.db.query(AlertDecisionHistory).count(), 0)
        self.assertEqual(alert.statut, "GENEREE")

    def test_05_insufficient_backend_permission_returns_403(self):
        alert = self.alert(self.entry("OFAC_SDN"))
        self.db.commit()
        client = TestClient(_test_app(self.db))
        client.get(f"/_test/login/{ROLE_ADMIN_TECHNIQUE}")
        response = client.put(
            f"/api/alerts/{alert.id}/treat",
            json={"statut": "FAUX_POSITIF", "treated_by": "ignored", "treatment_comment": "Motif"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(alert.statut, "GENEREE")

    def test_06_duplicate_pending_and_repeated_direct_treatments_are_refused(self):
        alert = self.alert(self.entry("OFAC_SDN"))
        request_alert_decision(
            self.db, alert=alert, new_status="CONFIRMEE", reason="Correspondance confirmée",
            actor=self.actor(), ip_address=None,
        )
        self.db.flush()
        with self.assertRaisesRegex(AlertDecisionConflict, "déjà en attente"):
            request_alert_decision(
                self.db, alert=alert, new_status="CLOTUREE", reason="Autre décision",
                actor=self.actor(), ip_address=None,
            )

        other = self.alert(self.entry("ONU"), reference="CLIENT-AUTRE")
        outcome, _ = request_alert_decision(
            self.db, alert=other, new_status="EN_COURS", reason="Analyse ouverte",
            actor=self.actor(), ip_address=None,
        )
        self.assertEqual(outcome, APPLIED_DECISION)
        with self.assertRaisesRegex(AlertDecisionConflict, "déjà ce statut"):
            request_alert_decision(
                self.db, alert=other, new_status="EN_COURS", reason="Double clic",
                actor=self.actor(), ip_address=None,
            )

    def test_07_rejection_keeps_alert_and_records_complete_audit(self):
        alert = self.alert(self.entry("OFAC_SDN"))
        _, approval = request_alert_decision(
            self.db, alert=alert, new_status="CLOTUREE", reason="Clôture proposée",
            actor=self.actor(), ip_address=None,
        )
        review_approval_request(
            self.db, approval=approval,
            reviewer=self.actor("superviseur", "supervisor-id"),
            approved=False, comment="Justificatifs insuffisants", ip_address=None,
        )
        self.db.flush()

        history = self.db.query(AlertDecisionHistory).one()
        self.assertEqual(alert.statut, "GENEREE")
        self.assertEqual(approval.status, REJECTED)
        self.assertEqual(history.decision_status, REJECTED_DECISION)
        self.assertEqual(history.reviewer_comment, "Justificatifs insuffisants")
        actions = {item.action for item in self.db.query(AuditLog).all()}
        self.assertTrue({
            "ALERT_DECISION_REQUESTED", "ALERT_DECISION_REJECTED", "FOUR_EYES_REJECTED",
        }.issubset(actions))
        self.assertEqual(json.loads(approval.old_values)["statut"], "GENEREE")
        self.assertEqual(json.loads(approval.new_values)["statut"], "CLOTUREE")

    def test_08_analysis_api_preserves_each_source_and_score_and_is_audited(self):
        first = self.alert(self.entry("OFAC_SDN"), score=98.25)
        self.alert(self.entry("ONU"), score=91.75)
        self.db.commit()
        client = TestClient(_test_app(self.db))
        client.get(f"/_test/login/{ROLE_CONSULTATION}")

        response = client.get(f"/api/alerts/{first.id}/analysis")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["classification"], "MULTI_SOURCE_PROBABLE")
        self.assertEqual(
            {(item["source"], item["score"]) for item in payload["sources"]},
            {("OFAC_SDN", 98.25), ("ONU", 91.75)},
        )
        self.assertIsNotNone(self.db.query(AuditLog).filter(
            AuditLog.action == "VIEW_ALERT_ANALYSIS",
        ).first())

    def test_09_stale_critical_decision_becomes_obsolete_without_overwrite(self):
        alert = self.alert(self.entry("OFAC_SDN"))
        _, approval = request_alert_decision(
            self.db, alert=alert, new_status="CONFIRMEE", reason="À confirmer",
            actor=self.actor(), ip_address=None,
        )
        self.db.flush()
        alert.statut = "EN_COURS"
        self.db.flush()

        review_approval_request(
            self.db, approval=approval,
            reviewer=self.actor("superviseur", "supervisor-id"),
            approved=True, comment="Validation", ip_address=None,
        )
        self.db.flush()

        history = self.db.query(AlertDecisionHistory).one()
        self.assertEqual(alert.statut, "EN_COURS")
        self.assertEqual(approval.status, OBSOLETE)
        self.assertEqual(history.decision_status, OBSOLETE_DECISION)

    def test_10_web_analysis_groups_sources_and_hides_form_while_pending(self):
        first = self.alert(self.entry("OFAC_SDN"), score=97.0)
        self.alert(self.entry("ONU"), score=93.0)
        request_alert_decision(
            self.db, alert=first, new_status="FAUX_POSITIF", reason="Identité distincte",
            actor=self.actor(), ip_address=None,
        )
        self.db.commit()
        client = TestClient(_test_app(self.db))
        client.get(f"/_test/login/{ROLE_ANALYSTE_CONFORMITE}")

        response = client.get(f"/web/alerts/{first.id}/treat")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Correspondance multi-source probable", response.text)
        self.assertIn("OFAC_SDN", response.text)
        self.assertIn("ONU", response.text)
        self.assertIn("déjà en attente de validation", response.text)
        self.assertNotIn('id="treatForm"', response.text)

    def test_11_schema_creation_is_idempotent(self):
        Base.metadata.create_all(self.engine)
        Base.metadata.create_all(self.engine)
        columns = AlertDecisionHistory.__table__.columns.keys()
        self.assertEqual(
            set(columns),
            {
                "id", "alert_id", "approval_request_id", "old_status", "requested_status",
                "decision_status", "initiated_by", "initiated_at", "reason", "reviewed_by",
                "reviewed_at", "reviewer_comment", "applied_at",
            },
        )
        startup_source = Path("app/main.py").read_text(encoding="utf-8")
        self.assertIn(
            "CREATE INDEX IF NOT EXISTS ix_alerts_client_reference_created_at",
            startup_source,
        )

    def test_12_supervisor_can_open_alert_analysis_before_review(self):
        alert = self.alert(self.entry("OFAC_SDN"))
        _, approval = request_alert_decision(
            self.db, alert=alert, new_status="CONFIRMEE", reason="Correspondance à confirmer",
            actor=self.actor(), ip_address=None,
        )
        self.db.commit()
        client = TestClient(_test_app(self.db))
        client.get(f"/_test/login/{ROLE_SUPERVISEUR_CONFORMITE}")

        response = client.get("/web/approvals")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Alerte CLIENT-3B — OFAC_SDN", response.text)
        self.assertIn(f'/web/alerts/{alert.id}/treat', response.text)
        self.assertIn("Voir alerte", response.text)
        self.assertEqual(approval.status, PENDING)


if __name__ == "__main__":
    unittest.main()
