"""LOT 2C local regression: internal lists stay inactive until four-eyes approval."""

import io
import json
import re
import time
import unittest
from unittest.mock import patch

from openpyxl import Workbook
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from app.database import Base
from app.models import Alert, ApprovalRequest, AuditLog, ImportBatch, InternalListHistory, SanctionEntry
from app.schemas import ClientCheckRequest
from app.routers.matching import check_client
from app.services.approval_service import PENDING, review_approval_request
from app.services.authorization_service import (
    PERMISSION_INTERNAL_LISTS_CREATE, PERMISSION_INTERNAL_LISTS_EDIT,
    PERMISSION_INTERNAL_LISTS_SENSITIVE_VIEW, PERMISSION_INTERNAL_LISTS_VALIDATE,
    PERMISSION_INTERNAL_LISTS_VIEW,
    ROLE_ADMIN_TECHNIQUE, ROLE_ANALYSTE_CONFORMITE, ROLE_AUDITEUR,
    ROLE_CONSULTATION, ROLE_GESTIONNAIRE_LISTES, ROLE_SUPERVISEUR_CONFORMITE,
    has_permission,
)
from app.services.internal_list_service import (
    ACTIVE, DELISTED, DRAFT, PENDING as INTERNAL_PENDING, SUSPENDED,
    DuplicateInternalEntryError, create_internal_entry, parse_internal_import,
    preview_internal_import, request_entry_change, serialize_internal_entry,
    submit_internal_entry,
)
from app.services.matching_service import select_matching_candidates
from app.database import get_db
from app.routers import internal_lists, sanctions, web


def _sqlite_functions(dbapi_connection, _):
    dbapi_connection.create_function("unaccent", 1, lambda value: value)
    dbapi_connection.create_function("regexp_replace", 4, lambda value, pattern, replacement, flags:
                                     re.sub(pattern, replacement, value or ""))


class Lot2CInternalListsTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        event.listen(self.engine, "connect", _sqlite_functions)
        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()
        self.analyst = {"id": "analyst-id", "username": "analyst"}
        self.supervisor = {"id": "supervisor-id", "username": "supervisor"}

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def create(self, category="ANIF", name="DOE", **values):
        return create_internal_entry(self.db, category=category, values={"nom": name, **values}, aliases=["D. DOE"], actor="analyst")

    def activate(self, entry):
        approval = submit_internal_entry(self.db, entry=entry, actor=self.analyst, comment="Contrôle", ip_address=None)
        review_approval_request(self.db, approval=approval, reviewer=self.supervisor, approved=True, comment="Validé", ip_address=None)
        self.db.flush()
        return approval

    def client_for(self, role):
        app = FastAPI(); app.add_middleware(SessionMiddleware, secret_key="lot2c-test")
        @app.get("/_login")
        def login(request: Request):
            request.session["user"] = {"id": f"id-{role}", "username": role.lower(), "role": role}
            return {"ok": True}
        app.dependency_overrides[get_db] = lambda: self.db
        app.include_router(internal_lists.router)
        app.include_router(sanctions.router)
        app.include_router(web.router)
        client = TestClient(app); client.get("/_login")
        return client

    def test_01_creation_brouillon_anif(self):
        entry = self.create()
        self.assertEqual((entry.source_liste, entry.internal_status, entry.statut), ("ANIF", DRAFT, DRAFT))

    def test_02_creation_ppe_fields(self):
        entry = self.create("PPE_INTERNE", ppe_type="NATIONALE", ppe_function="MINISTRE", ppe_institution="ETAT", ppe_status="ACTUELLE")
        self.assertEqual(entry.ppe_function, "MINISTRE")

    def test_03_submission_creates_pending_approval(self):
        entry = self.create(); approval = submit_internal_entry(self.db, entry=entry, actor=self.analyst, comment="x", ip_address=None)
        self.assertEqual(entry.internal_status, INTERNAL_PENDING); self.assertEqual(approval.status, PENDING)

    def test_04_self_validation_is_forbidden(self):
        entry = self.create(); approval = submit_internal_entry(self.db, entry=entry, actor=self.analyst, comment=None, ip_address=None)
        with self.assertRaises(PermissionError): review_approval_request(self.db, approval=approval, reviewer=self.analyst, approved=True, comment=None, ip_address=None)

    def test_05_second_user_activates(self):
        entry = self.create(); self.activate(entry)
        self.assertEqual((entry.internal_status, entry.validated_by), (ACTIVE, "supervisor"))

    def test_06_rejection_returns_submission_to_draft(self):
        entry = self.create(); approval = submit_internal_entry(self.db, entry=entry, actor=self.analyst, comment=None, ip_address=None)
        review_approval_request(self.db, approval=approval, reviewer=self.supervisor, approved=False, comment="À compléter", ip_address=None)
        self.assertEqual((approval.status, entry.internal_status), ("REJETE", DRAFT))

    def test_07_active_modification_is_submitted(self):
        entry = self.create(); self.activate(entry)
        approval = request_entry_change(self.db, entry=entry, actor=self.analyst, action="UPDATE", values={"risk_level": "ELEVE"}, aliases=None, comment="Révision", ip_address=None)
        self.assertEqual(approval.status, PENDING); self.assertIsNone(entry.risk_level)

    def test_08_active_entry_is_used_by_matching(self):
        entry = self.create(name="ALPHA"); self.activate(entry)
        candidates = select_matching_candidates(self.db, "ALPHA")
        self.assertIn(entry.id, [candidate[0].id for candidate in candidates])

    def test_09_draft_is_ignored_by_matching(self):
        entry = self.create(name="BETA")
        self.assertNotIn(entry.id, [candidate[0].id for candidate in select_matching_candidates(self.db, "BETA")])

    def test_10_pending_is_ignored_by_matching(self):
        entry = self.create(name="GAMMA"); submit_internal_entry(self.db, entry=entry, actor=self.analyst, comment=None, ip_address=None)
        self.assertEqual(select_matching_candidates(self.db, "GAMMA"), [])

    def test_11_suspended_is_ignored_by_matching(self):
        entry = self.create(name="DELTA"); self.activate(entry)
        request = request_entry_change(self.db, entry=entry, actor=self.analyst, action="SUSPEND", values={}, aliases=None, comment=None, ip_address=None)
        review_approval_request(self.db, approval=request, reviewer=self.supervisor, approved=True, comment=None, ip_address=None)
        self.assertEqual(entry.internal_status, SUSPENDED); self.assertEqual(select_matching_candidates(self.db, "DELTA"), [])

    def test_12_delisted_is_ignored_by_matching(self):
        entry = self.create(name="EPSILON"); self.activate(entry)
        request = request_entry_change(self.db, entry=entry, actor=self.analyst, action="RADIATE", values={}, aliases=None, comment=None, ip_address=None)
        review_approval_request(self.db, approval=request, reviewer=self.supervisor, approved=True, comment=None, ip_address=None)
        self.assertEqual(entry.internal_status, DELISTED); self.assertEqual(select_matching_candidates(self.db, "EPSILON"), [])

    def test_13_reactivation_requires_validation(self):
        entry = self.create(); self.activate(entry); entry.internal_status = entry.statut = SUSPENDED
        approval = request_entry_change(self.db, entry=entry, actor=self.analyst, action="REACTIVATE", values={}, aliases=None, comment=None, ip_address=None)
        self.assertEqual(entry.internal_status, SUSPENDED); review_approval_request(self.db, approval=approval, reviewer=self.supervisor, approved=True, comment=None, ip_address=None)
        self.assertEqual(entry.internal_status, ACTIVE)

    def test_14_alert_provenance_is_internal_source(self):
        entry = self.create("JUDICIAIRE", name="MATCHABLE"); self.activate(entry)
        check_client(ClientCheckRequest(nom="MATCHABLE"), self.db, {"username": "analyst"})
        alert = self.db.query(Alert).filter_by(sanction_entry_id=entry.id).one()
        self.assertEqual(alert.source_liste, "JUDICIAIRE")

    def test_15_consultation_audit_is_recorded(self):
        entry = self.create(); self.db.add(AuditLog(user_identifier="reader", action="VIEW_INTERNAL_LIST_DETAIL", entity_type="InternalSanctionEntry", entity_id=str(entry.id), description="Consultation nominative d'une fiche interne.")); self.db.flush()
        self.assertEqual(self.db.query(AuditLog).filter_by(action="VIEW_INTERNAL_LIST_DETAIL").count(), 1)

    def test_16_admin_technique_is_read_only(self):
        user = {"role": ROLE_ADMIN_TECHNIQUE}; self.assertTrue(has_permission(user, PERMISSION_INTERNAL_LISTS_VIEW)); self.assertFalse(has_permission(user, PERMISSION_INTERNAL_LISTS_CREATE)); self.assertFalse(has_permission(user, PERMISSION_INTERNAL_LISTS_SENSITIVE_VIEW))

    def test_17_analyst_can_create_and_edit(self):
        user = {"role": ROLE_ANALYSTE_CONFORMITE}; self.assertTrue(has_permission(user, PERMISSION_INTERNAL_LISTS_CREATE)); self.assertTrue(has_permission(user, PERMISSION_INTERNAL_LISTS_EDIT)); self.assertTrue(has_permission(user, PERMISSION_INTERNAL_LISTS_SENSITIVE_VIEW))

    def test_18_supervisor_can_validate(self):
        self.assertTrue(has_permission({"role": ROLE_SUPERVISEUR_CONFORMITE}, PERMISSION_INTERNAL_LISTS_VALIDATE))

    def test_19_consultation_is_read_only(self):
        user = {"role": ROLE_CONSULTATION}; self.assertTrue(has_permission(user, PERMISSION_INTERNAL_LISTS_VIEW)); self.assertFalse(has_permission(user, PERMISSION_INTERNAL_LISTS_EDIT)); self.assertFalse(has_permission(user, PERMISSION_INTERNAL_LISTS_SENSITIVE_VIEW))

    def test_20_valid_csv_preview(self):
        workbook = Workbook(); sheet = workbook.active; sheet.append(["nom", "prenom", "risk_level"]); sheet.append(["DOE", "JOHN", "ELEVE"])
        content = io.BytesIO(); workbook.save(content)
        accepted, rejected = parse_internal_import(content.getvalue(), "internal.xlsx")
        self.assertEqual((len(accepted), rejected), (1, []))

    def test_21_invalid_import_row_is_rejected(self):
        accepted, rejected = parse_internal_import(b"nom,source_reference\n,REF\n", "internal.csv")
        self.assertEqual((accepted, rejected[0]["error"]), ([], "nom obligatoire"))

    def test_22_imported_data_stays_draft(self):
        accepted, _ = parse_internal_import(b"nom\nDOE\n", "internal.csv")
        entry = create_internal_entry(self.db, category="ANIF", values=accepted[0], aliases=[], actor="analyst")
        self.assertEqual(entry.internal_status, DRAFT)

    def test_23_history_is_preserved(self):
        entry = self.create(); self.activate(entry)
        self.assertGreaterEqual(self.db.query(InternalListHistory).filter_by(sanction_entry_id=entry.id).count(), 3)

    def test_24_sensitive_change_keeps_old_and_new_values(self):
        entry = self.create(); self.activate(entry)
        approval = request_entry_change(self.db, entry=entry, actor=self.analyst, action="UPDATE", values={"source_reference": "REF-2"}, aliases=None, comment="x", ip_address=None)
        self.assertIn("source_reference", approval.old_values); self.assertIn("REF-2", approval.new_values)

    def test_25_direct_unprivileged_api_write_returns_403(self):
        app = FastAPI(); app.add_middleware(SessionMiddleware, secret_key="lot2c-test")
        @app.get("/_login")
        def login(request: Request):
            request.session["user"] = {"id": "reader", "username": "reader", "role": ROLE_CONSULTATION}
            return {"ok": True}
        app.dependency_overrides[get_db] = lambda: self.db
        app.include_router(internal_lists.router)
        client = TestClient(app); client.get("/_login")
        response = client.post("/api/internal-lists/", json={"category": "ANIF", "values": {"nom": "DOE"}})
        self.assertEqual(response.status_code, 403)

    def test_26_active_update_waits_for_validation(self):
        entry = self.create(risk_level="ELEVE"); self.activate(entry)
        approval = request_entry_change(self.db, entry=entry, actor=self.analyst, action="UPDATE",
                                        values={"risk_level": "MOYEN"}, aliases=None,
                                        comment="révision", ip_address=None)
        self.assertEqual(entry.risk_level, "ELEVE")
        self.assertIn("MOYEN", approval.new_values)

    def test_27_rejected_active_update_keeps_old_value(self):
        entry = self.create(risk_level="ELEVE"); self.activate(entry)
        approval = request_entry_change(self.db, entry=entry, actor=self.analyst, action="UPDATE",
                                        values={"risk_level": "MOYEN"}, aliases=None, comment=None, ip_address=None)
        review_approval_request(self.db, approval=approval, reviewer=self.supervisor,
                                approved=False, comment="refus", ip_address=None)
        self.assertEqual(entry.risk_level, "ELEVE")

    def test_28_approved_active_update_applies_new_value(self):
        entry = self.create(risk_level="ELEVE"); self.activate(entry)
        approval = request_entry_change(self.db, entry=entry, actor=self.analyst, action="UPDATE",
                                        values={"risk_level": "MOYEN"}, aliases=None, comment=None, ip_address=None)
        review_approval_request(self.db, approval=approval, reviewer=self.supervisor,
                                approved=True, comment="ok", ip_address=None)
        self.assertEqual(entry.risk_level, "MOYEN")

    def test_29_pending_active_name_change_keeps_old_matching_state(self):
        entry = self.create(name="ORIGINAL"); self.activate(entry)
        request_entry_change(self.db, entry=entry, actor=self.analyst, action="UPDATE",
                             values={"nom": "PROPOSE"}, aliases=None, comment=None, ip_address=None)
        self.assertIn(entry.id, [candidate[0].id for candidate in select_matching_candidates(self.db, "ORIGINAL")])
        self.assertNotIn(entry.id, [candidate[0].id for candidate in select_matching_candidates(self.db, "PROPOSE")])

    def test_30_pending_suspension_keeps_entry_active(self):
        entry = self.create(name="SUSPEND WAIT"); self.activate(entry)
        request_entry_change(self.db, entry=entry, actor=self.analyst, action="SUSPEND",
                             values={}, aliases=None, comment=None, ip_address=None)
        self.assertEqual(entry.internal_status, ACTIVE)
        self.assertIn(entry.id, [candidate[0].id for candidate in select_matching_candidates(self.db, "SUSPEND WAIT")])

    def test_31_pending_radiation_keeps_entry_active_then_validation_excludes_it(self):
        entry = self.create(name="RADIATE WAIT"); self.activate(entry)
        approval = request_entry_change(self.db, entry=entry, actor=self.analyst, action="RADIATE",
                                        values={}, aliases=None, comment=None, ip_address=None)
        self.assertIn(entry.id, [candidate[0].id for candidate in select_matching_candidates(self.db, "RADIATE WAIT")])
        review_approval_request(self.db, approval=approval, reviewer=self.supervisor,
                                approved=True, comment="ok", ip_address=None)
        self.assertEqual(entry.internal_status, DELISTED)
        self.assertEqual(select_matching_candidates(self.db, "RADIATE WAIT"), [])

    def test_32_pending_reactivation_stays_suspended(self):
        entry = self.create(name="REACTIVATE WAIT"); self.activate(entry)
        suspension = request_entry_change(self.db, entry=entry, actor=self.analyst, action="SUSPEND",
                                          values={}, aliases=None, comment=None, ip_address=None)
        review_approval_request(self.db, approval=suspension, reviewer=self.supervisor,
                                approved=True, comment="ok", ip_address=None)
        request_entry_change(self.db, entry=entry, actor=self.analyst, action="REACTIVATE",
                             values={}, aliases=None, comment=None, ip_address=None)
        self.assertEqual(entry.internal_status, SUSPENDED)
        self.assertEqual(select_matching_candidates(self.db, "REACTIVATE WAIT"), [])

    def test_33_general_api_payload_masks_sensitive_fields(self):
        entry = self.create(risk_level="ELEVE", source_reference="SECRET-REF",
                            compliance_comment="SECRET-COMMENT", num_passeport="P123")
        payload = serialize_internal_entry(entry, include_sensitive=False)
        for field in (
            "risk_level", "source_reference", "compliance_comment", "num_passeport",
            "created_by", "submitted_by", "validated_by", "history",
        ):
            self.assertNotIn(field, payload)

    def test_34_direct_api_filters_sensitive_fields_and_audits_view(self):
        entry = self.create(risk_level="ELEVE", source_reference="SECRET-REF")
        self.db.flush()
        response = self.client_for(ROLE_CONSULTATION).get(f"/api/internal-lists/{entry.id}")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("source_reference", response.json())
        audit = self.db.query(AuditLog).filter_by(action="VIEW_INTERNAL_LIST_DETAIL").one()
        self.assertIn("CONSULTATION", audit.description)
        self.assertIn("ANIF", audit.description)
        self.assertIsNotNone(audit.ip_address)

    def test_35_sensitive_api_permission_returns_full_business_fields(self):
        entry = self.create(source_reference="SECRET-REF", compliance_comment="SECRET-COMMENT")
        self.db.flush()
        response = self.client_for(ROLE_ANALYSTE_CONFORMITE).get(f"/api/internal-lists/{entry.id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["source_reference"], "SECRET-REF")

    def test_36_technical_audit_logs_never_contain_sensitive_comment(self):
        entry = self.create(compliance_comment="TOP-SECRET")
        submit_internal_entry(self.db, entry=entry, actor=self.analyst,
                              comment="TOP-SECRET", ip_address=None)
        self.db.flush()
        descriptions = " ".join(item.description or "" for item in self.db.query(AuditLog).all())
        self.assertNotIn("TOP-SECRET", descriptions)

    def test_37_document_number_duplicate_is_blocked(self):
        self.create(document_number="DOC-123")
        with self.assertRaises(DuplicateInternalEntryError):
            self.create(name="OTHER", document_number="DOC-123")

    def test_38_passport_duplicate_is_blocked(self):
        self.create(num_passeport="P-123")
        with self.assertRaises(DuplicateInternalEntryError):
            self.create(name="OTHER", num_passeport="P-123")

    def test_39_duplicate_inside_import_file_is_reported(self):
        content = b"nom,date_naissance\nDOE,1980-01-01\nDOE,1980-01-01\n"
        accepted, rejected, duplicates = preview_internal_import(
            self.db, category="ANIF", file_content=content, filename="internal.csv")
        self.assertEqual((len(accepted), len(rejected), len(duplicates)), (1, 0, 1))

    def test_40_import_duplicate_against_database_is_reported(self):
        self.create(num_passeport="P-BASE")
        accepted, _, duplicates = preview_internal_import(
            self.db, category="ANIF", file_content=b"nom,num_passeport\nOTHER,P-BASE\n",
            filename="internal.csv")
        self.assertEqual(len(accepted), 0); self.assertEqual(len(duplicates), 1)

    def test_41_name_only_homonym_is_not_merged(self):
        first = self.create(name="HOMONYME")
        second = self.create(category="JUDICIAIRE", name="HOMONYME")
        self.assertNotEqual(first.id, second.id)

    def test_42_ppe_end_date_never_changes_lifecycle_automatically(self):
        entry = self.create("PPE_INTERNE", ppe_status="ANCIENNE",
                            ppe_function_end_date="2020-01-01")
        self.assertEqual(entry.internal_status, DRAFT)
        self.activate(entry)
        self.assertEqual(entry.internal_status, ACTIVE)

    def test_43_matching_performance_remains_bounded_with_internal_columns(self):
        self.db.add_all([
            SanctionEntry(source_liste="ANIF", is_internal_list=True, internal_status=ACTIVE,
                          statut=ACTIVE, type_entite="PERSONNE_PHYSIQUE", nom=f"PERF {index}",
                          nom_complet=f"PERF {index}")
            for index in range(1_000)
        ])
        self.db.flush()
        started = time.perf_counter()
        matches = select_matching_candidates(self.db, "PERF 999")
        elapsed = time.perf_counter() - started
        self.assertTrue(matches)
        self.assertLess(elapsed, 5.0)

    def test_44_generic_sanction_detail_refuses_sensitive_internal_record(self):
        entry = self.create(num_passeport="PRIVATE-PASSPORT"); self.db.flush()
        response = self.client_for(ROLE_CONSULTATION).get(f"/api/sanctions/{entry.id}")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("PRIVATE-PASSPORT", response.text)

    def test_45_import_requires_preview_confirmation_and_creates_draft(self):
        client = self.client_for(ROLE_ANALYSTE_CONFORMITE)
        upload = {"file": ("internal.csv", b"nom,num_passeport\nIMPORT TEST,NEW-PASS\n", "text/csv")}
        preview_required = client.post("/api/internal-lists/import?category=ANIF", files=upload)
        self.assertEqual(preview_required.status_code, 409)
        direct_confirmation = client.post(
            "/api/internal-lists/import?category=ANIF&confirmed=true", files=upload,
        )
        self.assertEqual(direct_confirmation.status_code, 409)
        preview = client.post("/api/internal-lists/import/preview?category=ANIF", files=upload)
        self.assertEqual(preview.status_code, 200)
        confirmed = client.post(
            "/api/internal-lists/import?category=ANIF&confirmed=true&preview_token="
            + preview.json()["preview_token"], files=upload,
        )
        self.assertEqual(confirmed.status_code, 201)
        entry = self.db.query(SanctionEntry).filter_by(num_passeport="NEW-PASS").one()
        self.assertEqual(entry.internal_status, DRAFT)

    def test_45b_web_import_page_uses_existing_preview_api_and_rbac(self):
        analyst_page = self.client_for(ROLE_ANALYSTE_CONFORMITE).get("/web/internal-lists/import")
        self.assertEqual(analyst_page.status_code, 200)
        for text in ("Importer un fichier", "Télécharger le modèle CSV", "Prévisualiser le fichier", "Confirmer l'import", "/api/internal-lists/import/preview", "Valides", "Doublons potentiels"):
            self.assertIn(text, analyst_page.text)
        listing = self.client_for(ROLE_ANALYSTE_CONFORMITE).get("/web/internal-lists")
        self.assertIn("Importer un fichier", listing.text)
        self.assertEqual(self.client_for(ROLE_ADMIN_TECHNIQUE).get("/web/internal-lists/import").status_code, 403)

    def test_45c_file_preview_reads_csv_and_xlsx_without_persisting(self):
        client = self.client_for(ROLE_ANALYSTE_CONFORMITE)
        csv = {"file": ("visible.csv", b"nom,prenom\nCSV DOE,JOHN\n", "text/csv")}
        csv_response = client.post("/api/internal-lists/import/file-preview", files=csv)
        self.assertEqual(csv_response.status_code, 200)
        self.assertEqual(csv_response.json()["rows"][0]["values"]["nom"], "CSV DOE")
        workbook = Workbook(); sheet = workbook.active; sheet.append(["nom", "prenom"]); sheet.append(["XLSX DOE", "JANE"])
        content = io.BytesIO(); workbook.save(content)
        xlsx_response = client.post("/api/internal-lists/import/file-preview", files={
            "file": ("visible.xlsx", content.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        })
        self.assertEqual(xlsx_response.status_code, 200)
        self.assertEqual(xlsx_response.json()["rows"][0]["values"]["nom"], "XLSX DOE")
        self.assertEqual(self.db.query(SanctionEntry).count(), 0)
        self.assertEqual(self.client_for(ROLE_ADMIN_TECHNIQUE).post(
            "/api/internal-lists/import/file-preview", files=csv,
        ).status_code, 403)

    def test_45d_internal_import_rejects_oversized_upload_before_parsing(self):
        client = self.client_for(ROLE_ANALYSTE_CONFORMITE)
        with patch.object(internal_lists, "INTERNAL_LIST_IMPORT_MAX_BYTES", 8):
            response = client.post(
                "/api/internal-lists/import/preview?category=ANIF",
                files={"file": ("large.csv", b"nom\nTOO-LARGE\n", "text/csv")},
            )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.db.query(SanctionEntry).count(), 0)

    def test_46_web_new_form_creates_a_draft_with_existing_service(self):
        client = self.client_for(ROLE_ANALYSTE_CONFORMITE)
        self.assertEqual(client.get("/web/internal-lists/new").status_code, 200)
        response = client.post(
            "/web/internal-lists",
            data={"category": "ANIF", "nom": "FORM DOE", "aliases": "F. DOE, Formulaire Doe"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        entry = self.db.query(SanctionEntry).filter_by(nom="FORM DOE").one()
        self.assertEqual(entry.internal_status, DRAFT)
        self.assertEqual(entry.statut, DRAFT)

    def test_47_web_edit_draft_updates_the_existing_record(self):
        entry = self.create(name="DRAFT BEFORE", risk_level="FAIBLE")
        client = self.client_for(ROLE_ANALYSTE_CONFORMITE)
        page = client.get(f"/web/internal-lists/{entry.id}/edit")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Modifier la fiche interne", page.text)
        self.assertIn("DRAFT BEFORE", page.text)
        response = client.post(
            f"/web/internal-lists/{entry.id}/edit",
            data={"nom": "DRAFT AFTER", "risk_level": "MOYEN", "aliases": "DRAFT ALIAS"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual((entry.nom, entry.risk_level, entry.internal_status), ("DRAFT AFTER", "MOYEN", DRAFT))
        self.assertEqual([alias.alias for alias in entry.aliases], ["DRAFT ALIAS"])

    def test_48_web_edit_active_creates_a_four_eyes_update_without_mutation(self):
        entry = self.create(name="ACTIVE BEFORE", risk_level="ELEVE"); self.activate(entry)
        client = self.client_for(ROLE_ANALYSTE_CONFORMITE)
        response = client.post(
            f"/web/internal-lists/{entry.id}/edit",
            data={"nom": "ACTIVE AFTER", "risk_level": "MOYEN", "aliases": "ACTIVE ALIAS"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual((entry.nom, entry.risk_level, entry.internal_status), ("ACTIVE BEFORE", "ELEVE", ACTIVE))
        approval = self.db.query(ApprovalRequest).filter_by(target_entity_id=str(entry.id), status=PENDING).one()
        proposal = json.loads(approval.new_values)
        self.assertEqual((proposal["action"], proposal["values"]["nom"], proposal["values"]["risk_level"]),
                         ("UPDATE", "ACTIVE AFTER", "MOYEN"))

    def test_49_web_edit_button_and_routes_require_edit_permission(self):
        entry = self.create()
        for role in (ROLE_ANALYSTE_CONFORMITE, ROLE_SUPERVISEUR_CONFORMITE, ROLE_GESTIONNAIRE_LISTES):
            with self.subTest(role=role, expected="allowed"):
                client = self.client_for(role)
                self.assertIn("Modifier la fiche", client.get(f"/web/internal-lists/{entry.id}").text)
                self.assertEqual(client.get(f"/web/internal-lists/{entry.id}/edit").status_code, 200)
        for role in (ROLE_ADMIN_TECHNIQUE, ROLE_CONSULTATION, ROLE_AUDITEUR):
            with self.subTest(role=role, expected="forbidden"):
                client = self.client_for(role)
                self.assertNotIn("Modifier la fiche", client.get(f"/web/internal-lists/{entry.id}").text)
                self.assertEqual(client.get(f"/web/internal-lists/{entry.id}/edit").status_code, 403)
                self.assertEqual(client.post(f"/web/internal-lists/{entry.id}/edit", data={"nom": "NOPE"}).status_code, 403)

    def test_50_internal_web_pages_use_structured_cards_and_conditional_ppe(self):
        entry = self.create(name="VISUAL DOE", risk_level="ELEVE")
        client = self.client_for(ROLE_ANALYSTE_CONFORMITE)
        detail = client.get(f"/web/internal-lists/{entry.id}")
        self.assertEqual(detail.status_code, 200)
        for label in ("Classification", "Identité", "Identification", "Informations conformité", "Risque Élevé"):
            self.assertIn(label, detail.text)
        self.assertIn("grid-template-columns:repeat(2", detail.text)
        self.assertNotIn("<h3>PPE</h3>", detail.text)
        form = client.get(f"/web/internal-lists/{entry.id}/edit")
        self.assertEqual(form.status_code, 200)
        self.assertIn("Enregistrer les modifications", form.text)
        self.assertIn('data-tab="classification"', form.text)
        ppe = self.create(category="PPE_INTERNE", name="PPE VISUAL", ppe_status="ACTUELLE")
        ppe_detail = client.get(f"/web/internal-lists/{ppe.id}")
        self.assertEqual(ppe_detail.status_code, 200)
        self.assertIn('data-panel="ppe"', ppe_detail.text)

    def test_51_internal_web_pages_use_compact_tabs_and_sticky_actions(self):
        entry = self.create(name="TABS DOE", risk_level="MOYEN")
        client = self.client_for(ROLE_ANALYSTE_CONFORMITE)
        form = client.get(f"/web/internal-lists/{entry.id}/edit")
        self.assertEqual(form.status_code, 200)
        for tab_name in ("classification", "identity", "identification", "compliance", "ppe"):
            self.assertIn(f'data-tab="{tab_name}"', form.text)
        self.assertIn('class="actions-bar"', form.text)
        self.assertIn('position:sticky', form.text)
        self.assertIn('id="ppe-tab"', form.text)
        detail = client.get(f"/web/internal-lists/{entry.id}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn('class="tabs"', detail.text)
        self.assertIn('data-panel="identity" hidden', detail.text)
        self.assertNotIn('data-tab="ppe"', detail.text)

    def test_52_internal_history_is_a_sensitive_business_diff_not_raw_json(self):
        entry = self.create(name="HISTORY DOE", risk_level="FAIBLE")
        request_entry_change(
            self.db, entry=entry, actor=self.analyst, action="UPDATE", values={"risk_level": "MOYEN"},
            aliases=None, comment="Mise à jour du risque", ip_address=None,
        )
        analyst_detail = self.client_for(ROLE_ANALYSTE_CONFORMITE).get(f"/web/internal-lists/{entry.id}")
        self.assertEqual(analyst_detail.status_code, 200)
        for label in ("Champ", "Ancienne valeur", "Nouvelle valeur", "Niveau de risque", "Faible", "Moyen"):
            self.assertIn(label, analyst_detail.text)
        self.assertIn("Fiche créée en brouillon", analyst_detail.text)
        self.assertNotIn("old_values", analyst_detail.text)
        self.assertIn("#fef2f2", analyst_detail.text)
        self.assertIn("inset 0 -2px #dc2626", analyst_detail.text)
        consultation_detail = self.client_for(ROLE_CONSULTATION).get(f"/web/internal-lists/{entry.id}")
        self.assertEqual(consultation_detail.status_code, 200)
        self.assertNotIn("Historique des changements", consultation_detail.text)

    def test_53_active_risk_only_update_contains_and_applies_only_risk_level(self):
        entry = self.create(
            name="RISK ONLY", prenom="ALICE", risk_level="FAIBLE",
            nationalite="GABONAISE", source_reference="KEEP-REFERENCE",
        )
        self.activate(entry)
        original = {
            "nom": entry.nom, "prenom": entry.prenom, "nationalite": entry.nationalite,
            "source_reference": entry.source_reference, "ppe_status": entry.ppe_status,
            "aliases": [alias.alias for alias in entry.aliases],
        }
        approval = request_entry_change(
            self.db, entry=entry, actor=self.analyst, action="UPDATE",
            values={
                "nom": "RISK ONLY", "prenom": "ALICE", "risk_level": "ELEVE",
                "nationalite": "GABONAISE", "source_reference": "KEEP-REFERENCE",
                "document_number": None, "compliance_comment": "None",
                "ppe_status": "NONE", "ppe_function": "None",
            },
            aliases=["D. DOE"], comment="Risque uniquement", ip_address=None,
        )
        payload = json.loads(approval.new_values)
        self.assertEqual(payload, {"action": "UPDATE", "values": {"risk_level": "ELEVE"}})
        self.assertEqual(entry.risk_level, "FAIBLE")
        self.assertEqual(original, {
            "nom": entry.nom, "prenom": entry.prenom, "nationalite": entry.nationalite,
            "source_reference": entry.source_reference, "ppe_status": entry.ppe_status,
            "aliases": [alias.alias for alias in entry.aliases],
        })
        review_approval_request(
            self.db, approval=approval, reviewer=self.supervisor, approved=True,
            comment="Validé", ip_address=None,
        )
        self.assertEqual(entry.risk_level, "ELEVE")
        self.assertEqual(original, {
            "nom": entry.nom, "prenom": entry.prenom, "nationalite": entry.nationalite,
            "source_reference": entry.source_reference, "ppe_status": entry.ppe_status,
            "aliases": [alias.alias for alias in entry.aliases],
        })
        detail = self.client_for(ROLE_ANALYSTE_CONFORMITE).get(f"/web/internal-lists/{entry.id}")
        self.assertIn("Fiche créée en brouillon", detail.text)
        self.assertIn("Fiche activée après validation", detail.text)
        self.assertRegex(detail.text, r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}")


    def test_54_traceability_uses_persisted_timestamps_and_respects_sensitive_rbac(self):
        entry = self.create(name="TRACE DOE")
        approval = submit_internal_entry(
            self.db, entry=entry, actor=self.analyst, comment="Soumission", ip_address=None,
        )
        review_approval_request(
            self.db, approval=approval, reviewer=self.supervisor, approved=False,
            comment="Informations à compléter", ip_address=None,
        )
        self.db.flush()

        sensitive_detail = self.client_for(ROLE_ANALYSTE_CONFORMITE).get(
            f"/web/internal-lists/{entry.id}"
        )
        self.assertEqual(sensitive_detail.status_code, 200)
        for label in ("Traçabilité", "Création", "Soumission", "Validation", "modification", "Rejet"):
            self.assertIn(label, sensitive_detail.text)
        self.assertIn("supervisor", sensitive_detail.text)
        self.assertRegex(sensitive_detail.text, r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}")

        consultation_detail = self.client_for(ROLE_CONSULTATION).get(
            f"/web/internal-lists/{entry.id}"
        )
        self.assertEqual(consultation_detail.status_code, 200)
        self.assertNotIn("Traçabilité", consultation_detail.text)


    def test_55_sensitive_transition_has_toast_pending_state_and_no_duplicate(self):
        entry = self.create(name="PENDING SUSPEND")
        self.activate(entry)
        client = self.client_for(ROLE_ANALYSTE_CONFORMITE)

        response = client.post(
            f"/web/internal-lists/{entry.id}/lifecycle",
            data={"action": "SUSPEND", "comment": "Revue requise"}, follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn("success=1", response.headers["location"])
        self.assertEqual(entry.internal_status, ACTIVE)
        self.assertEqual(
            self.db.query(ApprovalRequest).filter_by(
                target_entity_id=str(entry.id), status=PENDING,
            ).count(),
            1,
        )

        detail = client.get(response.headers["location"])
        self.assertEqual(detail.status_code, 200)
        self.assertIn('data-action-notice', detail.text)
        self.assertIn("Demande de suspension envoyée pour validation", detail.text)
        self.assertIn('class="btn pending-button"', detail.text)
        self.assertIn("En attente", detail.text)
        self.assertIn('status-ACTIF">ACTIF', detail.text)
        self.assertNotIn('status-SUSPENDUE">SUSPENDUE', detail.text)
        self.assertNotIn('name="action" value="SUSPEND"', detail.text)
        self.assertNotIn('name="action" value="RADIATE"', detail.text)
        self.assertIn("sensitive-action-form", detail.text)
        self.assertIn("form.dataset.submitting", detail.text)

        duplicate = client.post(
            f"/web/internal-lists/{entry.id}/lifecycle",
            data={"action": "SUSPEND", "comment": "Double clic"}, follow_redirects=False,
        )
        self.assertEqual(duplicate.status_code, 303)
        self.assertEqual(
            self.db.query(ApprovalRequest).filter_by(
                target_entity_id=str(entry.id), status=PENDING,
            ).count(),
            1,
        )
        consultation = self.client_for(ROLE_CONSULTATION).post(
            f"/web/internal-lists/{entry.id}/lifecycle", data={"action": "SUSPEND"},
        )
        self.assertEqual(consultation.status_code, 403)


    def test_56_status_specific_actions_risk_labels_and_suspended_kpi(self):
        active = self.create(name="ACTIVE UI", risk_level="ELEVE")
        self.activate(active)
        suspended = self.create(name="SUSPENDED UI", risk_level="MOYEN")
        self.activate(suspended)
        suspension = request_entry_change(
            self.db, entry=suspended, actor=self.analyst, action="SUSPEND",
            values={}, aliases=None, comment="Suspendre", ip_address=None,
        )
        review_approval_request(
            self.db, approval=suspension, reviewer=self.supervisor, approved=True,
            comment="Validé", ip_address=None,
        )
        delisted = self.create(name="DELISTED UI", risk_level="FAIBLE")
        self.activate(delisted)
        radiation = request_entry_change(
            self.db, entry=delisted, actor=self.analyst, action="RADIATE",
            values={}, aliases=None, comment="Radier", ip_address=None,
        )
        review_approval_request(
            self.db, approval=radiation, reviewer=self.supervisor, approved=True,
            comment="Validé", ip_address=None,
        )
        self.db.flush()
        client = self.client_for(ROLE_ANALYSTE_CONFORMITE)

        active_page = client.get(f"/web/internal-lists/{active.id}")
        self.assertIn('name="action" value="SUSPEND"', active_page.text)
        self.assertIn('name="action" value="RADIATE"', active_page.text)
        self.assertNotIn('name="action" value="REACTIVATE"', active_page.text)
        self.assertIn("Risque Élevé", active_page.text)
        self.assertIn(">Élevé<", active_page.text)

        suspended_page = client.get(f"/web/internal-lists/{suspended.id}")
        self.assertNotIn('name="action" value="SUSPEND"', suspended_page.text)
        self.assertIn('name="action" value="REACTIVATE"', suspended_page.text)
        self.assertIn('name="action" value="RADIATE"', suspended_page.text)

        delisted_page = client.get(f"/web/internal-lists/{delisted.id}")
        self.assertNotIn("Transition soumise", delisted_page.text)
        self.assertNotIn('name="action" value="SUSPEND"', delisted_page.text)
        self.assertNotIn('name="action" value="REACTIVATE"', delisted_page.text)
        self.assertNotIn('name="action" value="RADIATE"', delisted_page.text)

        listing = client.get("/web/internal-lists")
        self.assertIn("Suspendues", listing.text)
        self.assertIn("<strong>1</strong><span>Suspendues</span>", listing.text)
        self.assertIn(">Élevé<", listing.text)
        consultation_page = self.client_for(ROLE_CONSULTATION).get(f"/web/internal-lists/{active.id}")
        self.assertNotIn("Transition soumise", consultation_page.text)


if __name__ == "__main__":
    unittest.main()
