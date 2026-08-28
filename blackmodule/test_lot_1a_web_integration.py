"""HTTP regression tests for the ADMIN_TECHNIQUE web session.

The session deliberately starts with obsolete embedded permissions, as a
browser session can outlive an RBAC deployment.  The routes must refresh that
payload from the central role matrix before authorizing or rendering a page.
"""

import unittest
import json
from datetime import datetime
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

from app.database import get_db
from app.models import ApprovalRequest, ImportBatch, ListVersion, ListVersionActivation, ListVersionEntry, SanctionEntry
from app.routers import alerts, imports, web
from app.services.authorization_service import (
    ROLE_ADMIN_TECHNIQUE,
    ROLE_ANALYSTE_CONFORMITE,
    ROLE_AUDITEUR,
    ROLE_CONSULTATION,
    ROLE_GESTIONNAIRE_LISTES,
    ROLE_SUPERVISEUR_CONFORMITE,
    role_label,
)


class _Query:
    def __init__(self, items=()):
        self.items = list(items)

    def filter(self, *_args):
        return self

    def group_by(self, *_args):
        return self

    def options(self, *_args):
        return self

    def order_by(self, *_args):
        return self

    def offset(self, *_args):
        return self

    def limit(self, *_args):
        return self

    def with_for_update(self):
        return self

    def all(self):
        return self.items

    def first(self):
        return self.items[0] if self.items else None

    def count(self):
        return len(self.items)


class _Db:
    def __init__(self, approvals=(), versions=(), batches=(), changes=(), activations=(), entries=()):
        self.items_by_model = {
            ApprovalRequest: list(approvals), ListVersion: list(versions), ImportBatch: list(batches),
            ListVersionEntry: list(changes), ListVersionActivation: list(activations),
            SanctionEntry: list(entries),
        }

    def query(self, *_args):
        return _Query(self.items_by_model.get(_args[0], ()) if _args else ())

    def add(self, _item):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass


def _integration_app(approvals=(), versions=(), batches=(), changes=(), activations=(), entries=()) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="blackmodule-rbac-test")
    db = _Db(approvals, versions, batches, changes, activations, entries)

    @app.get("/_test/login/{role}")
    def login(request: Request, role: str):
        request.session["user"] = {
            "id": f"test-{role.lower()}",
            "username": role.lower(),
            "full_name": role_label(role),
            "role": role,
            # Reproduit la session d'avant le correctif RBAC/Navbar.
            "permissions": ["USERS_MANAGE"],
        }
        return {"status": "session ready"}

    app.dependency_overrides[get_db] = lambda: db
    app.include_router(web.router)
    app.include_router(alerts.router)
    app.include_router(imports.router)
    return app


class Lot1AWebIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(_integration_app())
        response = self.client.get(f"/_test/login/{ROLE_ADMIN_TECHNIQUE}")
        self.assertEqual(response.status_code, 200)

    def test_01_admin_technical_read_pages_and_notification_endpoint_return_200(self):
        for path in (
            "/web/dashboard",
            "/web/sanctions",
            "/web/alerts",
            "/web/imports",
            "/web/list-updates",
            "/web/scheduler-status",
            "/web/import-history",
            "/web/list-versions",
            "/web/approvals",
            "/api/alerts/critical-notifications",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_02_rendered_navbar_contains_read_navigation_and_human_role_label(self):
        response = self.client.get("/web/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Filtrage &amp; Conformité", response.text)
        self.assertIn("Listes de sanctions", response.text)
        self.assertIn("Importer les listes", response.text)
        self.assertIn("Scheduler", response.text)
        self.assertIn("Historique des imports", response.text)
        self.assertIn("Versions et restaurations", response.text)
        self.assertIn("Administration", response.text)
        self.assertIn("Audit &amp; Qualité", response.text)
        self.assertIn("Demandes de validation", response.text)
        self.assertIn("Sanctions", response.text)
        self.assertIn("Alertes", response.text)
        self.assertIn('id="notifBell"', response.text)
        self.assertIn("Administrateur technique", response.text)
        self.assertNotIn(">ADMIN_TECHNIQUE<", response.text)

    def test_03_business_and_list_write_routes_return_403(self):
        alert_id = uuid4()
        for status in ("EN_COURS", "FAUX_POSITIF", "CONFIRMEE", "CLOTUREE"):
            with self.subTest(alert_status=status):
                response = self.client.put(
                    f"/api/alerts/{alert_id}/treat",
                    json={"statut": status, "treatment_comment": "test"},
                )
                self.assertEqual(response.status_code, 403)

        approval_response = self.client.post(
            f"/web/approvals/{uuid4()}/review",
            data={"decision": "APPROVE", "comment": "test"},
        )
        self.assertEqual(approval_response.status_code, 403)

    def test_04_approvals_empty_state_is_styled_and_has_no_actions_for_technical_admin(self):
        response = self.client.get("/web/approvals")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Demandes de validation", response.text)
        self.assertIn("Aucune demande de validation", response.text)
        self.assertIn("Aucune opération sensible n'est actuellement en attente de validation.", response.text)
        self.assertIn('class="card"', response.text)
        self.assertNotIn(">Valider<", response.text)
        self.assertNotIn(">Rejeter<", response.text)

    def test_05_user_with_approval_validate_sees_actions_for_another_users_request(self):
        approval = ApprovalRequest(
            id=uuid4(),
            operation_type="ALERT_TREATMENT",
            status="EN_ATTENTE_VALIDATION",
            initiator_user_id="another-user",
            initiated_by="another-user",
            target_entity_type="Alert",
            target_entity_id="target-alert",
        )
        client = TestClient(_integration_app([approval]))
        self.assertEqual(client.get(f"/_test/login/{ROLE_SUPERVISEUR_CONFORMITE}").status_code, 200)
        response = client.get("/web/approvals")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Décision sur alerte", response.text)
        self.assertIn(">Valider<", response.text)
        self.assertIn(">Rejeter<", response.text)
        self.assertNotIn(">Voir fiche<", response.text)

    def test_06_initiator_cannot_see_or_submit_a_review_of_own_request(self):
        role = ROLE_SUPERVISEUR_CONFORMITE
        approval = ApprovalRequest(
            id=uuid4(),
            operation_type="ALERT_TREATMENT",
            status="EN_ATTENTE_VALIDATION",
            initiator_user_id=f"test-{role.lower()}",
            initiated_by=role.lower(),
            target_entity_type="Alert",
            target_entity_id="target-alert",
        )
        client = TestClient(_integration_app([approval]))
        self.assertEqual(client.get(f"/_test/login/{role}").status_code, 200)
        page = client.get("/web/approvals")
        self.assertNotIn(">Valider<", page.text)
        response = client.post(
            f"/web/approvals/{approval.id}/review",
            data={"decision": "APPROVE", "comment": "test"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_07_list_versions_uses_human_labels_and_safe_actions(self):
        active = ListVersion(
            id=uuid4(), source_liste="OFAC_SDN", technical_version="V-active", file_hash="a" * 64,
            archive_content=b"archive", archive_compression="gzip", status="ACTIVE", total_entries=12,
            added_entries=1, modified_entries=2, delisted_entries=0, reactivated_entries=0,
            downloaded_at=datetime(2026, 8, 26, 14, 42),
        )
        archived = ListVersion(
            id=uuid4(), source_liste="OFAC_CONSOLIDATED", technical_version="V-archivee", file_hash="b" * 64,
            archive_content=b"archive", archive_compression="gzip", status="ARCHIVED", total_entries=9,
            downloaded_at=datetime(2026, 8, 25, 9, 15),
        )
        legacy = ImportBatch(
            id=uuid4(), source_liste="FR_GEL", status="SUCCESS", file_hash="c" * 64,
            total_records=4, imported_at=datetime(2026, 8, 24, 8, 0),
        )
        client = TestClient(_integration_app(versions=[active, archived], batches=[legacy]))
        self.assertEqual(client.get(f"/_test/login/{ROLE_ADMIN_TECHNIQUE}").status_code, 200)
        response = client.get("/web/list-versions")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Versions et restaurations des listes", response.text)
        self.assertIn("OFAC SDN", response.text)
        self.assertIn("OFAC Consolidated", response.text)
        self.assertIn("France Gel", response.text)
        self.assertIn("26/08/2026 14:42", response.text)
        self.assertIn("Version active", response.text)
        self.assertIn("Versions archivées restaurables", response.text)
        self.assertIn("<strong>1</strong><span>Versions archivées restaurables</span>", response.text)
        self.assertIn("Non restaurable", response.text)
        self.assertIn("Import réalisé avant la mise en place de l'archivage des versions.", response.text)
        self.assertIn("Voir le détail", response.text)
        self.assertIn(f"/web/list-versions/{archived.id}#restauration", response.text)
        self.assertNotIn(f"/web/list-versions/{active.id}#restauration", response.text)
        self.assertNotIn(">OFAC_SDN<", response.text)

    def test_08_list_version_detail_uses_human_change_labels(self):
        version = ListVersion(
            id=uuid4(), source_liste="UE", technical_version="V-detail", file_hash="d" * 64,
            archive_content=b"archive", archive_compression="gzip", status="ACTIVE", total_entries=1,
            active_entries=1, downloaded_at=datetime(2026, 8, 26, 14, 42),
        )
        change = ListVersionEntry(
            id=uuid4(), list_version_id=version.id, sanction_entry_id=uuid4(), source_record_id="EU-42",
            change_type="MODIFICATION", entry_snapshot=json.dumps({"nom_complet": "Personne exemple"}),
            created_at=datetime(2026, 8, 26, 14, 43),
        )
        client = TestClient(_integration_app(versions=[version], changes=[change]))
        self.assertEqual(client.get(f"/_test/login/{ROLE_ADMIN_TECHNIQUE}").status_code, 200)
        response = client.get(f"/web/list-versions/{version.id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Union européenne", response.text)
        self.assertIn("Modification", response.text)
        self.assertIn("Personne exemple", response.text)
        self.assertIn("26/08/2026 14:43", response.text)
        self.assertIn("SHA-256", response.text)
        self.assertIn("Version active", response.text)

    def test_09_internal_list_creation_button_and_form_follow_rbac(self):
        creators = {
            ROLE_ANALYSTE_CONFORMITE,
            ROLE_SUPERVISEUR_CONFORMITE,
            ROLE_GESTIONNAIRE_LISTES,
        }
        for role in (
            ROLE_ANALYSTE_CONFORMITE, ROLE_SUPERVISEUR_CONFORMITE,
            ROLE_GESTIONNAIRE_LISTES, ROLE_ADMIN_TECHNIQUE,
            ROLE_CONSULTATION, ROLE_AUDITEUR,
        ):
            with self.subTest(role=role):
                client = TestClient(_integration_app())
                self.assertEqual(client.get(f"/_test/login/{role}").status_code, 200)
                listing = client.get("/web/internal-lists")
                self.assertEqual(listing.status_code, 200)
                if role in creators:
                    self.assertIn("+ Nouvelle fiche", listing.text)
                    form = client.get("/web/internal-lists/new")
                    self.assertEqual(form.status_code, 200)
                    self.assertIn("Nouvelle fiche interne", form.text)
                else:
                    self.assertNotIn("+ Nouvelle fiche", listing.text)
                    self.assertEqual(client.get("/web/internal-lists/new").status_code, 403)

    def test_10_approvals_table_uses_business_target_and_terminal_decision_display(self):
        entry = SanctionEntry(
            id=uuid4(), source_liste="ANIF", type_entite="PERSONNE_PHYSIQUE",
            nom="ALPHA", prenom="TESTANIF", nom_complet="ALPHA TESTANIF",
        )
        approval = ApprovalRequest(
            id=uuid4(), operation_type="INTERNAL_LIST_CHANGE", status="VALIDE",
            initiator_user_id="analyste", initiated_by="analyste",
            reviewer_user_id="superviseur", reviewed_by="superviseur",
            target_entity_type="InternalSanctionEntry", target_entity_id=str(entry.id),
            new_values=json.dumps({"action": "SUSPEND", "values": {}}),
            reviewed_at=datetime(2026, 8, 27, 14, 35),
        )
        client = TestClient(_integration_app(approvals=[approval], entries=[entry]))
        self.assertEqual(client.get(f"/_test/login/{ROLE_SUPERVISEUR_CONFORMITE}").status_code, 200)
        response = client.get("/web/approvals")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Traité le", response.text)
        self.assertIn("ALPHA TESTANIF — ANIF", response.text)
        self.assertIn("Suspension", response.text)
        self.assertIn("27/08/2026 14:35", response.text)
        self.assertIn("Traité", response.text)
        detail_path = f"/web/internal-lists/{entry.id}?from=approvals"
        self.assertIn(f'href="{detail_path}"', response.text)
        detail = client.get(detail_path)
        self.assertEqual(detail.status_code, 200)
        self.assertIn("Retour aux demandes de validation", detail.text)
        self.assertNotIn(f"<td>{entry.id}</td>", response.text)
        self.assertNotIn(">Valider<", response.text)
        self.assertNotIn(">Rejeter<", response.text)

    def test_11_internal_approval_link_respects_view_and_review_permissions(self):
        entry = SanctionEntry(
            id=uuid4(), source_liste="ANIF", type_entite="PERSONNE_PHYSIQUE",
            nom="PENDING", prenom="ANIF", nom_complet="PENDING ANIF",
        )
        approval = ApprovalRequest(
            id=uuid4(), operation_type="INTERNAL_LIST_CHANGE", status="EN_ATTENTE_VALIDATION",
            initiator_user_id="another-user", initiated_by="another-user",
            target_entity_type="InternalSanctionEntry", target_entity_id=str(entry.id),
            new_values=json.dumps({"action": "RADIATE", "values": {}}),
        )
        detail_path = f"/web/internal-lists/{entry.id}?from=approvals"
        supervisor = TestClient(_integration_app(approvals=[approval], entries=[entry]))
        self.assertEqual(supervisor.get(f"/_test/login/{ROLE_SUPERVISEUR_CONFORMITE}").status_code, 200)
        page = supervisor.get("/web/approvals")
        self.assertIn(f'href="{detail_path}"', page.text)
        self.assertIn(">Valider<", page.text)
        self.assertIn(">Rejeter<", page.text)

        technical_admin = TestClient(_integration_app(approvals=[approval], entries=[entry]))
        self.assertEqual(technical_admin.get(f"/_test/login/{ROLE_ADMIN_TECHNIQUE}").status_code, 200)
        page = technical_admin.get("/web/approvals")
        self.assertIn(f'href="{detail_path}"', page.text)
        self.assertNotIn(">Valider<", page.text)
        self.assertNotIn(">Rejeter<", page.text)
        self.assertEqual(technical_admin.get(detail_path).status_code, 200)
        self.assertEqual(technical_admin.post(
            f"/web/approvals/{approval.id}/review", data={"decision": "APPROVE"},
        ).status_code, 403)


if __name__ == "__main__":
    unittest.main()
