"""HTTP regression tests for the ADMIN_TECHNIQUE web session.

The session deliberately starts with obsolete embedded permissions, as a
browser session can outlive an RBAC deployment.  The routes must refresh that
payload from the central role matrix before authorizing or rendering a page.
"""

import unittest
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

from app.database import get_db
from app.models import ApprovalRequest
from app.routers import alerts, imports, web
from app.services.authorization_service import (
    ROLE_ADMIN_TECHNIQUE,
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
    def __init__(self, approvals=()):
        self.approvals = list(approvals)

    def query(self, *_args):
        if _args and _args[0] is ApprovalRequest:
            return _Query(self.approvals)
        return _Query()

    def add(self, _item):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass


def _integration_app(approvals=()) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="blackmodule-rbac-test")
    db = _Db(approvals)

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


if __name__ == "__main__":
    unittest.main()
