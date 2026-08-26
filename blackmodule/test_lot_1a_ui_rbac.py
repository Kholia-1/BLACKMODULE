import unittest
from types import SimpleNamespace

from app.routers import web
from app.routers.web import templates
from app.services.api_auth import require_permission as api_require_permission
from app.services.authorization_service import (
    PERMISSION_ALERTS_CLOSE,
    PERMISSION_ALERTS_CONFIRM,
    PERMISSION_ALERTS_TREAT,
    PERMISSION_LISTS_IMPORT,
    PERMISSION_LISTS_MANAGE,
    PERMISSION_LISTS_VIEW,
    PERMISSION_NOTIFICATIONS_VIEW,
    ROLE_ADMIN_TECHNIQUE,
    ROLE_ANALYSTE_CONFORMITE,
    ROLE_GESTIONNAIRE_LISTES,
    ROLE_SUPERVISEUR_CONFORMITE,
    has_permission,
    permissions_for_role,
    role_label,
)


def _navbar_for(role: str) -> str:
    permissions = sorted(permissions_for_role(role))
    request = SimpleNamespace(
        session={
            "user": {
                "username": "ui-test",
                "full_name": "UI Test",
                "role": role,
                "role_label": role_label(role),
                "permissions": permissions,
            }
        },
        url=SimpleNamespace(path="/web/dashboard"),
    )
    return templates.get_template("partials/navbar.html").render(request=request)


class _AuditDb:
    def __init__(self):
        self.added = []

    def add(self, item):
        self.added.append(item)

    def commit(self):
        pass


def _web_request(role: str):
    return SimpleNamespace(
        session={
            "user": {
                "username": "ui-test",
                "role": role,
                "permissions": sorted(permissions_for_role(role)),
            }
        },
        client=SimpleNamespace(host="127.0.0.1"),
    )


class Lot1AUiRbacRegressionTests(unittest.TestCase):
    def setUp(self):
        self.admin = {"role": ROLE_ADMIN_TECHNIQUE, "permissions": permissions_for_role(ROLE_ADMIN_TECHNIQUE)}
        self.navbar = _navbar_for(ROLE_ADMIN_TECHNIQUE)

    def test_01_admin_technical_sees_dashboard(self):
        self.assertIn("Dashboard", self.navbar)

    def test_02_admin_technical_sees_sanctions(self):
        self.assertIn("Sanctions", self.navbar)

    def test_03_admin_technical_sees_alerts(self):
        self.assertIn("Alertes", self.navbar)

    def test_04_admin_technical_sees_administration(self):
        self.assertIn("Administration", self.navbar)

    def test_05_admin_technical_sees_audit_quality(self):
        self.assertIn("Audit &amp; Qualité", self.navbar)

    def test_06_admin_technical_sees_notification_bell(self):
        self.assertIn('id="notifBell"', self.navbar)

    def test_07_admin_technical_has_technical_notifications_permission(self):
        self.assertTrue(has_permission(self.admin, PERMISSION_NOTIFICATIONS_VIEW))
        with open("app/routers/alerts.py", encoding="utf-8") as alerts_file:
            self.assertIn('AuditLog.action == "LIST_UPDATE_ALERT"', alerts_file.read())

    def test_08_admin_technical_cannot_treat_alerts(self):
        self.assertFalse(has_permission(self.admin, PERMISSION_ALERTS_TREAT))

    def test_09_admin_technical_cannot_confirm_alerts(self):
        self.assertFalse(has_permission(self.admin, PERMISSION_ALERTS_CONFIRM))

    def test_10_admin_technical_cannot_close_alerts(self):
        self.assertFalse(has_permission(self.admin, PERMISSION_ALERTS_CLOSE))

    def test_11_analyst_keeps_business_treatment_permission(self):
        analyst = {"role": ROLE_ANALYSTE_CONFORMITE, "permissions": permissions_for_role(ROLE_ANALYSTE_CONFORMITE)}
        self.assertTrue(has_permission(analyst, PERMISSION_ALERTS_TREAT))

    def test_12_supervisor_keeps_n2_permissions(self):
        supervisor = {"role": ROLE_SUPERVISEUR_CONFORMITE, "permissions": permissions_for_role(ROLE_SUPERVISEUR_CONFORMITE)}
        self.assertTrue(has_permission(supervisor, PERMISSION_ALERTS_CONFIRM))
        self.assertTrue(has_permission(supervisor, PERMISSION_ALERTS_CLOSE))

    def test_13_internal_role_code_is_not_rendered_as_badge_text(self):
        self.assertNotIn(">ADMIN_TECHNIQUE<", self.navbar)

    def test_14_human_role_label_is_rendered(self):
        self.assertIn("Administrateur technique", self.navbar)

    def test_15_admin_technical_sees_lists_and_lot_2a_scheduler_navigation(self):
        self.assertTrue(has_permission(self.admin, PERMISSION_LISTS_VIEW))
        self.assertIn("Listes de sanctions", self.navbar)
        self.assertIn("/web/scheduler-status", self.navbar)

    def test_16_admin_technical_temporarily_can_import_and_manage_lists(self):
        self.assertTrue(has_permission(self.admin, PERMISSION_LISTS_IMPORT))
        self.assertTrue(has_permission(self.admin, PERMISSION_LISTS_MANAGE))
        self.assertIn('href="/web/imports"', self.navbar)
        self.assertIn('href="/web/list-updates"', self.navbar)

    def test_17_list_manager_can_import_and_manage_lists(self):
        manager = {
            "role": ROLE_GESTIONNAIRE_LISTES,
            "permissions": permissions_for_role(ROLE_GESTIONNAIRE_LISTES),
        }
        navbar = _navbar_for(ROLE_GESTIONNAIRE_LISTES)
        self.assertTrue(has_permission(manager, PERMISSION_LISTS_IMPORT))
        self.assertTrue(has_permission(manager, PERMISSION_LISTS_MANAGE))
        self.assertIn('href="/web/imports"', navbar)
        self.assertIn('href="/web/list-updates"', navbar)

    def test_18_web_import_and_list_management_actions_are_available_for_technical_admin(self):
        request = _web_request(ROLE_ADMIN_TECHNIQUE)
        db = _AuditDb()
        import_allowed = web.require_admin_or_403(
            request, db, "/web/imports/ofac-sdn-xml", "test import allowed"
        )
        manage_allowed = web.require_admin_or_403(
            request, db, "/web/list-updates/ofac-sdn", "test management allowed"
        )
        self.assertIsNone(import_allowed)
        self.assertIsNone(manage_allowed)

    def test_19_api_import_and_management_guards_allow_technical_admin_temporarily(self):
        self.assertIs(api_require_permission(PERMISSION_LISTS_IMPORT)(self.admin), self.admin)
        self.assertIs(api_require_permission(PERMISSION_LISTS_MANAGE)(self.admin), self.admin)

    def test_20_list_manager_passes_import_and_management_backend_guards(self):
        manager = {
            "role": ROLE_GESTIONNAIRE_LISTES,
            "permissions": permissions_for_role(ROLE_GESTIONNAIRE_LISTES),
        }
        self.assertIs(api_require_permission(PERMISSION_LISTS_IMPORT)(manager), manager)
        self.assertIs(api_require_permission(PERMISSION_LISTS_MANAGE)(manager), manager)

    def test_21_technical_admin_passes_the_scheduler_read_guard(self):
        self.assertTrue(
            web.require_permission(
                _web_request(ROLE_ADMIN_TECHNIQUE),
                PERMISSION_LISTS_VIEW,
            )
        )


if __name__ == "__main__":
    unittest.main()
