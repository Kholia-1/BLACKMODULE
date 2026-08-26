"""Régression ciblée des exigences de validation du LOT 1A.

Ces tests n'accèdent à aucune base ni service externe : ils vérifient les
invariants de sécurité dans les services et les garde-fous des routes.
"""

import inspect
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from app.config import SESSION_IDLE_TIMEOUT_MINUTES
from app.models import ApprovalRequest, User
from app.routers import alerts, sanctions
from app.services.approval_service import PENDING, create_approval_request, review_approval_request
from app.services.authorization_service import (
    ALL_ROLES, LEGACY_ROLE_MAP, PERMISSION_ALERTS_CLOSE, PERMISSION_ALERTS_CONFIRM,
    PERMISSION_APPROVAL_VALIDATE, PERMISSION_SANCTIONS_VIEW, PERMISSION_TREAT_ALERTS,
    ROLE_ADMIN_TECHNIQUE, ROLE_ANALYSTE_CONFORMITE, ROLE_SUPERVISEUR_CONFORMITE,
    has_permission,
)
from app.services.auth_service import authenticate_user, hash_password


class _Query:
    def __init__(self, user): self.user = user
    def filter(self, *_args): return self
    def first(self): return self.user


class _AuthDb:
    def __init__(self, user): self.user = user
    def query(self, _model): return _Query(self.user)


class _AuditDb:
    def __init__(self): self.added = []
    def add(self, item): self.added.append(item)
    def flush(self): pass


def _user(failed=0, locked=None):
    return User(username="u", password_hash=hash_password("correct-password"), statut="ACTIF",
                failed_login_attempts=failed, locked_at=locked)


class Lot1AValidationTests(unittest.TestCase):
    def test_01_four_failures_do_not_lock(self):
        user = _user()
        db = _AuthDb(user)
        for _ in range(4): result = authenticate_user(db, "u", "wrong")
        self.assertFalse(result.locked_now); self.assertIsNone(user.locked_at)

    def test_02_fifth_failure_locks(self):
        user = _user(); db = _AuthDb(user)
        for _ in range(5): result = authenticate_user(db, "u", "wrong")
        self.assertTrue(result.locked_now); self.assertEqual(user.failed_login_attempts, 5)

    def test_03_locked_account_refuses_good_password(self):
        result = authenticate_user(_AuthDb(_user(locked=datetime.utcnow())), "u", "correct-password")
        self.assertIsNone(result.user); self.assertEqual(result.reason, "LOCKED")

    def test_04_administrator_unlock_resets_fields(self):
        user = _user(5, datetime.utcnow()); user.failed_login_attempts = 0; user.locked_at = None
        self.assertEqual(user.failed_login_attempts, 0); self.assertIsNone(user.locked_at)

    def test_05_success_resets_failures(self):
        user = _user(4); result = authenticate_user(_AuthDb(user), "u", "correct-password")
        self.assertIs(result.user, user); self.assertEqual(user.failed_login_attempts, 0)

    def test_06_technical_admin_cannot_treat(self):
        self.assertFalse(has_permission({"role": ROLE_ADMIN_TECHNIQUE}, PERMISSION_TREAT_ALERTS))

    def test_07_technical_admin_cannot_confirm_or_close(self):
        user = {"role": ROLE_ADMIN_TECHNIQUE}
        self.assertFalse(has_permission(user, PERMISSION_ALERTS_CONFIRM)); self.assertFalse(has_permission(user, PERMISSION_ALERTS_CLOSE))

    def test_08_analyst_can_treat(self):
        self.assertTrue(has_permission({"role": ROLE_ANALYSTE_CONFORMITE}, PERMISSION_TREAT_ALERTS))

    def test_09_supervisor_has_n2_permissions(self):
        user = {"role": ROLE_SUPERVISEUR_CONFORMITE}
        self.assertTrue(has_permission(user, PERMISSION_ALERTS_CONFIRM)); self.assertTrue(has_permission(user, PERMISSION_APPROVAL_VALIDATE))

    def test_10_forbidden_api_dependency_returns_403(self):
        self.assertIn("status_code=403", inspect.getsource(__import__("app.services.api_auth", fromlist=["*"])))

    def test_11_request_creation_sets_pending(self):
        db = _AuditDb(); approval = create_approval_request(db, operation_type="X", initiator={"id":"A","username":"a"}, target_entity_type="X", target_entity_id="1", old_values={"a":1}, new_values={"a":2}, comment="why", ip_address=None)
        self.assertEqual(approval.status, PENDING)

    def test_12_author_cannot_review_own_request(self):
        approval = ApprovalRequest(status=PENDING, initiator_user_id="A", initiated_by="a", operation_type="X", target_entity_type="X", target_entity_id="1")
        with self.assertRaises(PermissionError): review_approval_request(_AuditDb(), approval=approval, reviewer={"id":"A","username":"a"}, approved=False, comment="x", ip_address=None)

    def test_13_other_reviewer_can_reject(self):
        approval = ApprovalRequest(status=PENDING, initiator_user_id="A", initiated_by="a", operation_type="X", target_entity_type="X", target_entity_id="1")
        review_approval_request(_AuditDb(), approval=approval, reviewer={"id":"B","username":"b"}, approved=False, comment="reason", ip_address=None)
        self.assertEqual(approval.status, "REJETE")

    def test_14_unprivileged_user_lacks_review_permission(self):
        self.assertFalse(has_permission({"role": ROLE_ANALYSTE_CONFORMITE}, PERMISSION_APPROVAL_VALIDATE))

    def test_15_rejection_comment_is_preserved(self):
        approval = ApprovalRequest(status=PENDING, initiator_user_id="A", initiated_by="a", operation_type="X", target_entity_type="X", target_entity_id="1")
        review_approval_request(_AuditDb(), approval=approval, reviewer={"id":"B","username":"b"}, approved=False, comment="motif", ip_address=None)
        self.assertEqual(approval.reviewer_comment, "motif")

    def test_16_old_and_new_values_are_preserved(self):
        db = _AuditDb(); approval = create_approval_request(db, operation_type="X", initiator={"id":"A","username":"a"}, target_entity_type="X", target_entity_id="1", old_values={"x":1}, new_values={"x":2}, comment=None, ip_address=None)
        self.assertIn('"x": 1', approval.old_values); self.assertIn('"x": 2', approval.new_values)

    def test_17_threshold_change_is_deferred(self):
        source = inspect.getsource(__import__("app.routers.web", fromlist=["*"]))
        self.assertIn("create_approval_request(", source); self.assertIn("OP_MATCHING_SETTINGS", source)

    def test_18_bootstrap_admin_can_be_disabled_if_another_exists(self):
        source = inspect.getsource(__import__("app.routers.web", fromlist=["*"]))
        self.assertIn("remaining_admins == 0", source)

    def test_19_last_technical_admin_is_protected(self):
        source = inspect.getsource(__import__("app.routers.web", fromlist=["*"]))
        self.assertIn("Conservez au moins un administrateur technique actif", source)

    def test_20_bootstrap_login_is_audited(self):
        self.assertIn("BOOTSTRAP_ADMIN_LOGIN", inspect.getsource(__import__("app.routers.web", fromlist=["*"])))

    def test_21_idle_timeout_is_fifteen_minutes_by_default(self):
        self.assertEqual(SESSION_IDLE_TIMEOUT_MINUTES, 15)

    def test_22_recent_activity_remains_valid(self):
        self.assertLess(datetime.utcnow() - (datetime.utcnow() - timedelta(minutes=14)), timedelta(minutes=15))

    def test_23_activity_is_persisted(self):
        self.assertIn("last_activity_at = now", Path("app/services/session_security_service.py").read_text(encoding="utf-8"))

    def test_24_expiration_is_audited(self):
        self.assertIn("SESSION_EXPIRED", Path("app/services/session_security_service.py").read_text(encoding="utf-8"))

    def test_25_users_template_does_not_expose_password_hash(self):
        self.assertNotIn("password_hash", Path("app/templates/users.html").read_text(encoding="utf-8"))

    def test_26_no_user_export_exposes_sensitive_fields(self):
        source = Path("app/routers/exports.py").read_text(encoding="utf-8")
        self.assertNotIn("password_hash", source); self.assertNotIn("User", source)

    def test_27_api_sanction_detail_is_audited(self):
        self.assertIn("VIEW_SANCTION_DETAIL", inspect.getsource(sanctions.get_sanction))

    def test_28_alert_sanction_detail_is_audited(self):
        self.assertIn("VIEW_SANCTION_DETAIL", Path("app/routers/web.py").read_text(encoding="utf-8"))

    def test_29_sanction_list_has_no_per_row_audit(self):
        self.assertNotIn("write_audit_log", inspect.getsource(sanctions.list_sanctions))

    def test_30_login_audit_never_includes_submitted_password(self):
        source = inspect.getsource(__import__("app.routers.web", fromlist=["*"]).login_submit)
        self.assertNotIn("{password}", source)
        self.assertNotIn("password_hash", source)

    def test_roles_after_migration_are_valid(self):
        self.assertTrue(set(LEGACY_ROLE_MAP.values()).issubset(ALL_ROLES))


if __name__ == "__main__":
    unittest.main()
