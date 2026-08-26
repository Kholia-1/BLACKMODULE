import unittest

from app.models import User
from app.services.auth_service import authenticate_user, hash_password
from app.services.authorization_service import (
    PERMISSION_TREAT_ALERTS,
    ROLE_ADMIN_TECHNIQUE,
    ROLE_ANALYSTE_CONFORMITE,
    ROLE_SUPERVISEUR_CONFORMITE,
    has_permission,
    session_user_payload,
)


class _Query:
    def __init__(self, user):
        self.user = user

    def filter(self, *_args):
        return self

    def first(self):
        return self.user


class _Database:
    def __init__(self, user):
        self.user = user

    def query(self, _model):
        return _Query(self.user)


class Lot1ASecurityTests(unittest.TestCase):
    def test_five_failed_logins_lock_the_account(self):
        user = User(
            username="test-user",
            password_hash=hash_password("correct-password"),
            statut="ACTIF",
            failed_login_attempts=0,
        )
        db = _Database(user)
        for _ in range(5):
            result = authenticate_user(db, "test-user", "bad-password")
        self.assertIsNone(result.user)
        self.assertTrue(result.locked_now)
        self.assertEqual(user.failed_login_attempts, 5)
        self.assertIsNotNone(user.locked_at)

    def test_successful_login_resets_failure_counter(self):
        user = User(
            username="test-user",
            password_hash=hash_password("correct-password"),
            statut="ACTIF",
            failed_login_attempts=2,
        )
        result = authenticate_user(_Database(user), "test-user", "correct-password")
        self.assertIs(result.user, user)
        self.assertEqual(user.failed_login_attempts, 0)
        self.assertIsNone(user.locked_at)
        self.assertIsNotNone(user.last_login_at)

    def test_technical_admin_cannot_treat_business_alerts(self):
        technical_admin = {"role": ROLE_ADMIN_TECHNIQUE}
        analyst = {"role": ROLE_ANALYSTE_CONFORMITE}
        supervisor = {"role": ROLE_SUPERVISEUR_CONFORMITE}
        self.assertFalse(has_permission(technical_admin, PERMISSION_TREAT_ALERTS))
        self.assertTrue(has_permission(analyst, PERMISSION_TREAT_ALERTS))
        self.assertTrue(has_permission(supervisor, PERMISSION_TREAT_ALERTS))
        supervisor_user = User(
            username="supervisor",
            password_hash=hash_password("correct-password"),
            role=ROLE_SUPERVISEUR_CONFORMITE,
        )
        self.assertIn(PERMISSION_TREAT_ALERTS, session_user_payload(supervisor_user).get("permissions", []))


if __name__ == "__main__":
    unittest.main()
