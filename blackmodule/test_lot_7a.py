"""LOT 7A regression tests for corrective-action notifications."""

import unittest
from datetime import timedelta

from fastapi.testclient import TestClient

import test_lot_6a
from app.models import CorrectiveActionHistory, UserNotification, UserNotificationHistory
from app.routers import notifications
from app.services.corrective_action_service import create_corrective_action
from app.services.notification_service import (
    NOTIFICATION_DUE_SOON,
    NOTIFICATION_ESCALATED,
    NOTIFICATION_OVERDUE,
    NotificationError,
    dispatch_corrective_action_notifications,
    mark_notification_read,
    notification_center,
)
from app.services.quality_review_service import REVIEW_NON_COMPLIANT, REVIEW_PENDING, create_quality_review


class Lot7ANotificationTests(unittest.TestCase):
    def setUp(self):
        self.base = test_lot_6a.Lot6AQualityReviewTests()
        self.base.setUp()
        self.db = self.base.db
        self.now = self.base.now
        near_review = create_quality_review(
            self.db, decision_id=self.base.fp.id, review_status=REVIEW_PENDING,
            quality_comment=None, actor=self.base.actor(self.base.auditor),
        )
        overdue_review = create_quality_review(
            self.db, decision_id=self.base.confirmed.id, review_status=REVIEW_NON_COMPLIANT,
            quality_comment="Écart qualité à corriger.", actor=self.base.actor(self.base.auditor),
        )
        self.near_action = create_corrective_action(
            self.db, quality_review_id=near_review.id, responsible_user_id=self.base.analyst1.id,
            due_date=self.now.date(), priority="MOYENNE", comment="Rappel attendu.",
            actor=self.base.actor(self.base.admin),
        )
        self.overdue_action = create_corrective_action(
            self.db, quality_review_id=overdue_review.id, responsible_user_id=self.base.analyst1.id,
            due_date=(self.now - timedelta(days=1)).date(), priority="HAUTE", comment="Escalade attendue.",
            actor=self.base.actor(self.base.supervisor),
        )
        self.db.commit()

    def tearDown(self):
        self.base.tearDown()

    def _dispatch(self):
        result = dispatch_corrective_action_notifications(self.db, now=self.now)
        self.db.commit()
        return result

    def test_01_due_soon_overdue_escalation_and_deduplication(self):
        self.assertEqual(self._dispatch(), {"due_soon": 1, "overdue": 1, "escalated": 1})
        rows = self.db.query(UserNotification).order_by(UserNotification.notification_type).all()
        self.assertEqual(
            [row.notification_type for row in rows],
            sorted([NOTIFICATION_DUE_SOON, NOTIFICATION_OVERDUE, NOTIFICATION_ESCALATED]),
        )
        self.assertTrue(self.overdue_action.supervisor_escalated_at)
        escalation = self.db.query(CorrectiveActionHistory).filter(
            CorrectiveActionHistory.corrective_action_id == self.overdue_action.id,
            CorrectiveActionHistory.changed_by == "SCHEDULER",
        ).one()
        self.assertEqual(escalation.old_status, escalation.new_status)
        self.assertEqual(self._dispatch(), {"due_soon": 0, "overdue": 0, "escalated": 0})
        self.assertEqual(self.db.query(UserNotification).count(), 3)

    def test_02_center_read_state_history_and_recipient_isolation(self):
        self._dispatch()
        center = notification_center(self.db, recipient_user_id=self.base.analyst1.id)
        self.assertEqual(center["unread_count"], 2)
        notification = center["notifications"][0]
        marked = mark_notification_read(
            self.db, notification_id=notification.id, recipient_user_id=self.base.analyst1.id,
            actor_username=self.base.analyst1.username,
        )
        self.db.commit()
        self.assertTrue(marked.is_read)
        self.assertIsNotNone(marked.read_at)
        history = self.db.query(UserNotificationHistory).filter_by(notification_id=notification.id).all()
        self.assertEqual({event.event_type for event in history}, {"CREE", "LUE"})
        self.assertEqual(notification_center(self.db, recipient_user_id=self.base.analyst1.id)["unread_count"], 1)
        with self.assertRaises(PermissionError):
            mark_notification_read(
                self.db, notification_id=notification.id, recipient_user_id=self.base.analyst2.id,
                actor_username=self.base.analyst2.username,
            )

    def test_03_notification_history_is_append_only(self):
        self._dispatch()
        event = self.db.query(UserNotificationHistory).first()
        event.event_type = "MODIFIEE"
        with self.assertRaises(ValueError):
            self.db.flush()
        self.db.rollback()
        event = self.db.query(UserNotificationHistory).first()
        self.db.delete(event)
        with self.assertRaises(ValueError):
            self.db.flush()
        self.db.rollback()

    def test_04_web_and_api_rbac_and_notification_ownership(self):
        self._dispatch()
        app = test_lot_6a._test_app(self.db)
        app.include_router(notifications.router)
        expected = {
            "ADMIN_TECHNIQUE": 200,
            "SUPERVISEUR_CONFORMITE": 200,
            "ANALYSTE_CONFORMITE": 200,
            "AUDITEUR": 403,
            "CONSULTATION": 403,
        }
        with TestClient(app) as client:
            for role, expected_status in expected.items():
                client.get(f"/_test/login/{role}")
                self.assertEqual(client.get("/web/notifications").status_code, expected_status)
                self.assertEqual(client.get("/api/notifications/").status_code, expected_status)
            notification = self.db.query(UserNotification).filter(
                UserNotification.recipient_user_id == self.base.analyst1.id,
            ).first()
            client.get("/_test/login/SUPERVISEUR_CONFORMITE")
            self.assertEqual(client.post(f"/api/notifications/{notification.id}/read").status_code, 403)
            client.get("/_test/login/ANALYSTE_CONFORMITE")
            response = client.post(f"/api/notifications/{notification.id}/read")
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json()["is_read"])

    def test_05_invalid_notification_identifier_is_rejected(self):
        with self.assertRaises(NotificationError):
            notification_center(self.db, recipient_user_id="not-a-uuid")


if __name__ == "__main__":
    unittest.main()
