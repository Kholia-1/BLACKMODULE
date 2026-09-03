"""LOT 7B regression tests for external e-mail notification delivery."""

import unittest
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

import test_lot_6a
import test_lot_7a
from app.models import ExternalNotificationAttempt, ExternalNotificationDelivery, NotificationTemplate, UserNotification
from app.services import external_notification_service as external
from app.services.external_notification_service import (
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_SENT,
    external_delivery_dashboard,
    process_pending_email_deliveries,
)
from app.services.notification_service import dispatch_corrective_action_notifications


class Lot7BExternalNotificationTests(unittest.TestCase):
    def setUp(self):
        self.base = test_lot_7a.Lot7ANotificationTests()
        self.base.setUp()
        self.db = self.base.db
        self.original = {
            "enabled": external.EMAIL_NOTIFICATIONS_ENABLED,
            "host": external.EMAIL_SMTP_HOST,
            "sender": external.EMAIL_SMTP_FROM,
            "max_attempts": external.EMAIL_NOTIFICATION_MAX_ATTEMPTS,
            "retry_minutes": external.EMAIL_NOTIFICATION_RETRY_MINUTES,
            "send": external._send_email,
        }
        external.EMAIL_NOTIFICATIONS_ENABLED = True
        external.EMAIL_SMTP_HOST = "smtp.test.local"
        external.EMAIL_SMTP_FROM = "blackmodule@example.test"
        external.EMAIL_NOTIFICATION_MAX_ATTEMPTS = 3
        external.EMAIL_NOTIFICATION_RETRY_MINUTES = 1

    def tearDown(self):
        external.EMAIL_NOTIFICATIONS_ENABLED = self.original["enabled"]
        external.EMAIL_SMTP_HOST = self.original["host"]
        external.EMAIL_SMTP_FROM = self.original["sender"]
        external.EMAIL_NOTIFICATION_MAX_ATTEMPTS = self.original["max_attempts"]
        external.EMAIL_NOTIFICATION_RETRY_MINUTES = self.original["retry_minutes"]
        external._send_email = self.original["send"]
        self.base.tearDown()

    def _dispatch(self):
        result = dispatch_corrective_action_notifications(self.db, now=self.base.now)
        self.db.commit()
        return result

    def test_01_enabled_channel_queues_templates_and_deduplicates(self):
        self.assertEqual(self._dispatch(), {"due_soon": 1, "overdue": 1, "escalated": 1})
        deliveries = self.db.query(ExternalNotificationDelivery).all()
        self.assertEqual(len(deliveries), 3)
        self.assertTrue(all(item.status == STATUS_PENDING for item in deliveries))
        self.assertEqual(self.db.query(NotificationTemplate).count(), 3)
        self.assertEqual(self.db.query(ExternalNotificationAttempt).count(), 3)
        self.assertEqual(self._dispatch(), {"due_soon": 0, "overdue": 0, "escalated": 0})
        self.assertEqual(self.db.query(ExternalNotificationDelivery).count(), 3)

    def test_02_successful_send_marks_delivery_and_attempt_history(self):
        self._dispatch()
        sent_to = []
        external._send_email = lambda delivery: sent_to.append(delivery.recipient_username)
        result = process_pending_email_deliveries(self.db, now=datetime.utcnow() + timedelta(minutes=1))
        self.db.commit()
        self.assertEqual(result, {"enabled": True, "sent": 3, "failed": 0, "processed": 3})
        self.assertEqual(len(sent_to), 3)
        self.assertTrue(all(item.status == STATUS_SENT and item.attempt_count == 1 for item in self.db.query(ExternalNotificationDelivery).all()))
        self.assertEqual(self.db.query(ExternalNotificationAttempt).filter_by(status=STATUS_SENT).count(), 3)

    def test_03_failed_delivery_retries_at_controlled_time_then_stops(self):
        self._dispatch()
        external.EMAIL_NOTIFICATION_MAX_ATTEMPTS = 2
        for delivery in self.db.query(ExternalNotificationDelivery).all():
            delivery.max_attempts = 2
        self.db.commit()
        external._send_email = lambda _delivery: (_ for _ in ()).throw(RuntimeError("transport unavailable"))
        first_time = datetime.utcnow() + timedelta(minutes=1)
        self.assertEqual(process_pending_email_deliveries(self.db, now=first_time)["failed"], 3)
        self.db.commit()
        self.assertTrue(all(item.status == STATUS_FAILED and item.attempt_count == 1 for item in self.db.query(ExternalNotificationDelivery).all()))
        self.assertEqual(process_pending_email_deliveries(self.db, now=first_time)["processed"], 0)
        self.assertEqual(process_pending_email_deliveries(self.db, now=first_time + timedelta(minutes=2))["failed"], 3)
        self.db.commit()
        self.assertTrue(all(item.attempt_count == 2 and item.next_attempt_at is None for item in self.db.query(ExternalNotificationDelivery).all()))

    def test_04_disabled_channel_preserves_in_app_notifications_without_outbox(self):
        external.EMAIL_NOTIFICATIONS_ENABLED = False
        self.assertEqual(self._dispatch(), {"due_soon": 1, "overdue": 1, "escalated": 1})
        self.assertEqual(self.db.query(UserNotification).count(), 3)
        self.assertEqual(self.db.query(ExternalNotificationDelivery).count(), 0)
        self.assertEqual(process_pending_email_deliveries(self.db), {"enabled": False, "sent": 0, "failed": 0, "processed": 0})

    def test_05_attempt_history_is_immutable_and_supervision_rbac_is_enforced(self):
        self._dispatch()
        attempt = self.db.query(ExternalNotificationAttempt).first()
        attempt.status = STATUS_SENT
        with self.assertRaises(ValueError):
            self.db.flush()
        self.db.rollback()
        app = test_lot_6a._test_app(self.db)
        expected = {
            "ADMIN_TECHNIQUE": 200,
            "SUPERVISEUR_CONFORMITE": 200,
            "AUDITEUR": 200,
            "ANALYSTE_CONFORMITE": 403,
            "CONSULTATION": 403,
        }
        with TestClient(app) as client:
            for role, status in expected.items():
                client.get(f"/_test/login/{role}")
                self.assertEqual(client.get("/web/notification-deliveries").status_code, status)
        report = external_delivery_dashboard(self.db)
        self.assertEqual(report["kpis"], {"pending": 3, "sent": 0, "failed": 0})
        self.assertFalse("@" in str(report["deliveries"][0].recipient_username))


if __name__ == "__main__":
    unittest.main()
