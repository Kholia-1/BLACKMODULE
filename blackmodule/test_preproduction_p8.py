"""Preproduction P8 tests for strict SMTP STARTTLS security."""

import ssl
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace

import test_lot_7b
from app.services import external_notification_service as external
from app.services.external_notification_service import (
    DeliveryConfigurationError,
    STATUS_FAILED,
    _secure_tls_context,
    _send_email,
    process_pending_email_deliveries,
)


class PreproductionP8SmtpSecurityTests(unittest.TestCase):
    def setUp(self):
        self.base = test_lot_7b.Lot7BExternalNotificationTests()
        self.base.setUp()
        self.db = self.base.db
        self.saved = {
            "port": external.EMAIL_SMTP_PORT,
            "starttls": external.EMAIL_SMTP_STARTTLS,
            "username": external.EMAIL_SMTP_USERNAME,
            "password": external.EMAIL_SMTP_PASSWORD,
            "smtp": external.smtplib.SMTP,
        }
        external.EMAIL_SMTP_PORT = 587
        external.EMAIL_SMTP_STARTTLS = True
        external.EMAIL_SMTP_USERNAME = None
        external.EMAIL_SMTP_PASSWORD = None

    def tearDown(self):
        external.EMAIL_SMTP_PORT = self.saved["port"]
        external.EMAIL_SMTP_STARTTLS = self.saved["starttls"]
        external.EMAIL_SMTP_USERNAME = self.saved["username"]
        external.EMAIL_SMTP_PASSWORD = self.saved["password"]
        external.smtplib.SMTP = self.saved["smtp"]
        self.base.tearDown()

    @staticmethod
    def delivery():
        return SimpleNamespace(
            recipient_email="recipient@example.test",
            subject="P8 local test",
            body="No real SMTP connection.",
        )

    def test_01_default_context_requires_certificate_and_hostname(self):
        context = _secure_tls_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_02_send_uses_secure_context_with_starttls_on_port_587(self):
        captured = {}

        class FakeSmtp:
            def __init__(self, host, port, timeout):
                captured.update(host=host, port=port, timeout=timeout)

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def starttls(self, *, context):
                captured["context"] = context

            def send_message(self, _message):
                captured["sent"] = True

        external.smtplib.SMTP = FakeSmtp
        _send_email(self.delivery())
        self.assertEqual(captured["port"], 587)
        self.assertEqual(captured["timeout"], 15)
        self.assertTrue(captured["context"].check_hostname)
        self.assertEqual(captured["context"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(captured["sent"])

    def test_03_incomplete_smtp_configuration_fails_before_connecting(self):
        external.EMAIL_SMTP_HOST = None
        with self.assertRaises(DeliveryConfigurationError) as raised:
            _send_email(self.delivery())
        self.assertEqual(raised.exception.code, "SMTP_NON_CONFIGURE")

    def test_04_unsecured_transport_configuration_is_rejected(self):
        for starttls, port in ((False, 587), (True, 25), (True, 465)):
            with self.subTest(starttls=starttls, port=port):
                external.EMAIL_SMTP_STARTTLS = starttls
                external.EMAIL_SMTP_PORT = port
                with self.assertRaises(DeliveryConfigurationError) as raised:
                    _send_email(self.delivery())
                self.assertEqual(
                    raised.exception.code, "SMTP_TLS_CONFIGURATION_INVALIDE"
                )

    def test_05_tls_failure_is_persisted_as_generic_error_only(self):
        self.base._dispatch()
        sensitive_detail = "private.smtp.test certificate payload"

        def fail_tls(_delivery):
            raise ssl.SSLCertVerificationError(sensitive_detail)

        external._send_email = fail_tls
        result = process_pending_email_deliveries(
            self.db, now=datetime.utcnow() + timedelta(minutes=1),
        )
        self.db.commit()
        self.assertEqual(result["failed"], 3)
        deliveries = self.db.query(external.ExternalNotificationDelivery).all()
        self.assertTrue(all(item.status == STATUS_FAILED for item in deliveries))
        self.assertTrue(all(item.last_error_code == "SMTP_TLS" for item in deliveries))
        attempts = self.db.query(external.ExternalNotificationAttempt).all()
        persisted = " ".join(
            str(value)
            for item in attempts
            for value in (item.status, item.error_code)
            if value is not None
        )
        self.assertNotIn(sensitive_detail, persisted)


if __name__ == "__main__":
    unittest.main()
