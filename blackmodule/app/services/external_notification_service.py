"""Durable optional e-mail outbox built from LOT 7A in-app notifications."""

from __future__ import annotations

import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import (
    EMAIL_NOTIFICATIONS_ENABLED,
    EMAIL_NOTIFICATION_MAX_ATTEMPTS,
    EMAIL_NOTIFICATION_RETRY_MINUTES,
    EMAIL_SMTP_FROM,
    EMAIL_SMTP_HOST,
    EMAIL_SMTP_PASSWORD,
    EMAIL_SMTP_PORT,
    EMAIL_SMTP_STARTTLS,
    EMAIL_SMTP_USERNAME,
)
from app.models import (
    ExternalNotificationAttempt,
    ExternalNotificationDelivery,
    NotificationTemplate,
    User,
    UserNotification,
)


CHANNEL_EMAIL = "EMAIL"
STATUS_PENDING = "EN_ATTENTE"
STATUS_SENT = "ENVOYE"
STATUS_FAILED = "ECHEC"
ATTEMPT_QUEUED = "EN_ATTENTE"

DEFAULT_EMAIL_TEMPLATE = {
    "subject": "BLACKMODULE — {title}",
    "body": "{message}",
}


class ExternalNotificationError(ValueError):
    pass


class DeliveryConfigurationError(ExternalNotificationError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _template_key(notification: UserNotification) -> str:
    return notification.notification_type


def _get_or_create_template(db: Session, template_key: str) -> NotificationTemplate:
    template = db.query(NotificationTemplate).filter(
        NotificationTemplate.template_key == template_key,
        NotificationTemplate.channel == CHANNEL_EMAIL,
    ).first()
    if template:
        return template
    template = NotificationTemplate(
        template_key=template_key,
        channel=CHANNEL_EMAIL,
        subject_template=DEFAULT_EMAIL_TEMPLATE["subject"],
        body_template=DEFAULT_EMAIL_TEMPLATE["body"],
    )
    db.add(template)
    db.flush()
    return template


def _render(template: NotificationTemplate, notification: UserNotification) -> tuple[str, str]:
    context = {"title": notification.title, "message": notification.message}
    try:
        return template.subject_template.format(**context), template.body_template.format(**context)
    except (KeyError, ValueError) as exc:
        raise ExternalNotificationError("MODELE_EMAIL_INVALIDE") from exc


def _attempt(db: Session, delivery: ExternalNotificationDelivery, *, status: str, error_code: str | None = None) -> None:
    db.add(ExternalNotificationAttempt(
        delivery_id=delivery.id,
        attempt_number=delivery.attempt_count,
        status=status,
        error_code=error_code,
    ))


def queue_email_notification(db: Session, notification: UserNotification) -> ExternalNotificationDelivery | None:
    """Queue one optional external delivery; disabled e-mail never blocks LOT 7A."""
    if not EMAIL_NOTIFICATIONS_ENABLED:
        return None
    existing = db.query(ExternalNotificationDelivery.id).filter(
        ExternalNotificationDelivery.user_notification_id == notification.id,
        ExternalNotificationDelivery.channel == CHANNEL_EMAIL,
    ).first()
    if existing:
        return None
    recipient = db.query(User).filter(User.id == notification.recipient_user_id).first()
    template = _get_or_create_template(db, _template_key(notification))
    if not template.is_active:
        return None
    subject, body = _render(template, notification)
    delivery = ExternalNotificationDelivery(
        user_notification_id=notification.id,
        channel=CHANNEL_EMAIL,
        recipient_username=recipient.username if recipient else "INCONNU",
        recipient_email=recipient.email if recipient else None,
        template_key=template.template_key,
        subject=subject,
        body=body,
        status=STATUS_PENDING if recipient and recipient.email else STATUS_FAILED,
        max_attempts=EMAIL_NOTIFICATION_MAX_ATTEMPTS,
        next_attempt_at=datetime.utcnow() if recipient and recipient.email else None,
        last_error_code=None if recipient and recipient.email else "DESTINATAIRE_EMAIL_ABSENT",
    )
    try:
        with db.begin_nested():
            db.add(delivery)
            db.flush()
    except IntegrityError:
        return None
    _attempt(
        db, delivery,
        status=ATTEMPT_QUEUED if delivery.status == STATUS_PENDING else STATUS_FAILED,
        error_code=delivery.last_error_code,
    )
    return delivery


def _send_email(delivery: ExternalNotificationDelivery) -> None:
    if not delivery.recipient_email:
        raise DeliveryConfigurationError("DESTINATAIRE_EMAIL_ABSENT")
    if not EMAIL_SMTP_HOST or not EMAIL_SMTP_FROM:
        raise DeliveryConfigurationError("SMTP_NON_CONFIGURE")
    if EMAIL_SMTP_USERNAME and not EMAIL_SMTP_PASSWORD:
        raise DeliveryConfigurationError("SMTP_AUTH_NON_CONFIGUREE")
    message = EmailMessage()
    message["From"] = EMAIL_SMTP_FROM
    message["To"] = delivery.recipient_email
    message["Subject"] = delivery.subject
    message.set_content(delivery.body)
    with smtplib.SMTP(EMAIL_SMTP_HOST, EMAIL_SMTP_PORT, timeout=15) as smtp:
        if EMAIL_SMTP_STARTTLS:
            smtp.starttls()
        if EMAIL_SMTP_USERNAME:
            smtp.login(EMAIL_SMTP_USERNAME, EMAIL_SMTP_PASSWORD)
        smtp.send_message(message)


def _error_code(error: Exception) -> str:
    if isinstance(error, DeliveryConfigurationError):
        return error.code
    if isinstance(error, smtplib.SMTPAuthenticationError):
        return "SMTP_AUTHENTIFICATION"
    if isinstance(error, smtplib.SMTPException):
        return "SMTP_ERREUR"
    return "SMTP_TRANSPORT"


def process_pending_email_deliveries(db: Session, *, now: datetime | None = None, limit: int = 100) -> dict[str, int | bool]:
    """Send due entries with bounded retries; disabled mode leaves the outbox intact."""
    if not EMAIL_NOTIFICATIONS_ENABLED:
        return {"enabled": False, "sent": 0, "failed": 0, "processed": 0}
    current_time = now or datetime.utcnow()
    deliveries = db.query(ExternalNotificationDelivery).filter(
        ExternalNotificationDelivery.channel == CHANNEL_EMAIL,
        ExternalNotificationDelivery.status.in_((STATUS_PENDING, STATUS_FAILED)),
        ExternalNotificationDelivery.attempt_count < ExternalNotificationDelivery.max_attempts,
        or_(
            ExternalNotificationDelivery.next_attempt_at.is_(None),
            ExternalNotificationDelivery.next_attempt_at <= current_time,
        ),
    ).order_by(ExternalNotificationDelivery.created_at.asc()).limit(max(1, min(limit, 500))).with_for_update().all()
    result = {"enabled": True, "sent": 0, "failed": 0, "processed": 0}
    for delivery in deliveries:
        delivery.attempt_count += 1
        delivery.updated_at = current_time
        result["processed"] += 1
        try:
            _send_email(delivery)
        except Exception as error:
            code = _error_code(error)
            delivery.status = STATUS_FAILED
            delivery.last_error_code = code
            delivery.next_attempt_at = (
                current_time + timedelta(minutes=EMAIL_NOTIFICATION_RETRY_MINUTES)
                if delivery.attempt_count < delivery.max_attempts else None
            )
            _attempt(db, delivery, status=STATUS_FAILED, error_code=code)
            result["failed"] += 1
        else:
            delivery.status = STATUS_SENT
            delivery.sent_at = current_time
            delivery.next_attempt_at = None
            delivery.last_error_code = None
            _attempt(db, delivery, status=STATUS_SENT)
            result["sent"] += 1
    return result


def external_delivery_dashboard(db: Session, *, limit: int = 200) -> dict:
    rows = db.query(ExternalNotificationDelivery).filter(
        ExternalNotificationDelivery.channel == CHANNEL_EMAIL,
    ).order_by(ExternalNotificationDelivery.created_at.desc()).limit(max(1, min(limit, 500))).all()
    delivery_ids = [row.id for row in rows]
    histories = {str(delivery_id): [] for delivery_id in delivery_ids}
    if delivery_ids:
        for item in db.query(ExternalNotificationAttempt).filter(
            ExternalNotificationAttempt.delivery_id.in_(delivery_ids),
        ).order_by(ExternalNotificationAttempt.created_at.desc()).all():
            histories[str(item.delivery_id)].append(item)
    for row in rows:
        row.history = histories[str(row.id)]
    return {
        "deliveries": rows,
        "kpis": {
            "pending": db.query(ExternalNotificationDelivery).filter_by(channel=CHANNEL_EMAIL, status=STATUS_PENDING).count(),
            "sent": db.query(ExternalNotificationDelivery).filter_by(channel=CHANNEL_EMAIL, status=STATUS_SENT).count(),
            "failed": db.query(ExternalNotificationDelivery).filter_by(channel=CHANNEL_EMAIL, status=STATUS_FAILED).count(),
        },
        "enabled": EMAIL_NOTIFICATIONS_ENABLED,
    }
