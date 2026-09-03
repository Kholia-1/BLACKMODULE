"""Persistent notifications for corrective-action deadlines and escalation."""

from __future__ import annotations

from datetime import datetime, timedelta
from math import ceil
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import CORRECTIVE_ACTION_DUE_SOON_HOURS
from app.models import CorrectiveAction, CorrectiveActionHistory, User, UserNotification, UserNotificationHistory
from app.services.authorization_service import ROLE_SUPERVISEUR_CONFORMITE
from app.services.corrective_action_service import CLOSED


NOTIFICATION_DUE_SOON = "CORRECTIVE_ACTION_DUE_SOON"
NOTIFICATION_OVERDUE = "CORRECTIVE_ACTION_OVERDUE"
NOTIFICATION_ESCALATED = "CORRECTIVE_ACTION_ESCALATED"
NOTIFICATION_EVENT_CREATED = "CREE"
NOTIFICATION_EVENT_READ = "LUE"


class NotificationError(ValueError):
    pass


def _uuid(value) -> UUID:
    try:
        return UUID(str(value))
    except (TypeError, ValueError) as exc:
        raise NotificationError("Notification invalide.") from exc


def _history(db: Session, notification: UserNotification, event_type: str, actor_username: str) -> None:
    db.add(UserNotificationHistory(
        notification_id=notification.id,
        event_type=event_type,
        actor_username=actor_username or "SYSTEM",
    ))


def _create_notification(
    db: Session,
    *,
    recipient: User,
    notification_type: str,
    action: CorrectiveAction,
    title: str,
    message: str,
    deduplication_key: str,
) -> UserNotification | None:
    """Insert once per recipient/event; the unique key also covers scheduler races."""
    existing = db.query(UserNotification.id).filter(
        UserNotification.deduplication_key == deduplication_key,
    ).first()
    if existing:
        return None

    notification = UserNotification(
        recipient_user_id=recipient.id,
        notification_type=notification_type,
        entity_type="CorrectiveAction",
        entity_id=action.id,
        title=title,
        message=message,
        deduplication_key=deduplication_key,
    )
    try:
        with db.begin_nested():
            db.add(notification)
            db.flush()
    except IntegrityError:
        # Another scheduler instance has already delivered this event.
        return None
    _history(db, notification, NOTIFICATION_EVENT_CREATED, "SYSTEM")
    # LOT 7B is deliberately optional: a disabled or misconfigured external
    # channel must never prevent the durable in-app notification from existing.
    try:
        from app.services.external_notification_service import queue_email_notification
        queue_email_notification(db, notification)
    except Exception:
        # Delivery supervision records safe failures where possible; do not
        # leak SMTP details or make the parent notification workflow fail.
        pass
    return notification


def _active_responsible(db: Session, action: CorrectiveAction) -> User | None:
    return db.query(User).filter(
        User.id == action.responsible_user_id,
        User.statut == "ACTIF",
    ).first()


def _active_supervisors(db: Session) -> list[User]:
    return db.query(User).filter(
        User.role == ROLE_SUPERVISEUR_CONFORMITE,
        User.statut == "ACTIF",
    ).order_by(User.username.asc()).all()


def _record_automatic_escalation(db: Session, action: CorrectiveAction, now: datetime) -> None:
    if action.supervisor_escalated_at:
        return
    action.supervisor_escalated_at = now
    action.updated_at = now
    db.add(CorrectiveActionHistory(
        corrective_action_id=action.id,
        old_status=action.status,
        new_status=action.status,
        old_responsible=action.responsible_username,
        new_responsible=action.responsible_username,
        changed_by="SCHEDULER",
        comment="Escalade automatique vers le superviseur : échéance dépassée.",
    ))


def dispatch_corrective_action_notifications(db: Session, *, now: datetime | None = None) -> dict[str, int]:
    """Notify responsible users, then supervisors when a corrective action is overdue.

    Due dates are stored without a time. A reminder therefore covers today and
    the configurable number of following calendar days; an action is overdue
    only from the day after its deadline.
    """
    current_time = now or datetime.utcnow()
    today = current_time.date()
    due_soon_end = today + timedelta(days=ceil(CORRECTIVE_ACTION_DUE_SOON_HOURS / 24))
    near_actions = db.query(CorrectiveAction).filter(
        CorrectiveAction.status != CLOSED,
        CorrectiveAction.due_date >= today,
        CorrectiveAction.due_date <= due_soon_end,
    ).order_by(CorrectiveAction.due_date.asc()).all()
    overdue_actions = db.query(CorrectiveAction).filter(
        CorrectiveAction.status != CLOSED,
        CorrectiveAction.due_date < today,
    ).order_by(CorrectiveAction.due_date.asc()).all()

    result = {"due_soon": 0, "overdue": 0, "escalated": 0}
    for action in near_actions:
        recipient = _active_responsible(db, action)
        if not recipient:
            continue
        notification = _create_notification(
            db,
            recipient=recipient,
            notification_type=NOTIFICATION_DUE_SOON,
            action=action,
            title="Action corrective proche de l'échéance",
            message=f"Votre action corrective arrive à échéance le {action.due_date.strftime('%d/%m/%Y')}.",
            deduplication_key=f"corrective-action:{action.id}:due-soon:{action.due_date.isoformat()}:{recipient.id}",
        )
        result["due_soon"] += int(notification is not None)

    supervisors = _active_supervisors(db)
    for action in overdue_actions:
        recipient = _active_responsible(db, action)
        if recipient:
            notification = _create_notification(
                db,
                recipient=recipient,
                notification_type=NOTIFICATION_OVERDUE,
                action=action,
                title="Action corrective en retard",
                message=f"Votre action corrective est en retard depuis le {action.due_date.strftime('%d/%m/%Y')}.",
                deduplication_key=f"corrective-action:{action.id}:overdue:{action.due_date.isoformat()}:{recipient.id}",
            )
            result["overdue"] += int(notification is not None)
        if supervisors:
            _record_automatic_escalation(db, action, current_time)
        for supervisor in supervisors:
            notification = _create_notification(
                db,
                recipient=supervisor,
                notification_type=NOTIFICATION_ESCALATED,
                action=action,
                title="Escalade d'une action corrective en retard",
                message=f"Une action corrective en retard depuis le {action.due_date.strftime('%d/%m/%Y')} requiert votre supervision.",
                deduplication_key=f"corrective-action:{action.id}:escalated:{action.due_date.isoformat()}:{supervisor.id}",
            )
            result["escalated"] += int(notification is not None)
    return result


def notification_center(db: Session, *, recipient_user_id, limit: int = 100) -> dict:
    recipient_id = _uuid(recipient_user_id)
    rows = db.query(UserNotification).filter(
        UserNotification.recipient_user_id == recipient_id,
    ).order_by(UserNotification.created_at.desc()).limit(max(1, min(limit, 200))).all()
    notification_ids = [row.id for row in rows]
    histories = {str(notification_id): [] for notification_id in notification_ids}
    if notification_ids:
        for event in db.query(UserNotificationHistory).filter(
            UserNotificationHistory.notification_id.in_(notification_ids),
        ).order_by(UserNotificationHistory.created_at.desc()).all():
            histories[str(event.notification_id)].append(event)
    for row in rows:
        row.history = histories[str(row.id)]
    unread = db.query(UserNotification).filter(
        UserNotification.recipient_user_id == recipient_id,
        UserNotification.is_read.is_(False),
    ).count()
    return {"notifications": rows, "unread_count": unread}


def mark_notification_read(db: Session, *, notification_id, recipient_user_id, actor_username: str) -> UserNotification:
    row = db.query(UserNotification).filter(
        UserNotification.id == _uuid(notification_id),
    ).with_for_update().first()
    if not row:
        raise NotificationError("Notification introuvable.")
    if row.recipient_user_id != _uuid(recipient_user_id):
        raise PermissionError("Cette notification appartient à un autre utilisateur.")
    if not row.is_read:
        row.is_read = True
        row.read_at = datetime.utcnow()
        _history(db, row, NOTIFICATION_EVENT_READ, actor_username)
    return row
