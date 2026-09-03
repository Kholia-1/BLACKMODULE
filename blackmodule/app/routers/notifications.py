"""Authenticated API for the persistent user notification center."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.api_auth import require_permission
from app.services.authorization_service import PERMISSION_NOTIFICATIONS_VIEW
from app.services.notification_service import NotificationError, mark_notification_read, notification_center


router = APIRouter(prefix="/api/notifications", tags=["Notifications"])


def _serialize(notification):
    return {
        "id": str(notification.id),
        "type": notification.notification_type,
        "entity_type": notification.entity_type,
        "entity_id": str(notification.entity_id),
        "title": notification.title,
        "message": notification.message,
        "is_read": notification.is_read,
        "read_at": notification.read_at.isoformat() if notification.read_at else None,
        "created_at": notification.created_at.isoformat() if notification.created_at else None,
        "history": [
            {
                "event": item.event_type,
                "actor": item.actor_username,
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in getattr(notification, "history", [])
        ],
    }


@router.get("/")
def list_notifications(
    db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_NOTIFICATIONS_VIEW)),
):
    center = notification_center(db, recipient_user_id=user.get("id"))
    return {"unread_count": center["unread_count"], "items": [_serialize(row) for row in center["notifications"]]}


@router.post("/{notification_id}/read")
def read_notification(
    notification_id: UUID,
    db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_NOTIFICATIONS_VIEW)),
):
    try:
        row = mark_notification_read(
            db, notification_id=notification_id, recipient_user_id=user.get("id"),
            actor_username=user.get("username") or "SYSTEM",
        )
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail="Accès refusé à cette notification.") from exc
    except NotificationError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    db.commit()
    return _serialize(row)
