"""Corrective-action workflow attached to immutable quality reviews."""

from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import AlertQualityReview, CorrectiveAction, CorrectiveActionHistory, User
from app.services.authorization_service import ROLE_ANALYSTE_CONFORMITE, canonical_role


OPEN = "OUVERT"
IN_PROGRESS = "EN_COURS"
BLOCKED = "BLOQUE"
CLOSED = "CLOTURE"
ACTION_STATUSES = (OPEN, IN_PROGRESS, BLOCKED, CLOSED)
ACTION_PRIORITIES = ("BASSE", "MOYENNE", "HAUTE")
ACTION_STATUS_LABELS = {OPEN: "Ouvert", IN_PROGRESS: "En cours", BLOCKED: "Bloqué", CLOSED: "Clôturé"}
ACTION_PRIORITY_LABELS = {"BASSE": "Basse", "MOYENNE": "Moyenne", "HAUTE": "Haute"}
ELIGIBLE_REVIEW_STATUSES = ("A_REVOIR", "NON_CONFORME")


class CorrectiveActionError(ValueError):
    pass


def eligible_responsibles(db: Session) -> list[User]:
    return db.query(User).filter(
        User.statut == "ACTIF", User.role == ROLE_ANALYSTE_CONFORMITE,
    ).order_by(User.full_name.asc(), User.username.asc()).all()


def _responsible(db: Session, user_id) -> User:
    try:
        identifier = UUID(str(user_id))
    except (TypeError, ValueError) as exc:
        raise CorrectiveActionError("Responsable invalide.") from exc
    user = db.query(User).filter(User.id == identifier).first()
    if not user or user.statut != "ACTIF" or user.role != ROLE_ANALYSTE_CONFORMITE:
        raise CorrectiveActionError("Le responsable doit être un analyste conformité actif.")
    return user


def _history(db: Session, action: CorrectiveAction, actor: dict, *, old_status=None, old_responsible=None, comment=None):
    row = CorrectiveActionHistory(
        corrective_action_id=action.id,
        old_status=old_status,
        new_status=action.status,
        old_responsible=old_responsible,
        new_responsible=action.responsible_username,
        changed_by=actor.get("username") or "SYSTEM",
        comment=(comment or "").strip() or None,
    )
    db.add(row)
    return row


def create_corrective_action(db: Session, *, quality_review_id, responsible_user_id, due_date, priority, comment, actor: dict) -> CorrectiveAction:
    review = db.query(AlertQualityReview).filter(AlertQualityReview.id == quality_review_id).first()
    if not review or review.review_status not in ELIGIBLE_REVIEW_STATUSES:
        raise CorrectiveActionError("Une action corrective exige une revue À revoir ou Non conforme.")
    target = _responsible(db, responsible_user_id)
    if not isinstance(due_date, date):
        raise CorrectiveActionError("Échéance invalide.")
    selected_priority = (priority or "").strip().upper()
    if selected_priority not in ACTION_PRIORITIES:
        raise CorrectiveActionError("Priorité invalide.")
    cleaned_comment = (comment or "").strip() or None
    if cleaned_comment and len(cleaned_comment) > 2000:
        raise CorrectiveActionError("Le commentaire est limité à 2 000 caractères.")
    action = CorrectiveAction(
        quality_review_id=review.id,
        alert_id=review.alert_id,
        responsible_user_id=target.id,
        responsible_username=target.username,
        due_date=due_date,
        priority=selected_priority,
        status=OPEN,
        comment=cleaned_comment,
        created_by=actor.get("username") or "SYSTEM",
    )
    db.add(action)
    db.flush()
    _history(db, action, actor, comment=cleaned_comment)
    return action


def update_corrective_action(db: Session, *, action_id, status, comment, actor: dict, responsible_user_id=None) -> CorrectiveAction:
    action = db.query(CorrectiveAction).filter(CorrectiveAction.id == action_id).with_for_update().first()
    if not action:
        raise CorrectiveActionError("Action corrective introuvable.")
    selected_status = (status or "").strip().upper()
    if selected_status not in ACTION_STATUSES:
        raise CorrectiveActionError("Statut d'action corrective invalide.")
    role = canonical_role(actor.get("role"))
    is_manager = role != ROLE_ANALYSTE_CONFORMITE
    if not is_manager and str(action.responsible_user_id) != str(actor.get("id")):
        raise PermissionError("Un analyste ne peut modifier que ses actions correctives.")
    if action.status == CLOSED:
        raise CorrectiveActionError("Une action clôturée ne peut plus être modifiée.")
    old_status, old_responsible = action.status, action.responsible_username
    if responsible_user_id is not None:
        if not is_manager:
            raise PermissionError("Seul un responsable habilité peut réassigner l'action.")
        target = _responsible(db, responsible_user_id)
        action.responsible_user_id, action.responsible_username = target.id, target.username
    action.status = selected_status
    action.updated_at = datetime.utcnow()
    action.closed_at = datetime.utcnow() if selected_status == CLOSED else None
    cleaned_comment = (comment or "").strip() or None
    if cleaned_comment and len(cleaned_comment) > 2000:
        raise CorrectiveActionError("Le commentaire est limité à 2 000 caractères.")
    _history(db, action, actor, old_status=old_status, old_responsible=old_responsible, comment=cleaned_comment)
    return action


def corrective_action_dashboard(db: Session, *, now: datetime | None = None, responsible_user_id=None) -> dict:
    today = (now or datetime.utcnow()).date()
    query = db.query(CorrectiveAction)
    scoped = []
    if responsible_user_id:
        try:
            responsible_id = UUID(str(responsible_user_id))
        except (TypeError, ValueError):
            responsible_id = None
        scoped = [CorrectiveAction.responsible_user_id == responsible_id] if responsible_id else [False]
        query = query.filter(*scoped)
    rows = query.order_by(CorrectiveAction.due_date.asc(), CorrectiveAction.created_at.desc()).limit(200).all()
    kpis = {
        "open": db.query(func.count(CorrectiveAction.id)).filter(*scoped, CorrectiveAction.status != CLOSED).scalar() or 0,
        "overdue": db.query(func.count(CorrectiveAction.id)).filter(*scoped, CorrectiveAction.status != CLOSED, CorrectiveAction.due_date < today).scalar() or 0,
        "closed": db.query(func.count(CorrectiveAction.id)).filter(*scoped, CorrectiveAction.status == CLOSED).scalar() or 0,
    }
    action_ids = [row.id for row in rows]
    histories = {str(action_id): [] for action_id in action_ids}
    for row in db.query(CorrectiveActionHistory).filter(CorrectiveActionHistory.corrective_action_id.in_(action_ids)).order_by(CorrectiveActionHistory.created_at.desc()).all():
        histories[str(row.corrective_action_id)].append(row)
    for action in rows:
        action.is_overdue = action.status != CLOSED and action.due_date < today
        action.history = histories[str(action.id)]
    reviews = db.query(AlertQualityReview).filter(
        AlertQualityReview.review_status.in_(ELIGIBLE_REVIEW_STATUSES),
    ).order_by(AlertQualityReview.reviewed_at.desc()).limit(200).all()
    return {
        "actions": rows, "kpis": kpis, "responsibles": eligible_responsibles(db),
        "reviews": reviews, "today": today,
    }
