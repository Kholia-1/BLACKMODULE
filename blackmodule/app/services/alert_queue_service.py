"""Operational alert queue: assignment, SLA and supervisor escalation."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from sqlalchemy import case
from sqlalchemy.orm import Query, Session

from app.config import ALERT_SLA_HOURS, ALERT_SLA_NEAR_RATIO
from app.models import Alert, AlertAssignmentHistory, User
from app.services.audit_service import write_audit_log
from app.services.authorization_service import (
    ROLE_ANALYSTE_CONFORMITE,
    ROLE_SUPERVISEUR_CONFORMITE,
    canonical_role,
)


ASSIGNMENT = "ASSIGNATION"
REASSIGNMENT = "REASSIGNATION"
SUPERVISOR_ESCALATION = "ESCALADE_SUPERVISEUR"

SLA_OK = "DANS_SLA"
SLA_NEAR = "PROCHE_SLA"
SLA_BREACHED = "HORS_SLA"
SLA_COMPLETED = "TRAITEE"

TERMINAL_ALERT_STATUSES = {"FAUX_POSITIF", "CLOTUREE"}
ASSIGNABLE_ROLES = {ROLE_ANALYSTE_CONFORMITE, ROLE_SUPERVISEUR_CONFORMITE}


class AlertAssignmentConflict(ValueError):
    """Raised when an alert assignment changed concurrently or is duplicated."""


def _as_uuid(value) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value)) if value else None
    except (TypeError, ValueError, AttributeError):
        return None


def _naive_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=None) if value.tzinfo else value


def calculate_alert_sla(alert: Alert, *, now: datetime | None = None) -> dict:
    """Return a stable, explainable SLA snapshot for one alert."""
    current_time = _naive_utc(now or datetime.utcnow())
    created_at = _naive_utc(alert.created_at or current_time)
    elapsed = max(timedelta(0), current_time - created_at)
    sla_hours = ALERT_SLA_HOURS.get(
        (alert.niveau_alerte or "").upper(),
        ALERT_SLA_HOURS["ALERTE_POSSIBLE"],
    )
    deadline = created_at + timedelta(hours=sla_hours)
    age_hours = elapsed.total_seconds() / 3600

    if (alert.statut or "").upper() in TERMINAL_ALERT_STATUSES:
        status = SLA_COMPLETED
    elif current_time >= deadline:
        status = SLA_BREACHED
    elif age_hours >= sla_hours * ALERT_SLA_NEAR_RATIO:
        status = SLA_NEAR
    else:
        status = SLA_OK

    days, remainder = divmod(int(elapsed.total_seconds()), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    age_label = f"{days} j {hours} h" if days else f"{hours} h {minutes} min"
    return {
        "age_hours": round(age_hours, 2),
        "age_label": age_label,
        "sla_hours": sla_hours,
        "sla_deadline": deadline,
        "sla_status": status,
    }


def annotate_alerts(alerts: list[Alert], *, now: datetime | None = None) -> list[Alert]:
    for alert in alerts:
        for key, value in calculate_alert_sla(alert, now=now).items():
            setattr(alert, key, value)
    return alerts


def filter_by_sla(alerts: list[Alert], sla_status: str | None) -> list[Alert]:
    if not sla_status:
        return alerts
    expected = sla_status.strip().upper()
    return [alert for alert in alerts if getattr(alert, "sla_status", None) == expected]


def apply_queue_filters(
    query: Query,
    *,
    statut: str | None = None,
    criticite: str | None = None,
    source: str | None = None,
    analyste: str | None = None,
    current_user_id: str | None = None,
    escaladee: bool | None = None,
) -> Query:
    if statut:
        query = query.filter(Alert.statut == statut.strip().upper())
    if criticite:
        query = query.filter(Alert.niveau_alerte == criticite.strip().upper())
    if source:
        query = query.filter(Alert.source_liste == source.strip().upper())
    if analyste:
        normalized = analyste.strip()
        if normalized.upper() == "NON_ASSIGNEE":
            query = query.filter(Alert.assigned_to_user_id.is_(None))
        elif normalized.upper() == "MOI":
            actor_id = _as_uuid(current_user_id)
            query = query.filter(Alert.assigned_to_user_id == actor_id) if actor_id else query.filter(False)
        else:
            analyst_id = _as_uuid(normalized)
            query = query.filter(Alert.assigned_to_user_id == analyst_id) if analyst_id else query.filter(False)
    if escaladee is True:
        query = query.filter(Alert.supervisor_escalated_at.is_not(None))
    elif escaladee is False:
        query = query.filter(Alert.supervisor_escalated_at.is_(None))
    return query


def queue_ordering():
    status_rank = case(
        (Alert.statut == "ESCALADEE", 0),
        (Alert.statut == "GENEREE", 1),
        (Alert.statut == "EN_COURS", 2),
        (Alert.statut == "CONFIRMEE", 3),
        else_=4,
    )
    criticality_rank = case(
        (Alert.niveau_alerte == "ALERTE_EXACTE", 0),
        (Alert.niveau_alerte == "ALERTE_PROBABLE", 1),
        (Alert.niveau_alerte == "ALERTE_POSSIBLE", 2),
        else_=3,
    )
    return status_rank.asc(), criticality_rank.asc(), Alert.created_at.asc()


def eligible_assignees(db: Session) -> list[User]:
    return (
        db.query(User)
        .filter(User.statut == "ACTIF", User.role.in_(sorted(ASSIGNABLE_ROLES)))
        .order_by(User.full_name.asc(), User.username.asc())
        .all()
    )


def _eligible_user(db: Session, identifier) -> User:
    user_id = _as_uuid(identifier)
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or user.statut != "ACTIF" or canonical_role(user.role) not in ASSIGNABLE_ROLES:
        raise ValueError("L'utilisateur cible n'est pas un analyste actif habilite.")
    return user


def _record_history(
    db: Session,
    *,
    alert: Alert,
    action: str,
    actor: dict,
    previous_user_id=None,
    previous_username: str | None = None,
    target: User | None = None,
    reason: str | None = None,
) -> AlertAssignmentHistory:
    history = AlertAssignmentHistory(
        alert_id=alert.id,
        action=action,
        from_user_id=_as_uuid(previous_user_id),
        from_username=previous_username,
        to_user_id=target.id if target else None,
        to_username=target.username if target else None,
        changed_by_user_id=_as_uuid(actor.get("id")),
        changed_by_username=actor.get("username") or "SYSTEM",
        reason=(reason or "").strip() or None,
    )
    db.add(history)
    return history


def assign_alert(
    db: Session,
    *,
    alert_id,
    assignee_user_id,
    actor: dict,
    reason: str | None = None,
    ip_address: str | None = None,
) -> Alert:
    target = _eligible_user(db, assignee_user_id)
    now = datetime.utcnow()
    updated = (
        db.query(Alert)
        .filter(
            Alert.id == alert_id,
            Alert.assigned_to_user_id.is_(None),
            ~Alert.statut.in_(TERMINAL_ALERT_STATUSES),
        )
        .update(
            {
                Alert.assigned_to_user_id: target.id,
                Alert.assigned_to: target.username,
                Alert.assigned_at: now,
            },
            synchronize_session=False,
        )
    )
    if updated != 1:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise LookupError("Alerte introuvable.")
        if (alert.statut or "").upper() in TERMINAL_ALERT_STATUSES:
            raise AlertAssignmentConflict("Une alerte terminee ne peut pas etre assignee.")
        raise AlertAssignmentConflict(
            f"Alerte deja prise en charge par {alert.assigned_to or 'un autre analyste'}."
        )

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    _record_history(db, alert=alert, action=ASSIGNMENT, actor=actor, target=target, reason=reason)
    write_audit_log(
        db, actor.get("username"), "ALERT_ASSIGNED", "Alert", str(alert.id),
        f"Alerte assignee a {target.username}.", ip_address,
    )
    return alert


def reassign_alert(
    db: Session,
    *,
    alert_id,
    assignee_user_id,
    actor: dict,
    reason: str | None = None,
    ip_address: str | None = None,
) -> Alert:
    target = _eligible_user(db, assignee_user_id)
    alert = db.query(Alert).filter(Alert.id == alert_id).with_for_update().first()
    if not alert:
        raise LookupError("Alerte introuvable.")
    if (alert.statut or "").upper() in TERMINAL_ALERT_STATUSES:
        raise AlertAssignmentConflict("Une alerte terminee ne peut pas etre reassignee.")
    if alert.assigned_to_user_id == target.id:
        raise AlertAssignmentConflict("Cette alerte est deja assignee a cet analyste.")

    previous_id, previous_username = alert.assigned_to_user_id, alert.assigned_to
    alert.assigned_to_user_id = target.id
    alert.assigned_to = target.username
    alert.assigned_at = datetime.utcnow()
    _record_history(
        db, alert=alert, action=REASSIGNMENT, actor=actor,
        previous_user_id=previous_id, previous_username=previous_username,
        target=target, reason=reason,
    )
    write_audit_log(
        db, actor.get("username"), "ALERT_REASSIGNED", "Alert", str(alert.id),
        f"Alerte reassignee de {previous_username or 'non assignee'} a {target.username}.",
        ip_address,
    )
    return alert


def escalate_to_supervisor(
    db: Session,
    *,
    alert_id,
    actor: dict,
    reason: str,
    ip_address: str | None = None,
) -> Alert:
    cleaned_reason = (reason or "").strip()
    if len(cleaned_reason) < 3:
        raise ValueError("Le motif d'escalade est obligatoire.")
    alert = db.query(Alert).filter(Alert.id == alert_id).with_for_update().first()
    if not alert:
        raise LookupError("Alerte introuvable.")
    if alert.supervisor_escalated_at:
        raise AlertAssignmentConflict("Cette alerte est deja escaladee au superviseur.")
    if (alert.statut or "").upper() in TERMINAL_ALERT_STATUSES:
        raise AlertAssignmentConflict("Une alerte terminee ne peut pas etre escaladee.")

    alert.supervisor_escalated_at = datetime.utcnow()
    alert.supervisor_escalated_by = actor.get("username") or "SYSTEM"
    _record_history(
        db, alert=alert, action=SUPERVISOR_ESCALATION, actor=actor,
        previous_user_id=alert.assigned_to_user_id,
        previous_username=alert.assigned_to,
        reason=cleaned_reason,
    )
    write_audit_log(
        db, actor.get("username"), "ALERT_ESCALATED_TO_SUPERVISOR", "Alert", str(alert.id),
        "Alerte escaladée vers le superviseur.", ip_address,
    )
    return alert


def assignment_history(db: Session, alert_id) -> list[AlertAssignmentHistory]:
    return (
        db.query(AlertAssignmentHistory)
        .filter(AlertAssignmentHistory.alert_id == alert_id)
        .order_by(AlertAssignmentHistory.created_at.desc())
        .all()
    )
