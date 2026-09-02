"""Operational alert queue: assignment, SLA and supervisor escalation."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from sqlalchemy import case, func
from sqlalchemy.orm import Query, Session

from app.config import ALERT_INACTIVITY_HOURS, ALERT_SLA_HOURS, ALERT_SLA_NEAR_RATIO
from app.models import Alert, AlertAssignmentHistory, AlertDecisionHistory, User
from app.services.audit_service import write_audit_log
from app.services.authorization_service import (
    ROLE_ANALYSTE_CONFORMITE,
)


ASSIGNMENT = "ASSIGNATION"
REASSIGNMENT = "REASSIGNATION"
SUPERVISOR_ESCALATION = "ESCALADE_SUPERVISEUR"

SLA_OK = "DANS_SLA"
SLA_NEAR = "PROCHE_SLA"
SLA_BREACHED = "HORS_SLA"
SLA_COMPLETED = "TRAITEE"

TERMINAL_ALERT_STATUSES = {"FAUX_POSITIF", "CLOTUREE"}
# A supervisor coordinates assignments but is never an analyst assignee.
ASSIGNABLE_ROLES = {ROLE_ANALYSTE_CONFORMITE}
SUPERVISION_FOCUSES = {
    "ALL", "CRITICAL_UNASSIGNED", "OUT_SLA", "ESCALATED", "INACTIVE",
}


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


def _latest_datetime(*values: datetime | None) -> datetime | None:
    available = [_naive_utc(value) for value in values if value is not None]
    return max(available) if available else None


def annotate_operational_activity(
    db: Session,
    alerts: list[Alert],
    *,
    now: datetime | None = None,
) -> list[Alert]:
    """Add last-activity and inactivity information without one query per alert."""
    if not alerts:
        return alerts

    alert_ids = [alert.id for alert in alerts]
    assignment_dates = {
        alert_id: created_at
        for alert_id, created_at in db.query(
            AlertAssignmentHistory.alert_id,
            func.max(AlertAssignmentHistory.created_at),
        ).filter(
            AlertAssignmentHistory.alert_id.in_(alert_ids),
        ).group_by(AlertAssignmentHistory.alert_id).all()
    }
    decision_dates = {
        alert_id: _latest_datetime(initiated_at, reviewed_at, applied_at)
        for alert_id, initiated_at, reviewed_at, applied_at in db.query(
            AlertDecisionHistory.alert_id,
            func.max(AlertDecisionHistory.initiated_at),
            func.max(AlertDecisionHistory.reviewed_at),
            func.max(AlertDecisionHistory.applied_at),
        ).filter(
            AlertDecisionHistory.alert_id.in_(alert_ids),
        ).group_by(AlertDecisionHistory.alert_id).all()
    }

    current_time = _naive_utc(now or datetime.utcnow())
    for alert in alerts:
        last_activity = _latest_datetime(
            alert.created_at,
            alert.assigned_at,
            alert.supervisor_escalated_at,
            alert.treated_at,
            assignment_dates.get(alert.id),
            decision_dates.get(alert.id),
        ) or current_time
        inactivity_hours = max(
            0.0, (current_time - last_activity).total_seconds() / 3600,
        )
        alert.last_activity_at = last_activity
        alert.inactivity_hours = round(inactivity_hours, 2)
        alert.is_inactive = inactivity_hours >= ALERT_INACTIVITY_HOURS
    return alerts


def _supervision_priority(alert: Alert) -> tuple[int, int, float, str]:
    criticality_rank = {
        "ALERTE_EXACTE": 0,
        "ALERTE_PROBABLE": 1,
        "ALERTE_POSSIBLE": 2,
    }.get((alert.niveau_alerte or "").upper(), 3)
    if alert.niveau_alerte == "ALERTE_EXACTE" and not alert.assigned_to_user_id:
        priority_rank, label = 0, "Critique non assignée"
    elif getattr(alert, "sla_status", None) == SLA_BREACHED:
        priority_rank, label = 1, "Hors SLA"
    elif alert.supervisor_escalated_at:
        priority_rank, label = 2, "Escaladée"
    elif getattr(alert, "sla_status", None) == SLA_NEAR:
        priority_rank, label = 3, "Proche SLA"
    elif alert.niveau_alerte == "ALERTE_EXACTE":
        priority_rank, label = 4, "Critique"
    else:
        priority_rank, label = 5, "Standard"
    alert.operational_priority = label
    alert.operational_priority_rank = priority_rank
    return priority_rank, criticality_rank, -getattr(alert, "age_hours", 0.0), str(alert.id)


def analyst_workloads(alerts: list[Alert], analysts: list[User]) -> list[dict]:
    analysts = [
        analyst for analyst in analysts
        if analyst.role == ROLE_ANALYSTE_CONFORMITE
    ]
    workloads = []
    for analyst in analysts:
        owned = [item for item in alerts if item.assigned_to_user_id == analyst.id]
        workloads.append({
            "user": analyst,
            "total": len(owned),
            "critical": sum(item.niveau_alerte == "ALERTE_EXACTE" for item in owned),
            "out_sla": sum(getattr(item, "sla_status", None) == SLA_BREACHED for item in owned),
            "inactive": sum(bool(getattr(item, "is_inactive", False)) for item in owned),
        })
    return sorted(
        workloads,
        key=lambda item: (-item["out_sla"], -item["critical"], -item["total"], item["user"].username),
    )


def recent_operational_history(db: Session, *, limit: int = 20) -> list[dict]:
    assignment_rows = (
        db.query(AlertAssignmentHistory)
        .order_by(AlertAssignmentHistory.created_at.desc())
        .limit(limit)
        .all()
    )
    decision_rows = (
        db.query(AlertDecisionHistory)
        .order_by(AlertDecisionHistory.initiated_at.desc())
        .limit(limit)
        .all()
    )
    events = []
    for item in assignment_rows:
        if item.action == ASSIGNMENT:
            description = f"Assignée à {item.to_username or '—'}"
        elif item.action == REASSIGNMENT:
            description = f"Réassignée de {item.from_username or '—'} à {item.to_username or '—'}"
        else:
            description = "Escaladée vers le superviseur"
        events.append({
            "alert_id": item.alert_id,
            "event_type": item.action,
            "description": description,
            "actor": item.changed_by_username,
            "created_at": item.created_at,
        })
    for item in decision_rows:
        events.append({
            "alert_id": item.alert_id,
            "event_type": "DECISION",
            "description": (
                f"Décision {item.old_status or '—'} → {item.requested_status} "
                f"({item.decision_status})"
            ),
            "actor": item.reviewed_by or item.initiated_by,
            "created_at": _latest_datetime(item.applied_at, item.reviewed_at, item.initiated_at),
        })
    events.sort(
        key=lambda item: _naive_utc(item["created_at"]) if item["created_at"] else datetime.min,
        reverse=True,
    )
    selected = events[:limit]
    alert_references = {
        alert_id: reference
        for alert_id, reference in db.query(Alert.id, Alert.client_reference).filter(
            Alert.id.in_([item["alert_id"] for item in selected]),
        ).all()
    } if selected else {}
    for item in selected:
        item["alert_reference"] = alert_references.get(item["alert_id"]) or "Sans référence"
    return selected


def build_supervision_dashboard(
    db: Session,
    *,
    focus: str | None = None,
    analyst: str | None = None,
    statut: str | None = None,
    source: str | None = None,
    now: datetime | None = None,
) -> dict:
    """Build the supervisor queue from the existing alert and history models."""
    alerts = (
        db.query(Alert)
        .filter(~Alert.statut.in_(TERMINAL_ALERT_STATUSES))
        .all()
    )
    annotate_alerts(alerts, now=now)
    annotate_operational_activity(db, alerts, now=now)
    alerts.sort(key=_supervision_priority)

    analysts = eligible_assignees(db)
    metrics = {
        "active": len(alerts),
        "critical_unassigned": sum(
            item.niveau_alerte == "ALERTE_EXACTE" and not item.assigned_to_user_id
            for item in alerts
        ),
        "out_sla": sum(item.sla_status == SLA_BREACHED for item in alerts),
        "escalated": sum(bool(item.supervisor_escalated_at) for item in alerts),
        "inactive": sum(bool(item.is_inactive) for item in alerts),
    }

    current_focus = (focus or "ALL").strip().upper()
    if current_focus not in SUPERVISION_FOCUSES:
        current_focus = "ALL"
    filtered = list(alerts)
    if current_focus == "CRITICAL_UNASSIGNED":
        filtered = [item for item in filtered if item.niveau_alerte == "ALERTE_EXACTE" and not item.assigned_to_user_id]
    elif current_focus == "OUT_SLA":
        filtered = [item for item in filtered if item.sla_status == SLA_BREACHED]
    elif current_focus == "ESCALATED":
        filtered = [item for item in filtered if item.supervisor_escalated_at]
    elif current_focus == "INACTIVE":
        filtered = [item for item in filtered if item.is_inactive]

    current_analyst = (analyst or "").strip()
    if current_analyst:
        if current_analyst.upper() == "NON_ASSIGNEE":
            filtered = [item for item in filtered if not item.assigned_to_user_id]
        else:
            analyst_id = _as_uuid(current_analyst)
            filtered = [item for item in filtered if analyst_id and item.assigned_to_user_id == analyst_id]
    current_status = (statut or "").strip().upper()
    if current_status:
        filtered = [item for item in filtered if (item.statut or "").upper() == current_status]
    current_source = (source or "").strip().upper()
    if current_source:
        filtered = [item for item in filtered if (item.source_liste or "").upper() == current_source]

    return {
        "alerts": filtered,
        "metrics": metrics,
        "workloads": analyst_workloads(alerts, analysts),
        "history": recent_operational_history(db),
        "analysts": analysts,
        "sources": sorted({item.source_liste for item in alerts if item.source_liste}),
        "focus": current_focus,
        "analyst": current_analyst or None,
        "statut": current_status or None,
        "source": current_source or None,
        "inactivity_hours": ALERT_INACTIVITY_HOURS,
    }


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
    if not user or user.statut != "ACTIF" or user.role not in ASSIGNABLE_ROLES:
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
