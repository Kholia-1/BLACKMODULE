import json
from datetime import datetime
from uuid import UUID

from sqlalchemy.orm import Session

from app.models import Alert, AlertDecisionHistory, ApprovalRequest
from app.services.audit_service import write_audit_log


ALLOWED_ALERT_STATUSES = frozenset({
    "GENEREE", "EN_COURS", "FAUX_POSITIF", "CONFIRMEE", "ESCALADEE", "CLOTUREE",
})
FOUR_EYES_ALERT_STATUSES = frozenset({"FAUX_POSITIF", "CONFIRMEE", "CLOTUREE"})
PENDING_DECISION = "EN_ATTENTE_VALIDATION"
APPLIED_DECISION = "APPLIQUEE"
APPROVED_DECISION = "VALIDEE"
REJECTED_DECISION = "REJETEE"
OBSOLETE_DECISION = "OBSOLETE"

ALLOWED_TRANSITIONS = {
    "GENEREE": {"EN_COURS", "FAUX_POSITIF", "CONFIRMEE", "ESCALADEE", "CLOTUREE"},
    "EN_COURS": {"FAUX_POSITIF", "CONFIRMEE", "ESCALADEE", "CLOTUREE"},
    "ESCALADEE": {"EN_COURS", "FAUX_POSITIF", "CONFIRMEE", "CLOTUREE"},
    "CONFIRMEE": {"CLOTUREE"},
    "FAUX_POSITIF": set(),
    "CLOTUREE": set(),
}

ALERT_STATUS_LABELS = {
    "GENEREE": "Générée",
    "EN_COURS": "En cours",
    "ESCALADEE": "Escaladée",
    "CONFIRMEE": "Confirmée",
    "FAUX_POSITIF": "Faux positif",
    "CLOTUREE": "Clôturée",
}
DECISION_STATUS_LABELS = {
    PENDING_DECISION: "En attente de validation",
    APPLIED_DECISION: "Appliquée",
    APPROVED_DECISION: "Validée et appliquée",
    REJECTED_DECISION: "Rejetée",
    OBSOLETE_DECISION: "Obsolète",
}


class AlertDecisionConflict(ValueError):
    pass


class ObsoleteAlertDecision(AlertDecisionConflict):
    pass


def available_alert_decisions(alert: Alert) -> tuple[str, ...]:
    """Return the transitions authorized by the central decision workflow."""
    current = (alert.statut or "GENEREE").upper()
    allowed = ALLOWED_TRANSITIONS.get(current, set())
    display_order = ("EN_COURS", "FAUX_POSITIF", "CONFIRMEE", "ESCALADEE", "CLOTUREE")
    return tuple(status for status in display_order if status in allowed)


def _duration_label(started_at: datetime | None, ended_at: datetime | None) -> str:
    if not started_at or not ended_at:
        return "—"
    seconds = max(0, int((ended_at - started_at).total_seconds()))
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return f"{days} j {hours} h"
    if hours:
        return f"{hours} h {minutes} min"
    return f"{minutes} min"


def decision_history_view(alert: Alert, rows: list[AlertDecisionHistory]) -> list[dict]:
    """Build a readable view without altering the persisted business records."""
    result = []
    for row in rows:
        decision_at = row.applied_at or row.reviewed_at
        has_independent_review = row.approval_request_id is not None
        result.append({
            "old_status": ALERT_STATUS_LABELS.get(row.old_status, row.old_status or "—"),
            "requested_status": ALERT_STATUS_LABELS.get(
                row.requested_status, row.requested_status,
            ),
            "decision_status": DECISION_STATUS_LABELS.get(
                row.decision_status, row.decision_status,
            ),
            "initiated_by": row.initiated_by,
            "initiated_at": row.initiated_at,
            "reviewed_by": row.reviewed_by if has_independent_review else None,
            "reviewed_at": row.reviewed_at if has_independent_review else None,
            "decision_at": decision_at,
            "delay_label": _duration_label(alert.created_at, decision_at),
            "reason": row.reason,
            "reviewer_comment": row.reviewer_comment,
        })
    return result


def _clean_reason(value: str | None) -> str | None:
    cleaned = (value or "").strip()
    return cleaned or None


def _pending_approval(db: Session, alert_id) -> ApprovalRequest | None:
    from app.services.approval_service import OP_ALERT_TREATMENT, PENDING

    return db.query(ApprovalRequest).filter(
        ApprovalRequest.operation_type == OP_ALERT_TREATMENT,
        ApprovalRequest.target_entity_type == "Alert",
        ApprovalRequest.target_entity_id == str(alert_id),
        ApprovalRequest.status == PENDING,
    ).first()


def _validate_transition(
    db: Session, *, alert: Alert, new_status: str, reason: str | None,
) -> tuple[str, str | None]:
    status = (new_status or "").upper().strip()
    if status not in ALLOWED_ALERT_STATUSES:
        raise ValueError("Statut d'alerte invalide.")
    if status == "FAUX_POSITIF" and not reason:
        raise ValueError("Un motif est obligatoire pour classer une alerte en faux positif.")
    current = (alert.statut or "GENEREE").upper()
    if status == current:
        raise AlertDecisionConflict("Cette alerte possède déjà ce statut.")
    if status not in ALLOWED_TRANSITIONS.get(current, set()):
        raise AlertDecisionConflict(f"Transition d'alerte interdite : {current} -> {status}.")
    if _pending_approval(db, alert.id):
        raise AlertDecisionConflict("Une décision est déjà en attente pour cette alerte.")
    return status, reason


def request_alert_decision(
    db: Session,
    *,
    alert: Alert,
    new_status: str,
    reason: str | None,
    actor: dict,
    ip_address: str | None,
) -> tuple[str, ApprovalRequest | None]:
    """Apply a reversible transition or create the existing four-eyes request."""
    from app.services.approval_service import OP_ALERT_TREATMENT, create_approval_request

    cleaned_reason = _clean_reason(reason)
    status, cleaned_reason = _validate_transition(
        db, alert=alert, new_status=new_status, reason=cleaned_reason,
    )
    username = actor.get("username") or "SYSTEM"
    old_status = alert.statut or "GENEREE"
    now = datetime.utcnow()

    if status in FOUR_EYES_ALERT_STATUSES:
        approval = create_approval_request(
            db=db,
            operation_type=OP_ALERT_TREATMENT,
            initiator=actor,
            target_entity_type="Alert",
            target_entity_id=str(alert.id),
            old_values={
                "statut": old_status,
                "treated_by": alert.treated_by,
                "treated_at": alert.treated_at.isoformat() if alert.treated_at else None,
            },
            new_values={"statut": status, "treatment_comment": cleaned_reason},
            comment=cleaned_reason,
            ip_address=ip_address,
        )
        history = AlertDecisionHistory(
            alert_id=alert.id,
            approval_request_id=approval.id,
            old_status=old_status,
            requested_status=status,
            decision_status=PENDING_DECISION,
            initiated_by=username,
            initiated_at=now,
            reason=cleaned_reason,
        )
        db.add(history)
        write_audit_log(
            db, username, "ALERT_DECISION_REQUESTED", "Alert", str(alert.id),
            f"Décision {old_status} -> {status} soumise au quatre yeux; motif conservé dans l'historique métier.",
            ip_address,
        )
        return PENDING_DECISION, approval

    alert.statut = status
    alert.treated_by = username
    alert.treatment_comment = cleaned_reason
    alert.treated_at = now
    db.add(AlertDecisionHistory(
        alert_id=alert.id,
        old_status=old_status,
        requested_status=status,
        decision_status=APPLIED_DECISION,
        initiated_by=username,
        initiated_at=now,
        reason=cleaned_reason,
        reviewed_by=username,
        reviewed_at=now,
        applied_at=now,
    ))
    write_audit_log(
        db, username, "ALERT_STATUS_CHANGED", "Alert", str(alert.id),
        f"Statut {old_status} -> {status}; motif conservé dans l'historique métier.",
        ip_address,
    )
    return APPLIED_DECISION, None


def _history_for_approval(db: Session, approval: ApprovalRequest) -> AlertDecisionHistory:
    history = db.query(AlertDecisionHistory).filter(
        AlertDecisionHistory.approval_request_id == approval.id,
    ).first()
    if not history:
        old_values = json.loads(approval.old_values or "{}")
        new_values = json.loads(approval.new_values or "{}")
        history = AlertDecisionHistory(
            alert_id=UUID(str(approval.target_entity_id)),
            approval_request_id=approval.id,
            old_status=old_values.get("statut"),
            requested_status=new_values.get("statut") or "INCONNU",
            decision_status=PENDING_DECISION,
            initiated_by=approval.initiated_by,
            initiated_at=approval.created_at or datetime.utcnow(),
            reason=new_values.get("treatment_comment") or approval.initiator_comment,
        )
        db.add(history)
        db.flush()
    return history


def apply_approved_alert_decision(
    db: Session, *, approval: ApprovalRequest, reviewer_username: str,
) -> None:
    values = json.loads(approval.new_values or "{}")
    old_values = json.loads(approval.old_values or "{}")
    try:
        alert_id = UUID(str(approval.target_entity_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("Identifiant d'alerte invalide.") from exc
    alert = db.query(Alert).filter(Alert.id == alert_id).with_for_update().first()
    if not alert:
        raise ValueError("Alerte cible introuvable.")
    expected_status = old_values.get("statut")
    if alert.statut != expected_status:
        raise ObsoleteAlertDecision(
            f"La décision est obsolète : statut attendu {expected_status}, statut actuel {alert.statut}."
        )

    history = _history_for_approval(db, approval)
    now = datetime.utcnow()
    alert.statut = values["statut"]
    alert.treated_by = reviewer_username
    alert.treatment_comment = values.get("treatment_comment")
    alert.treated_at = now
    history.decision_status = APPROVED_DECISION
    history.reviewed_by = reviewer_username
    history.reviewed_at = now
    history.applied_at = now
    write_audit_log(
        db, reviewer_username, "ALERT_DECISION_APPLIED", "Alert", str(alert.id),
        f"Statut {expected_status} -> {alert.statut}; initiateur={approval.initiated_by}; "
        "motif conservé dans l'historique métier.", None,
    )


def reject_alert_decision(
    db: Session, *, approval: ApprovalRequest, reviewer_username: str,
    reviewer_comment: str | None,
) -> None:
    history = _history_for_approval(db, approval)
    history.decision_status = REJECTED_DECISION
    history.reviewed_by = reviewer_username
    history.reviewed_at = approval.reviewed_at or datetime.utcnow()
    history.reviewer_comment = _clean_reason(reviewer_comment)
    write_audit_log(
        db, reviewer_username, "ALERT_DECISION_REJECTED", "Alert", approval.target_entity_id,
        f"Décision {history.old_status} -> {history.requested_status} rejetée; "
        f"initiateur={approval.initiated_by}; motifs conservés dans l'historique métier.", None,
    )


def mark_alert_decision_obsolete(db: Session, approval: ApprovalRequest, reviewer_username: str) -> None:
    history = _history_for_approval(db, approval)
    history.decision_status = OBSOLETE_DECISION
    history.reviewed_by = reviewer_username
    history.reviewed_at = approval.reviewed_at or datetime.utcnow()
