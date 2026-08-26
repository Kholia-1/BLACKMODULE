"""Service générique de validation à quatre yeux."""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.models import ApprovalRequest, Alert
from app.services.audit_service import write_audit_log
from app.services.matching_settings_service import update_matching_settings

PENDING = "EN_ATTENTE_VALIDATION"
APPROVED = "VALIDE"
REJECTED = "REJETE"
OP_MATCHING_SETTINGS = "MATCHING_SETTINGS_UPDATE"
OP_ALERT_TREATMENT = "ALERT_TREATMENT"


def create_approval_request(
    db: Session,
    *,
    operation_type: str,
    initiator: dict,
    target_entity_type: str,
    target_entity_id: str,
    old_values: dict,
    new_values: dict,
    comment: str | None,
    ip_address: str | None,
) -> ApprovalRequest:
    approval = ApprovalRequest(
        operation_type=operation_type,
        status=PENDING,
        initiator_user_id=initiator.get("id"),
        initiated_by=initiator.get("username"),
        target_entity_type=target_entity_type,
        target_entity_id=target_entity_id,
        old_values=json.dumps(old_values, ensure_ascii=False, sort_keys=True),
        new_values=json.dumps(new_values, ensure_ascii=False, sort_keys=True),
        initiator_comment=comment,
    )
    db.add(approval)
    db.flush()
    write_audit_log(
        db, initiator.get("username"), "FOUR_EYES_REQUEST_CREATED", "ApprovalRequest",
        str(approval.id), f"Demande {operation_type} créée pour {target_entity_type}:{target_entity_id}.", ip_address,
    )
    return approval


def review_approval_request(
    db: Session,
    *,
    approval: ApprovalRequest,
    reviewer: dict,
    approved: bool,
    comment: str | None,
    ip_address: str | None,
) -> None:
    if approval.status != PENDING:
        raise ValueError("Cette demande a déjà été traitée.")
    if approval.initiator_user_id and approval.initiator_user_id == reviewer.get("id"):
        raise PermissionError("L'auteur d'une demande ne peut pas la valider.")

    approval.status = APPROVED if approved else REJECTED
    approval.reviewer_user_id = reviewer.get("id")
    approval.reviewed_by = reviewer.get("username")
    approval.reviewer_comment = comment
    approval.reviewed_at = datetime.utcnow()

    if approved:
        _apply_approved_operation(db, approval, reviewer.get("username"))

    write_audit_log(
        db, reviewer.get("username"),
        "FOUR_EYES_APPROVED" if approved else "FOUR_EYES_REJECTED",
        "ApprovalRequest", str(approval.id),
        f"Demande {approval.operation_type} {'validée' if approved else 'rejetée'}.", ip_address,
    )


def _apply_approved_operation(db: Session, approval: ApprovalRequest, reviewer_username: str) -> None:
    values = json.loads(approval.new_values or "{}")
    if approval.operation_type == OP_MATCHING_SETTINGS:
        update_matching_settings(
            db,
            exact_threshold=float(values["exact_threshold"]),
            probable_threshold=float(values["probable_threshold"]),
            possible_threshold=float(values["possible_threshold"]),
            updated_by=reviewer_username,
            commit=False,
        )
        write_audit_log(
            db, reviewer_username, "UPDATE_MATCHING_SETTINGS", "MatchingSetting",
            approval.target_entity_id, "Seuils appliqués après validation à quatre yeux.", None,
        )
    elif approval.operation_type == OP_ALERT_TREATMENT:
        alert = db.query(Alert).filter(Alert.id == approval.target_entity_id).first()
        if not alert:
            raise ValueError("Alerte cible introuvable.")
        alert.statut = values["statut"]
        alert.treated_by = reviewer_username
        alert.treatment_comment = values.get("treatment_comment")
        alert.treated_at = datetime.utcnow()
        write_audit_log(
            db, reviewer_username, "TRAITEMENT_ALERTE", "Alert", str(alert.id),
            f"Décision {alert.statut} appliquée après validation à quatre yeux.", None,
        )
    else:
        raise ValueError("Type de demande inconnu.")
