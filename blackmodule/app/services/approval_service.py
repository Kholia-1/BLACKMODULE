"""Service générique de validation à quatre yeux."""

from __future__ import annotations

import json
import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.models import ApprovalRequest, Alert
from app.services.audit_service import write_audit_log
from app.services.matching_settings_service import update_matching_settings

PENDING = "EN_ATTENTE_VALIDATION"
APPROVED = "VALIDE"
REJECTED = "REJETE"
OBSOLETE = "OBSOLETE"
IN_PROGRESS = "EN_COURS"
FAILED = "ECHEC"
OP_MATCHING_SETTINGS = "MATCHING_SETTINGS_UPDATE"
OP_ALERT_TREATMENT = "ALERT_TREATMENT"
OP_LIST_VERSION_RESTORE = "LIST_VERSION_RESTORE"


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

    approval.reviewer_user_id = reviewer.get("id")
    approval.reviewed_by = reviewer.get("username")
    approval.reviewer_comment = comment
    approval.reviewed_at = datetime.utcnow()

    if approved:
        try:
            _apply_approved_operation(db, approval, reviewer.get("username"))
        except Exception as exc:
            from app.services.list_version_service import ObsoleteRestoreRequest

            if not isinstance(exc, ObsoleteRestoreRequest):
                raise
            approval.status = OBSOLETE
            write_audit_log(
                db, reviewer.get("username"), "FOUR_EYES_OBSOLETE", "ApprovalRequest",
                str(approval.id), str(exc), ip_address,
            )
            return
        approval.status = APPROVED
    else:
        approval.status = REJECTED

    write_audit_log(
        db, reviewer.get("username"),
        "FOUR_EYES_APPROVED" if approved else "FOUR_EYES_REJECTED",
        "ApprovalRequest", str(approval.id),
        f"Demande {approval.operation_type} {'validée' if approved else 'rejetée'}.", ip_address,
    )


def queue_restore_approval(
    db: Session, *, approval: ApprovalRequest, reviewer: dict,
    comment: str | None, ip_address: str | None,
) -> None:
    """Record the four-eyes decision without keeping the Web request open."""
    if approval.status != PENDING:
        raise ValueError("Cette demande a déjà été traitée.")
    if approval.initiator_user_id and approval.initiator_user_id == reviewer.get("id"):
        raise PermissionError("L'auteur d'une demande ne peut pas la valider.")
    if approval.operation_type != OP_LIST_VERSION_RESTORE:
        raise ValueError("Seule une restauration peut être programmée.")
    approval.reviewer_user_id = reviewer.get("id")
    approval.reviewed_by = reviewer.get("username")
    approval.reviewer_comment = comment
    approval.reviewed_at = datetime.utcnow()
    approval.status = IN_PROGRESS
    write_audit_log(
        db, reviewer.get("username"), "FOUR_EYES_RESTORE_QUEUED", "ApprovalRequest",
        str(approval.id), "Restauration validée et programmée en arrière-plan.", ip_address,
    )


def process_queued_restore(db: Session, approval_id: str) -> None:
    """Apply a previously approved restore in the scheduler transaction."""
    try:
        approval_uuid = uuid.UUID(str(approval_id))
    except (TypeError, ValueError, AttributeError):
        return
    approval = db.query(ApprovalRequest).filter(ApprovalRequest.id == approval_uuid).with_for_update().first()
    if not approval or approval.status != IN_PROGRESS:
        return
    try:
        # Keep the expensive, source-scoped impact calculation out of HTTP,
        # while retaining it in the approval record for auditability.
        values = json.loads(approval.new_values or "{}")
        from app.models import ListVersion
        from app.services.list_version_service import get_version_preview
        target_version = db.query(ListVersion).filter(
            ListVersion.id == uuid.UUID(values["target_version_id"])
        ).first()
        if not target_version:
            raise ValueError("Version cible introuvable.")
        approval.old_values = json.dumps(
            {"preview": get_version_preview(db, target_version)},
            ensure_ascii=False, sort_keys=True,
        )
        _apply_approved_operation(db, approval, approval.reviewed_by or "SCHEDULER")
        approval.status = APPROVED
        write_audit_log(
            db, approval.reviewed_by, "FOUR_EYES_APPROVED", "ApprovalRequest", str(approval.id),
            "Restauration appliquée après validation à quatre yeux.", None,
        )
        db.commit()
    except Exception as error:
        db.rollback()
        approval = db.query(ApprovalRequest).filter(ApprovalRequest.id == approval_uuid).with_for_update().first()
        if not approval:
            return
        from app.services.list_version_service import ObsoleteRestoreRequest
        approval.status = OBSOLETE if isinstance(error, ObsoleteRestoreRequest) else FAILED
        write_audit_log(
            db, approval.reviewed_by or "SCHEDULER",
            "FOUR_EYES_OBSOLETE" if approval.status == OBSOLETE else "FOUR_EYES_RESTORE_FAILED",
            "ApprovalRequest", str(approval.id),
            "Restauration obsolète." if approval.status == OBSOLETE else "Restauration en erreur; consulter les journaux d'audit.",
            None,
        )
        db.commit()


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
    elif approval.operation_type == OP_LIST_VERSION_RESTORE:
        # Import lazily to keep the generic four-eyes service independent of
        # list import modules during application startup.
        from app.services.list_version_service import apply_version_restore

        apply_version_restore(
            db,
            target_version_id=values["target_version_id"],
            expected_current_version_id=values["expected_current_version_id"],
            reviewer_username=reviewer_username,
            reason=values.get("reason"),
        )
    else:
        raise ValueError("Type de demande inconnu.")
