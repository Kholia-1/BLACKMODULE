from sqlalchemy.orm import Session

from app.models import AuditLog


def write_audit_log(
    db: Session,
    user_identifier: str | None,
    action: str,
    entity_type: str | None = None,
    entity_id: str | None = None,
    description: str | None = None,
    ip_address: str | None = None
):
    audit = AuditLog(
        user_identifier=user_identifier,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        description=description,
        ip_address=ip_address
    )

    db.add(audit)
    return audit