from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditLog
from app.schemas import AuditLogResponse


router = APIRouter(
    prefix="/api/audit-logs",
    tags=["Audit Logs"]
)


@router.get("/", response_model=list[AuditLogResponse])
def list_audit_logs(
    action: str | None = Query(
        None,
        description="Filtrer par action : TRAITEMENT_ALERTE, CREATION_SANCTION..."
    ),
    user_identifier: str | None = Query(
        None,
        description="Filtrer par utilisateur"
    ),
    db: Session = Depends(get_db)
):
    query = db.query(AuditLog)

    if action:
        query = query.filter(AuditLog.action == action.upper())

    if user_identifier:
        query = query.filter(AuditLog.user_identifier == user_identifier)

    logs = query.order_by(AuditLog.created_at.desc()).all()

    return logs