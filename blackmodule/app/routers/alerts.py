from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, AuditLog
from app.schemas import AlertResponse, AlertTreatmentRequest
from app.services.audit_service import write_audit_log
from app.services.api_auth import get_session_user, require_permission
from app.services.alert_analysis_service import build_alert_analysis
from app.services.alert_decision_service import AlertDecisionConflict, request_alert_decision
from app.services.authorization_service import (
    PERMISSION_NOTIFICATIONS_VIEW,
    PERMISSION_TREAT_ALERTS,
    PERMISSION_VIEW_ALERTS,
)


router = APIRouter(
    prefix="/api/alerts",
    tags=["Alerts"]
)


@router.get("/", response_model=list[AlertResponse])
def list_alerts(
    statut: str | None = Query(
        None,
        description="Filtrer par statut : GENEREE, EN_COURS, FAUX_POSITIF, CONFIRMEE, ESCALADEE, CLOTUREE"
    ),
    niveau_alerte: str | None = Query(
        None,
        description="Filtrer par niveau : ALERTE_EXACTE, ALERTE_PROBABLE, ALERTE_POSSIBLE"
    ),
    db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_VIEW_ALERTS))
):
    """
    Liste toutes les alertes générées par le moteur de matching.
    Possibilité de filtrer par statut ou par niveau d'alerte.
    """

    query = db.query(Alert)

    if statut:
        query = query.filter(Alert.statut == statut.upper())

    if niveau_alerte:
        query = query.filter(Alert.niveau_alerte == niveau_alerte.upper())

    alerts = query.order_by(Alert.created_at.desc()).all()

    return alerts


@router.get("/critical-notifications")
def get_critical_notifications(
    db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_NOTIFICATIONS_VIEW))
):
    """
    Fournit le contenu de la cloche de notifications : nombre et liste
    des alertes critiques actives, pour affichage en temps réel dans le menu.
    """

    query = db.query(Alert).filter(
        Alert.niveau_alerte.in_(["ALERTE_EXACTE", "ALERTE_PROBABLE"]),
        Alert.statut.in_(["GENEREE", "EN_COURS", "ESCALADEE"])
    )

    recent = query.order_by(Alert.created_at.desc()).limit(8).all()

    technical_notifications = (
        db.query(AuditLog)
        .filter(
            AuditLog.action == "LIST_UPDATE_ALERT",
            AuditLog.entity_type == "ListFreshness",
        )
        .order_by(AuditLog.created_at.desc())
        .limit(8)
        .all()
    )

    alert_items = [
        {
            "id": str(alert.id),
            "client_reference": alert.client_reference,
            "client_nom": alert.client_nom,
            "client_prenom": alert.client_prenom,
            "niveau_alerte": alert.niveau_alerte,
            "statut": alert.statut,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
            "notification_type": "ALERTE",
        }
        for alert in recent
    ]
    technical_items = [
        {
            "id": str(log.id),
            "title": f"Liste {log.entity_id}",
            "description": log.description,
            "niveau_alerte": "TECHNIQUE",
            "created_at": log.created_at.isoformat() if log.created_at else None,
            "notification_type": "TECHNIQUE",
        }
        for log in technical_notifications
    ]

    return {
        "total": query.count() + len(technical_items),
        "items": technical_items + alert_items,
    }


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: UUID,
    db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_VIEW_ALERTS))
):
    """
    Récupère une alerte précise à partir de son ID.
    """

    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alerte introuvable"
        )

    return alert


@router.put("/{alert_id}/treat", response_model=AlertResponse)
def treat_alert(
    alert_id: UUID,
    treatment: AlertTreatmentRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_TREAT_ALERTS))
):
    """
    Traite une alerte de conformité.

    Exemple de statuts possibles :
    - EN_COURS
    - FAUX_POSITIF
    - CONFIRMEE
    - ESCALADEE
    - CLOTUREE
    """

    allowed_statuses = [
        "GENEREE",
        "EN_COURS",
        "FAUX_POSITIF",
        "CONFIRMEE",
        "ESCALADEE",
        "CLOTUREE"
    ]

    new_status = treatment.statut.upper()

    if new_status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Statut invalide. Valeurs autorisées : {allowed_statuses}"
        )

    alert = db.query(Alert).filter(Alert.id == alert_id).with_for_update().first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alerte introuvable"
        )

    try:
        request_alert_decision(
            db, alert=alert, new_status=new_status,
            reason=treatment.treatment_comment, actor=user,
            ip_address=request.client.host if request.client else None,
        )
        db.commit()
        db.refresh(alert)
    except AlertDecisionConflict as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return alert


@router.get("/{alert_id}/analysis")
def get_alert_analysis(
    alert_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_VIEW_ALERTS)),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte introuvable")
    analysis = build_alert_analysis(db, alert)
    write_audit_log(
        db, user.get("username"), "VIEW_ALERT_ANALYSIS", "Alert", str(alert.id),
        "Consultation de l'analyse consolidée; chaque source reste indépendante.",
        request.client.host if request.client else None,
    )
    db.commit()
    return analysis
