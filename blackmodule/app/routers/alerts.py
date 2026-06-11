from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert
from app.schemas import AlertResponse, AlertTreatmentRequest
from app.services.audit_service import write_audit_log


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
    db: Session = Depends(get_db)
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


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: UUID,
    db: Session = Depends(get_db)
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
    db: Session = Depends(get_db)
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

    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alerte introuvable"
        )

    # 1. Mise à jour de l'alerte
    alert.statut = new_status
    alert.treated_by = treatment.treated_by
    alert.treatment_comment = treatment.treatment_comment
    alert.treated_at = datetime.utcnow()

    # 2. Écriture dans le journal d'audit
    write_audit_log(
        db=db,
        user_identifier=treatment.treated_by,
        action="TRAITEMENT_ALERTE",
        entity_type="Alert",
        entity_id=str(alert.id),
        description=(
            f"Alerte traitée avec le statut {new_status}. "
            f"Commentaire : {treatment.treatment_comment}"
        ),
        ip_address=None
    )

    # 3. Sauvegarde dans PostgreSQL
    db.commit()

    # 4. Rechargement de l'alerte après sauvegarde
    db.refresh(alert)

    # 5. Retour de l'alerte mise à jour dans Swagger/API
    return alert