from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import SanctionEntry, Alert, AuditLog
from app.schemas import DashboardStatsResponse


router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard"]
)


@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_sanctions = db.query(SanctionEntry).count()

    active_sanctions = db.query(SanctionEntry).filter(
        SanctionEntry.statut == "ACTIF"
    ).count()

    total_alerts = db.query(Alert).count()

    alerts_generee = db.query(Alert).filter(
        Alert.statut == "GENEREE"
    ).count()

    alerts_en_cours = db.query(Alert).filter(
        Alert.statut == "EN_COURS"
    ).count()

    alerts_confirmee = db.query(Alert).filter(
        Alert.statut == "CONFIRMEE"
    ).count()

    alerts_faux_positif = db.query(Alert).filter(
        Alert.statut == "FAUX_POSITIF"
    ).count()

    alerts_escaladee = db.query(Alert).filter(
        Alert.statut == "ESCALADEE"
    ).count()

    alerts_cloturee = db.query(Alert).filter(
        Alert.statut == "CLOTUREE"
    ).count()

    alertes_exactes = db.query(Alert).filter(
        Alert.niveau_alerte == "ALERTE_EXACTE"
    ).count()

    alertes_probables = db.query(Alert).filter(
        Alert.niveau_alerte == "ALERTE_PROBABLE"
    ).count()

    alertes_possibles = db.query(Alert).filter(
        Alert.niveau_alerte == "ALERTE_POSSIBLE"
    ).count()

    total_audit_logs = db.query(AuditLog).count()

    return DashboardStatsResponse(
        total_sanctions=total_sanctions,
        active_sanctions=active_sanctions,

        total_alerts=total_alerts,
        alerts_generee=alerts_generee,
        alerts_en_cours=alerts_en_cours,
        alerts_confirmee=alerts_confirmee,
        alerts_faux_positif=alerts_faux_positif,
        alerts_escaladee=alerts_escaladee,
        alerts_cloturee=alerts_cloturee,

        alertes_exactes=alertes_exactes,
        alertes_probables=alertes_probables,
        alertes_possibles=alertes_possibles,

        total_audit_logs=total_audit_logs
    )