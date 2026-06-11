from datetime import datetime
from typing import Optional
import os

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import SanctionEntry, Alert
from app.services.audit_service import write_audit_log
from app.services.matching_service import (
    build_full_name,
    calculate_name_score,
    classify_alert
)
from app.services.matching_settings_service import get_or_create_matching_settings


router = APIRouter(
    prefix="/api/external",
    tags=["External API"]
)


EXTERNAL_API_KEY = os.getenv("BLACKMODULE_API_KEY", "BLACKMODULE-API-KEY-2026")


def verify_api_key(x_api_key: str | None = Header(None)):
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="Clé API manquante. Header requis : X-API-KEY."
        )

    received_key = x_api_key.strip()
    expected_key = EXTERNAL_API_KEY.strip()

    if received_key != expected_key:
        raise HTTPException(
            status_code=403,
            detail="Clé API invalide."
        )

    return True

def build_request_id() -> str:
    return f"REQ-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"


class ExternalClientCheckRequest(BaseModel):
    client_reference: Optional[str] = None
    nom: str
    prenom: Optional[str] = None
    date_naissance: Optional[str] = None
    nationalite: Optional[str] = None
    num_passeport: Optional[str] = None


@router.get("/status")
def external_api_status(
    db: Session = Depends(get_db),
    authorized: bool = Depends(verify_api_key)
):
    write_audit_log(
        db=db,
        user_identifier="EXTERNAL_API",
        action="API_STATUS_CHECK",
        entity_type="ExternalAPI",
        entity_id="status",
        description="Consultation du statut de l’API externe.",
        ip_address=None
    )

    db.commit()



    return {
        "success": True,
        "request_id": build_request_id(),
        "timestamp": datetime.utcnow().isoformat(),
        "service": "BLACKMODULE External API",
        "status": "OK",
        "message": "API externe opérationnelle"
    }

@router.get("/documentation")
def external_api_documentation(
    db: Session = Depends(get_db),
    authorized: bool = Depends(verify_api_key)
):
    write_audit_log(
        db=db,
        user_identifier="EXTERNAL_API",
        action="API_DOCUMENTATION_ACCESS",
        entity_type="ExternalAPI",
        entity_id="documentation",
        description="Consultation de la documentation API externe.",
        ip_address=None
    )

    db.commit()

    return {
        "success": True,
        "request_id": build_request_id(),
        "timestamp": datetime.utcnow().isoformat(),
        "service": "BLACKMODULE External API",
        "version": "1.0",
        "authentication": {
            "type": "API_KEY",
            "header": "X-API-KEY",
            "description": "Toutes les requêtes doivent contenir une clé API valide dans le header X-API-KEY."
        },
        "endpoints": [
            {
                "name": "Statut API",
                "method": "GET",
                "path": "/api/external/status",
                "description": "Vérifie si l’API externe BLACKMODULE est opérationnelle."
            },
            {
                "name": "Vérification client",
                "method": "POST",
                "path": "/api/external/check-client",
                "description": "Lance un filtrage client contre les listes de sanctions actives.",
                "required_fields": [
                    "nom"
                ],
                "optional_fields": [
                    "client_reference",
                    "prenom",
                    "date_naissance",
                    "nationalite",
                    "num_passeport"
                ],
                "request_example": {
                    "client_reference": "API-TEST-001",
                    "nom": "DURAND",
                    "prenom": "PIERRE",
                    "date_naissance": "1972-09-01",
                    "nationalite": "FRANCAISE",
                    "num_passeport": "FRP123456"
                },
                "response_fields": [
                    "success",
                    "request_id",
                    "timestamp",
                    "client",
                    "screening_result",
                    "matches",
                    "message"
                ]
            },
            {
                "name": "Consultation des alertes client",
                "method": "GET",
                "path": "/api/external/alerts/{client_reference}",
                "description": "Retourne les alertes associées à une référence client."
            }
        ],
        "business_status_values": {
            "AUCUNE_ALERTE": "Aucune correspondance significative.",
            "ALERTE_POSSIBLE": "Correspondance faible nécessitant une vérification.",
            "ALERTE_PROBABLE": "Correspondance forte nécessitant une analyse conformité.",
            "ALERTE_EXACTE": "Correspondance critique nécessitant un blocage ou une escalade."
        },
        "recommended_actions": {
            "OPERATION_AUTORISEE": "Le traitement peut continuer.",
            "VERIFICATION_MANUELLE": "Une analyse manuelle est nécessaire.",
            "ESCALADE_CONFORMITE": "Le dossier doit être transmis à la conformité.",
            "BLOQUER_OPERATION": "L’opération doit être bloquée en attente de décision."
        },
        "message": "Documentation API externe BLACKMODULE."
    }

@router.post("/check-client")
def external_check_client(
    payload: ExternalClientCheckRequest,
    db: Session = Depends(get_db),
    authorized: bool = Depends(verify_api_key)
):
    parsed_date = None

    if payload.date_naissance:
        try:
            parsed_date = datetime.strptime(
                payload.date_naissance,
                "%Y-%m-%d"
            ).date()
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Format date_naissance invalide. Format attendu : YYYY-MM-DD."
            )

    client_reference = payload.client_reference

    if not client_reference or not client_reference.strip():
        client_reference = f"API-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    client_full_name = build_full_name(payload.prenom, payload.nom)

    settings = get_or_create_matching_settings(db)

    sanctions = db.query(SanctionEntry).filter(
        SanctionEntry.statut == "ACTIF"
    ).all()

    matches = []
    highest_score = 0.0
    global_status = "AUCUNE_ALERTE"
    global_action = "OPERATION_AUTORISEE"
    generated_alerts_count = 0
    existing_alerts_count = 0

    for sanction in sanctions:
        listed_name = sanction.nom_complet or build_full_name(
            sanction.prenom,
            sanction.nom
        )

        name_score = calculate_name_score(client_full_name, listed_name)
        final_score = name_score
        matching_type = "FUZZY_NAME"

        if payload.num_passeport and sanction.num_passeport:
            if payload.num_passeport.strip().upper() == sanction.num_passeport.strip().upper():
                final_score = 100.0
                matching_type = "EXACT_PASSPORT"

        if parsed_date and sanction.date_naissance:
            if parsed_date == sanction.date_naissance and name_score >= 80:
                final_score = max(final_score, 95.0)
                matching_type = "NAME_AND_BIRTHDATE"

        niveau_alerte, action_recommandee = classify_alert(
            final_score,
            exact_threshold=settings.exact_threshold,
            probable_threshold=settings.probable_threshold,
            possible_threshold=settings.possible_threshold
        )

        if final_score >= settings.possible_threshold:
            matches.append({
                "sanction_id": str(sanction.id),
                "source_liste": sanction.source_liste,
                "listed_name": listed_name,
                "score": final_score,
                "matching_type": matching_type,
                "niveau_alerte": niveau_alerte,
                "action_recommandee": action_recommandee
            })

            existing_alert = db.query(Alert).filter(
                Alert.client_reference == client_reference,
                Alert.sanction_entry_id == sanction.id,
                Alert.matching_type == matching_type,
                Alert.statut.in_(["GENEREE", "EN_COURS", "ESCALADEE", "CONFIRMEE"])
            ).first()

            if not existing_alert:
                alert = Alert(
                    client_reference=client_reference,
                    client_nom=payload.nom.upper(),
                    client_prenom=payload.prenom.upper() if payload.prenom else None,
                    client_date_naissance=parsed_date,
                    sanction_entry_id=sanction.id,
                    source_liste=sanction.source_liste,
                    matching_score=final_score,
                    matching_type=matching_type,
                    niveau_alerte=niveau_alerte,
                    statut="GENEREE",
                    action_recommandee=action_recommandee
                )

                db.add(alert)
                generated_alerts_count += 1

            else:
                existing_alerts_count += 1

        if final_score > highest_score:
            highest_score = final_score
            global_status = niveau_alerte
            global_action = action_recommandee

    write_audit_log(
        db=db,
        user_identifier="EXTERNAL_API",
        action="API_MATCHING_CLIENT",
        entity_type="ClientScreening",
        entity_id=client_reference,
        description=(
            f"Matching API effectué pour le client {client_full_name}. "
            f"Score maximum : {highest_score}. "
            f"Statut : {global_status}. "
            f"Alertes générées : {generated_alerts_count}. "
            f"Alertes déjà existantes : {existing_alerts_count}."
        ),
        ip_address=None
    )

    db.commit()

    return {
        "success": True,
        "request_id": build_request_id(),
        "timestamp": datetime.utcnow().isoformat(),
        "client": {
            "client_reference": client_reference,
            "nom_complet": client_full_name,
            "nom": payload.nom.upper() if payload.nom else None,
            "prenom": payload.prenom.upper() if payload.prenom else None,
            "date_naissance": parsed_date.isoformat() if parsed_date else None,
            "nationalite": payload.nationalite.upper() if payload.nationalite else None,
            "num_passeport": payload.num_passeport.upper() if payload.num_passeport else None
        },
        "screening_result": {
            "status": global_status,
            "highest_score": float(highest_score),
            "action_recommandee": global_action,
            "generated_alerts_count": generated_alerts_count,
            "existing_alerts_count": existing_alerts_count,
            "matches_count": len(matches)
        },
        "matches": matches,
        "message": "Vérification client terminée."
    }


@router.get("/alerts/{client_reference}")
def external_get_alerts_by_client(
    client_reference: str,
    db: Session = Depends(get_db),
    authorized: bool = Depends(verify_api_key)
):
    alerts = db.query(Alert).filter(
        Alert.client_reference == client_reference
    ).order_by(
        Alert.created_at.desc()
    ).all()

    write_audit_log(
        db=db,
        user_identifier="EXTERNAL_API",
        action="API_GET_ALERTS",
        entity_type="ClientAlerts",
        entity_id=client_reference,
        description=f"Consultation API des alertes du client {client_reference}.",
        ip_address=None
    )

    db.commit()

    return {
        "success": True,
        "request_id": build_request_id(),
        "timestamp": datetime.utcnow().isoformat(),
        "client_reference": client_reference,
        "total_alerts": len(alerts),
        "alerts": [
            {
                "id": str(alert.id),
                "source_liste": alert.source_liste,
                "matching_score": float(alert.matching_score) if alert.matching_score is not None else None,
                "matching_type": alert.matching_type,
                "niveau_alerte": alert.niveau_alerte,
                "statut": alert.statut,
                "action_recommandee": alert.action_recommandee,
                "created_at": alert.created_at.isoformat() if alert.created_at else None,
                "treated_by": alert.treated_by,
                "treated_at": alert.treated_at.isoformat() if alert.treated_at else None,
                "treatment_comment": alert.treatment_comment
            }
            for alert in alerts
        ],
        "message": "Consultation des alertes terminée."
    }

