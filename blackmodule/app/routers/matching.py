from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import SanctionEntry, Alert
from app.schemas import ClientCheckRequest, ClientCheckResponse, MatchResult
from app.services.matching_service import (
    build_full_name,
    calculate_name_score,
    classify_alert
)
from app.services.audit_service import write_audit_log


router = APIRouter(
    prefix="/api/matching",
    tags=["Matching"]
)


@router.post("/check-client", response_model=ClientCheckResponse)
def check_client(
    client: ClientCheckRequest,
    db: Session = Depends(get_db)
):
    client_full_name = build_full_name(client.prenom, client.nom)

    sanctions = db.query(SanctionEntry).filter(
        SanctionEntry.statut == "ACTIF"
    ).all()

    matches = []
    highest_score = 0.0
    global_status = "AUCUNE_ALERTE"
    global_action = "OPERATION_AUTORISEE"
    generated_alerts_count = 0

    for sanction in sanctions:
        listed_name = sanction.nom_complet

        if not listed_name:
            listed_name = build_full_name(sanction.prenom, sanction.nom)

        name_score = calculate_name_score(client_full_name, listed_name)

        final_score = name_score
        matching_type = "FUZZY_NAME"

        # Correspondance exacte par passeport
        if client.num_passeport and sanction.num_passeport:
            if client.num_passeport.strip().upper() == sanction.num_passeport.strip().upper():
                final_score = 100.0
                matching_type = "EXACT_PASSPORT"

        # Correspondance forte : nom + date de naissance
        if client.date_naissance and sanction.date_naissance:
            if client.date_naissance == sanction.date_naissance and name_score >= 80:
                final_score = max(final_score, 95.0)
                matching_type = "NAME_AND_BIRTHDATE"

        niveau_alerte, action_recommandee = classify_alert(final_score)

        if final_score >= 60:
            match_result = MatchResult(
                sanction_id=sanction.id,
                source_liste=sanction.source_liste,
                listed_name=listed_name,
                score=final_score,
                matching_type=matching_type,
                niveau_alerte=niveau_alerte,
                action_recommandee=action_recommandee
            )

            matches.append(match_result)

            alert = Alert(
                client_reference=client.client_reference,
                client_nom=client.nom.upper(),
                client_prenom=client.prenom.upper() if client.prenom else None,
                client_date_naissance=client.date_naissance,
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

        if final_score > highest_score:
            highest_score = final_score
            global_status = niveau_alerte
            global_action = action_recommandee

    # Audit du matching client
    write_audit_log(
        db=db,
        user_identifier="SYSTEM",
        action="MATCHING_CLIENT",
        entity_type="ClientScreening",
        entity_id=client.client_reference,
        description=(
            f"Matching effectué pour le client {client_full_name}. "
            f"Score maximum : {highest_score}. "
            f"Statut : {global_status}. "
            f"Alertes générées : {generated_alerts_count}."
        ),
        ip_address=None
    )

    db.commit()

    return ClientCheckResponse(
        client_reference=client.client_reference,
        client_name=client_full_name,
        status=global_status,
        highest_score=highest_score,
        action=global_action,
        matches=matches
    )