from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert
from app.schemas import ClientCheckRequest, ClientCheckResponse, MatchResult
from app.services.matching_service import (
    build_full_name,
    classify_alert,
    evaluate_candidate,
    select_matching_candidates,
)
from app.services.matching_settings_service import get_or_create_matching_settings
from app.services.audit_service import write_audit_log
from app.services.api_auth import require_permission
from app.services.authorization_service import PERMISSION_SCREEN_CLIENT
from app.services.performance import log_slow_operation, performance_timer


router = APIRouter(
    prefix="/api/matching",
    tags=["Matching"]
)


@router.post("/check-client", response_model=ClientCheckResponse)
def check_client(
    client: ClientCheckRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_SCREEN_CLIENT))
):
    started_at = performance_timer()
    client_full_name = build_full_name(client.prenom, client.nom)
    settings = get_or_create_matching_settings(db)

    candidates = select_matching_candidates(
        db, client_full_name, client.num_passeport, client.document_number
    )

    matches = []
    highest_score = 0.0
    global_status = "AUCUNE_ALERTE"
    global_action = "OPERATION_AUTORISEE"
    generated_alerts_count = 0

    for sanction, listed_name, name_score in candidates:
        evaluation = evaluate_candidate(
            sanction, client_full_name, listed_name, name_score,
            date_naissance=client.date_naissance,
            nationalite=client.nationalite,
            passport_number=client.num_passeport,
            document_number=client.document_number,
        )
        final_score = evaluation.score
        matching_type = evaluation.matching_type

        niveau_alerte, action_recommandee = classify_alert(
            final_score,
            exact_threshold=settings.exact_threshold,
            probable_threshold=settings.probable_threshold,
            possible_threshold=settings.possible_threshold,
            matching_type=matching_type,
        )

        if final_score >= settings.possible_threshold:
            match_result = MatchResult(
                sanction_id=sanction.id,
                source_liste=sanction.source_liste,
                listed_name=listed_name,
                score=final_score,
                matching_type=matching_type,
                niveau_alerte=niveau_alerte,
                action_recommandee=action_recommandee,
                explanation=list(evaluation.explanation),
                name_score=evaluation.name_score,
            )

            matches.append(match_result)

            alert = Alert(
                client_reference=client.client_reference,
                client_nom=client.nom.upper(),
                client_prenom=client.prenom.upper() if client.prenom else None,
                client_date_naissance=client.date_naissance,
                client_nationalite=client.nationalite.upper() if client.nationalite else None,
                client_num_passeport=client.num_passeport.upper() if client.num_passeport else None,
                client_num_piece=client.document_number.upper() if client.document_number else None,
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
        user_identifier=user.get("username"),
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

    log_slow_operation(
        "api_matching_check_client",
        started_at,
        result_count=len(matches),
        candidate_count=len(candidates),
    )

    return ClientCheckResponse(
        client_reference=client.client_reference,
        client_name=client_full_name,
        status=global_status,
        highest_score=highest_score,
        action=global_action,
        matches=matches
    )
