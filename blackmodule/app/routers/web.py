from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Form, HTTPException, Query, UploadFile, File
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import SanctionEntry, Alert, AuditLog, ImportBatch, User, MatchingSetting
from app.schemas import ClientCheckRequest
from app.services.auth_service import authenticate_user, hash_password, verify_password
from app.services.matching_service import build_full_name, calculate_name_score, classify_alert
from app.services.audit_service import write_audit_log
from app.services.import_service import (
    import_afb_ppe_csv,
    import_ofac_sdn_xml,
    import_un_xml,
    import_eu_csv,
    import_eu_xml,
    import_ofsi_csv,
    import_ofsi_excel,
    import_ofac_consolidated_xml,
    import_france_gel_json,
    import_france_gel_xml
)
from app.services.list_update_service import (
    auto_update_ofac_sdn,
    auto_update_ofac_consolidated,
    auto_update_france_gel,
    auto_update_eu_xml,
    auto_update_un_xml
)
from app.scheduler import get_scheduler_status
from app.services.matching_settings_service import (
    get_or_create_matching_settings,
    update_matching_settings
)

router = APIRouter(prefix="/web", tags=["Web Interface"])
templates = Jinja2Templates(directory="app/templates")


def require_login(request: Request) -> bool:
    return bool(request.session.get("user"))


def get_current_user(request: Request):
    return request.session.get("user")


def require_role(request: Request, allowed_roles: list[str]) -> bool:
    user = get_current_user(request)
    return bool(user and user.get("role") in allowed_roles)


def current_username(request: Request, fallback: str = "SYSTEM") -> str:
    user = get_current_user(request)
    return user.get("username") if user else fallback


def forbidden_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="403.html",
        context={"request": request},
        status_code=403,
    )


def log_access_denied(db: Session, request: Request, route: str, description: str):
    write_audit_log(
        db=db,
        user_identifier=current_username(request, "UNKNOWN"),
        action="ACCESS_DENIED",
        entity_type="WebRoute",
        entity_id=route,
        description=description,
        ip_address=request.client.host if request.client else None,
    )
    db.commit()


def require_admin_or_403(request: Request, db: Session, route: str, description: str):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN"]):
        log_access_denied(db=db, request=request, route=route, description=description)
        return forbidden_page(request)

    return None


@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"request": request, "error": None},
    )


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db=db, username=username, password=password)

    if not user:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"request": request, "error": "Identifiants incorrects ou compte désactivé."},
        )

    request.session["user"] = {
        "id": str(user.id),
        "username": user.username,
        "full_name": user.full_name,
        "role": user.role,
    }

    write_audit_log(
        db=db,
        user_identifier=user.username,
        action="LOGIN_SUCCESS",
        entity_type="User",
        entity_id=str(user.id),
        description=f"Connexion réussie pour l'utilisateur {user.username}.",
        ip_address=request.client.host if request.client else None,
    )
    db.commit()

    return RedirectResponse(url="/web/dashboard", status_code=303)


@router.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    user = request.session.get("user")

    if user:
        write_audit_log(
            db=db,
            user_identifier=user.get("username"),
            action="LOGOUT",
            entity_type="User",
            entity_id=user.get("id"),
            description=f"Déconnexion de l'utilisateur {user.get('username')}.",
            ip_address=request.client.host if request.client else None,
        )
        db.commit()

    request.session.clear()
    return RedirectResponse(url="/web/login", status_code=303)


@router.get("/dashboard")
def web_dashboard(request: Request, db: Session = Depends(get_db)):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    context = {
        "request": request,
        "total_sanctions": db.query(SanctionEntry).count(),
        "active_sanctions": db.query(SanctionEntry).filter(SanctionEntry.statut == "ACTIF").count(),
        "total_alerts": db.query(Alert).count(),
        "alerts_generee": db.query(Alert).filter(Alert.statut == "GENEREE").count(),
        "alerts_confirmee": db.query(Alert).filter(Alert.statut == "CONFIRMEE").count(),
        "alerts_faux_positif": db.query(Alert).filter(Alert.statut == "FAUX_POSITIF").count(),
        "alertes_exactes": db.query(Alert).filter(Alert.niveau_alerte == "ALERTE_EXACTE").count(),
        "alertes_probables": db.query(Alert).filter(Alert.niveau_alerte == "ALERTE_PROBABLE").count(),
        "alertes_possibles": db.query(Alert).filter(Alert.niveau_alerte == "ALERTE_POSSIBLE").count(),
        "total_audit_logs": db.query(AuditLog).count(),
        "recent_alerts": db.query(Alert).order_by(Alert.created_at.desc()).limit(10).all(),
    }

    return templates.TemplateResponse(request=request, name="dashboard.html", context=context)


@router.get("/check-client")
def check_client_page(
    request: Request,
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN", "SUPERVISEUR", "OPERATEUR"]):
        log_access_denied(
            db=db,
            request=request,
            route="/web/check-client",
            description="Tentative d'accès refusée à la vérification client."
        )
        return forbidden_page(request)

    settings = get_or_create_matching_settings(db)

    return templates.TemplateResponse(
        request=request,
        name="check_client.html",
        context={
            "request": request,
            "result": None,
            "form": {},
            "settings": settings
        }
    )


@router.post("/check-client")
def check_client_submit(
    request: Request,
    client_reference: Optional[str] = Form(None),
    nom: str = Form(...),
    prenom: Optional[str] = Form(None),
    date_naissance: Optional[str] = Form(None),
    nationalite: Optional[str] = Form(None),
    num_passeport: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN", "SUPERVISEUR", "OPERATEUR"]):
        log_access_denied(
            db=db,
            request=request,
            route="/web/check-client",
            description="Tentative d'accès refusée à la vérification client.",
        )
        return forbidden_page(request)

    # Récupération des seuils dynamiques
    settings = get_or_create_matching_settings(db)

    # Gestion date de naissance
    parsed_date = None

    if date_naissance:
        try:
            parsed_date = datetime.strptime(date_naissance, "%Y-%m-%d").date()
        except ValueError:
            parsed_date = None

    # Génération automatique référence client si vide
    if not client_reference or not client_reference.strip():
        client_reference = f"WEB-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    client = ClientCheckRequest(
        client_reference=client_reference,
        nom=nom,
        prenom=prenom,
        date_naissance=parsed_date,
        nationalite=nationalite,
        num_passeport=num_passeport,
    )

    client_full_name = build_full_name(client.prenom, client.nom)

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

        # Matching passeport exact
        if client.num_passeport and sanction.num_passeport:
            if client.num_passeport.strip().upper() == sanction.num_passeport.strip().upper():
                final_score = 100.0
                matching_type = "EXACT_PASSPORT"

        # Matching nom + date de naissance
        if client.date_naissance and sanction.date_naissance:
            if client.date_naissance == sanction.date_naissance and name_score >= 80:
                final_score = max(final_score, 95.0)
                matching_type = "NAME_AND_BIRTHDATE"

        niveau_alerte, action_recommandee = classify_alert(
            final_score,
            exact_threshold=settings.exact_threshold,
            probable_threshold=settings.probable_threshold,
            possible_threshold=settings.possible_threshold,
        )

        # On garde les résultats visibles si le score atteint le seuil possible
        if final_score >= settings.possible_threshold:
            matches.append({
                "sanction_id": sanction.id,
                "source_liste": sanction.source_liste,
                "listed_name": listed_name,
                "score": final_score,
                "matching_type": matching_type,
                "niveau_alerte": niveau_alerte,
                "action_recommandee": action_recommandee,
            })

            # Prévention des alertes doublons
            existing_alert = db.query(Alert).filter(
                Alert.client_reference == client.client_reference,
                Alert.sanction_entry_id == sanction.id,
                Alert.matching_type == matching_type,
                Alert.statut.in_(["GENEREE", "EN_COURS", "ESCALADEE", "CONFIRMEE"])
            ).first()

            if not existing_alert:
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
                    action_recommandee=action_recommandee,
                )

                db.add(alert)
                generated_alerts_count += 1

            else:
                existing_alerts_count += 1

        if final_score > highest_score:
            highest_score = final_score
            global_status = niveau_alerte
            global_action = action_recommandee

    current_user = get_current_user(request)
    username = current_user.get("username") if current_user else "SYSTEM"

    write_audit_log(
        db=db,
        user_identifier=username,
        action="WEB_MATCHING_CLIENT",
        entity_type="ClientScreening",
        entity_id=client.client_reference,
        description=(
            f"Matching web effectué pour le client {client_full_name}. "
            f"Score maximum : {highest_score}. "
            f"Statut : {global_status}. "
            f"Alertes générées : {generated_alerts_count}. "
            f"Alertes déjà existantes : {existing_alerts_count}."
        ),
        ip_address=request.client.host if request.client else None,
    )

    db.commit()

    result = {
        "client_reference": client.client_reference,
        "client_name": client_full_name,
        "status": global_status,
        "highest_score": highest_score,
        "action": global_action,
        "matches": matches,
        "existing_alerts_count": existing_alerts_count,
        "generated_alerts_count": generated_alerts_count,
    }

    form = {
        "client_reference": client_reference,
        "nom": nom,
        "prenom": prenom,
        "date_naissance": date_naissance,
        "nationalite": nationalite,
        "num_passeport": num_passeport,
    }

    return templates.TemplateResponse(
        request=request,
        name="check_client.html",
        context={
            "request": request,
            "result": result,
            "form": form,
            "settings": settings,
        },
    )


@router.get("/alerts")
def web_alerts(
    request: Request,
    statut: str | None = Query(None),
    niveau_alerte: str | None = Query(None),
    source_liste: str | None = Query(None),
    client_reference: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    message: str | None = Query(None),
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    query = db.query(Alert)

    current_status = None
    current_niveau = None
    current_source = None
    current_client_reference = None
    current_date_from = None
    current_date_to = None

    if statut:
        current_status = statut.strip().upper()
        query = query.filter(Alert.statut == current_status)

    if niveau_alerte:
        current_niveau = niveau_alerte.strip().upper()
        query = query.filter(Alert.niveau_alerte == current_niveau)

    if source_liste:
        current_source = source_liste.strip().upper()
        query = query.filter(Alert.source_liste == current_source)

    if client_reference:
        current_client_reference = client_reference.strip()
        query = query.filter(Alert.client_reference.ilike(f"%{current_client_reference}%"))

    if date_from:
        try:
            current_date_from = date_from
            parsed_date_from = datetime.strptime(date_from, "%Y-%m-%d")
            query = query.filter(Alert.created_at >= parsed_date_from)
        except ValueError:
            pass

    if date_to:
        try:
            current_date_to = date_to
            parsed_date_to = datetime.strptime(date_to, "%Y-%m-%d")
            parsed_date_to = parsed_date_to.replace(hour=23, minute=59, second=59)
            query = query.filter(Alert.created_at <= parsed_date_to)
        except ValueError:
            pass

    alerts = query.order_by(Alert.created_at.desc()).all()

    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "request": request,
            "alerts": alerts,
            "current_status": current_status,
            "niveau_alerte": current_niveau,
            "source_liste": current_source,
            "client_reference": current_client_reference,
            "date_from": current_date_from,
            "date_to": current_date_to,
            "message": message
        }
    )


@router.get("/alerts/{alert_id}/treat")
def web_treat_alert_page(alert_id: UUID, request: Request, db: Session = Depends(get_db)):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN", "SUPERVISEUR"]):
        log_access_denied(
            db=db,
            request=request,
            route=f"/web/alerts/{alert_id}/treat",
            description="Tentative d'accès refusée au traitement d'une alerte.",
        )
        return forbidden_page(request)

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte introuvable")

    return templates.TemplateResponse(
        request=request,
        name="treat_alert.html",
        context={"request": request, "alert": alert},
    )


@router.post("/alerts/{alert_id}/treat")
def web_treat_alert_submit(
    alert_id: UUID,
    request: Request,
    statut: str = Form(...),
    treated_by: str = Form(...),
    treatment_comment: str = Form(...),
    db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN", "SUPERVISEUR"]):
        log_access_denied(
            db=db,
            request=request,
            route=f"/web/alerts/{alert_id}/treat",
            description="Tentative d'accès refusée au traitement d'une alerte.",
        )
        return forbidden_page(request)

    allowed_statuses = ["GENEREE", "EN_COURS", "FAUX_POSITIF", "CONFIRMEE", "ESCALADEE", "CLOTUREE"]
    new_status = statut.upper()

    if new_status not in allowed_statuses:
        raise HTTPException(status_code=400, detail="Statut invalide")

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte introuvable")

    username = current_username(request, fallback=treated_by)
    alert.statut = new_status
    alert.treated_by = username
    alert.treatment_comment = treatment_comment
    alert.treated_at = datetime.utcnow()

    write_audit_log(
        db=db,
        user_identifier=username,
        action="WEB_TRAITEMENT_ALERTE",
        entity_type="Alert",
        entity_id=str(alert.id),
        description=(
            f"Alerte traitée depuis l'interface web avec le statut {new_status}. "
            f"Commentaire : {treatment_comment}"
        ),
        ip_address=request.client.host if request.client else None,
    )
    db.commit()

    return RedirectResponse(
        url=f"/web/alerts?message=Alerte traitée avec succès : {new_status}",
        status_code=303,
    )


@router.get("/imports")
def web_import_page(request: Request, db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(
        request,
        db,
        route="/web/imports",
        description="Tentative d'accès refusée à la page d'import des listes.",
    )
    if denied_response:
        return denied_response

    return templates.TemplateResponse(
        request=request,
        name="imports.html",
        context={"request": request, "message": None, "success": None, "result": None},
    )


async def process_web_import(
    request: Request,
    db: Session,
    file: UploadFile,
    imported_by: str,
    source_liste: str,
    file_type: str,
    import_function,
    success_message: str,
    audit_action: str,
):
    import_batch = ImportBatch(
        source_liste=source_liste,
        filename=file.filename,
        file_type=file_type,
        status="PENDING",
        imported_by=imported_by,
    )
    db.add(import_batch)
    db.flush()

    try:
        file_content = await file.read()
        result = import_function(db=db, file_content=file_content)

        import_batch.total_records = result["total_records"]
        import_batch.inserted_records = result["inserted_records"]
        import_batch.updated_records = result["updated_records"]
        import_batch.duplicate_records = result["duplicate_records"]
        import_batch.rejected_records = result["rejected_records"]
        import_batch.status = "SUCCESS"

        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action=audit_action,
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=(
                f"{success_message} "
                f"Total : {import_batch.total_records}, "
                f"Insérés : {import_batch.inserted_records}, "
                f"Mis à jour : {import_batch.updated_records}, "
                f"Rejetés : {import_batch.rejected_records}."
            ),
            ip_address=request.client.host if request.client else None,
        )

        db.commit()
        db.refresh(import_batch)

        return templates.TemplateResponse(
            request=request,
            name="imports.html",
            context={"request": request, "message": success_message, "success": True, "result": import_batch},
        )

    except Exception as e:
        db.rollback()

        failed_batch = ImportBatch(
            source_liste=source_liste,
            filename=file.filename,
            file_type=file_type,
            status="FAILED",
            imported_by=imported_by,
            error_message=str(e)[:1000],
        )
        db.add(failed_batch)
        db.flush()

        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action=f"{audit_action}_FAILED",
            entity_type="ImportBatch",
            entity_id=str(failed_batch.id),
            description=f"Échec import {source_liste} : {str(e)[:500]}",
            ip_address=request.client.host if request.client else None,
        )

        db.commit()
        db.refresh(failed_batch)

        return templates.TemplateResponse(
            request=request,
            name="imports.html",
            context={"request": request, "message": f"Erreur pendant l'import : {str(e)}", "success": False, "result": failed_batch},
        )


def check_file_extension(file: UploadFile, extensions: list[str]) -> bool:
    return any(file.filename.lower().endswith(ext) for ext in extensions)


@router.post("/imports/afb-ppe-csv")
async def web_import_afb_ppe_csv(request: Request, imported_by: str = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/imports/afb-ppe-csv", "Tentative d'accès refusée à l'import AFB_PPE CSV.")
    if denied_response:
        return denied_response
    if not check_file_extension(file, [".csv"]):
        return templates.TemplateResponse(request=request, name="imports.html", context={"request": request, "message": "Format invalide. Veuillez importer un fichier CSV.", "success": False, "result": None})
    return await process_web_import(request, db, file, current_username(request, imported_by), "AFB_PPE", "CSV", import_afb_ppe_csv, "Import CSV AFB_PPE effectué avec succès.", "WEB_IMPORT_AFB_PPE_CSV")


@router.post("/imports/ofac-sdn-xml")
async def web_import_ofac_sdn_xml(request: Request, imported_by: str = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/imports/ofac-sdn-xml", "Tentative d'accès refusée à l'import OFAC SDN XML.")
    if denied_response:
        return denied_response
    if not check_file_extension(file, [".xml"]):
        return templates.TemplateResponse(request=request, name="imports.html", context={"request": request, "message": "Format invalide. Veuillez importer un fichier XML OFAC SDN.", "success": False, "result": None})
    return await process_web_import(request, db, file, current_username(request, imported_by), "OFAC_SDN", "XML", import_ofac_sdn_xml, "Import XML OFAC SDN effectué avec succès.", "WEB_IMPORT_OFAC_SDN_XML")


@router.post("/imports/ofac-consolidated-xml")
async def web_import_ofac_consolidated_xml(request: Request, imported_by: str = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/imports/ofac-consolidated-xml", "Tentative d'accès refusée à l'import OFAC Consolidated XML.")
    if denied_response:
        return denied_response
    if not check_file_extension(file, [".xml"]):
        return templates.TemplateResponse(request=request, name="imports.html", context={"request": request, "message": "Format invalide. Veuillez importer un fichier XML OFAC Consolidated.", "success": False, "result": None})
    return await process_web_import(request, db, file, current_username(request, imported_by), "OFAC_CONSOLIDATED", "XML", import_ofac_consolidated_xml, "Import XML OFAC Consolidated effectué avec succès.", "WEB_IMPORT_OFAC_CONSOLIDATED_XML")


@router.post("/imports/un-xml")
async def web_import_un_xml(request: Request, imported_by: str = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/imports/un-xml", "Tentative d'accès refusée à l'import ONU XML.")
    if denied_response:
        return denied_response
    if not check_file_extension(file, [".xml"]):
        return templates.TemplateResponse(request=request, name="imports.html", context={"request": request, "message": "Format invalide. Veuillez importer un fichier XML ONU.", "success": False, "result": None})
    return await process_web_import(request, db, file, current_username(request, imported_by), "ONU", "XML", import_un_xml, "Import XML ONU effectué avec succès.", "WEB_IMPORT_UN_XML")


@router.post("/imports/eu-csv")
async def web_import_eu_csv(request: Request, imported_by: str = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/imports/eu-csv", "Tentative d'accès refusée à l'import UE CSV.")
    if denied_response:
        return denied_response
    if not check_file_extension(file, [".csv"]):
        return templates.TemplateResponse(request=request, name="imports.html", context={"request": request, "message": "Format invalide. Veuillez importer un fichier CSV Union Européenne.", "success": False, "result": None})
    return await process_web_import(request, db, file, current_username(request, imported_by), "UE", "CSV", import_eu_csv, "Import CSV Union Européenne effectué avec succès.", "WEB_IMPORT_EU_CSV")


@router.post("/imports/ofsi-csv")
async def web_import_ofsi_csv(request: Request, imported_by: str = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/imports/ofsi-csv", "Tentative d'accès refusée à l'import OFSI CSV.")
    if denied_response:
        return denied_response
    if not check_file_extension(file, [".csv"]):
        return templates.TemplateResponse(request=request, name="imports.html", context={"request": request, "message": "Format invalide. Veuillez importer un fichier CSV OFSI UK.", "success": False, "result": None})
    return await process_web_import(request, db, file, current_username(request, imported_by), "OFSI", "CSV", import_ofsi_csv, "Import CSV OFSI UK effectué avec succès.", "WEB_IMPORT_OFSI_CSV")


@router.post("/imports/ofsi-excel")
async def web_import_ofsi_excel(request: Request, imported_by: str = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/imports/ofsi-excel", "Tentative d'accès refusée à l'import OFSI Excel.")
    if denied_response:
        return denied_response
    if not check_file_extension(file, [".xls", ".xlsx"]):
        return templates.TemplateResponse(request=request, name="imports.html", context={"request": request, "message": "Format invalide. Veuillez importer un fichier Excel OFSI (.xls ou .xlsx).", "success": False, "result": None})
    file_type = "XLSX" if file.filename.lower().endswith(".xlsx") else "XLS"
    return await process_web_import(request, db, file, current_username(request, imported_by), "OFSI", file_type, import_ofsi_excel, "Import Excel OFSI UK effectué avec succès.", "WEB_IMPORT_OFSI_EXCEL")


@router.post("/imports/france-gel-json")
async def web_import_france_gel_json(request: Request, imported_by: str = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/imports/france-gel-json", "Tentative d'accès refusée à l'import France Gel JSON.")
    if denied_response:
        return denied_response
    if not check_file_extension(file, [".json"]):
        return templates.TemplateResponse(request=request, name="imports.html", context={"request": request, "message": "Format invalide. Veuillez importer un fichier JSON France Gel des Avoirs.", "success": False, "result": None})
    return await process_web_import(request, db, file, current_username(request, imported_by), "FR_GEL", "JSON", import_france_gel_json, "Import JSON France Gel des Avoirs effectué avec succès.", "WEB_IMPORT_FRANCE_GEL_JSON")


@router.post("/imports/france-gel-xml")
async def web_import_france_gel_xml(request: Request, imported_by: str = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/imports/france-gel-xml", "Tentative d'accès refusée à l'import France Gel XML.")
    if denied_response:
        return denied_response
    if not check_file_extension(file, [".xml"]):
        return templates.TemplateResponse(request=request, name="imports.html", context={"request": request, "message": "Format invalide. Veuillez importer un fichier XML France Gel des Avoirs.", "success": False, "result": None})
    return await process_web_import(request, db, file, current_username(request, imported_by), "FR_GEL", "XML", import_france_gel_xml, "Import XML France Gel des Avoirs effectué avec succès.", "WEB_IMPORT_FRANCE_GEL_XML")


@router.get("/sanctions")
def web_sanctions(
    request: Request,
    q: str | None = Query(None),
    source_liste: str | None = Query(None),
    statut: str | None = Query(None),
    db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    query = db.query(SanctionEntry)

    if q:
        search_value = f"%{q.strip()}%"
        query = query.filter(or_(
            SanctionEntry.nom.ilike(search_value),
            SanctionEntry.prenom.ilike(search_value),
            SanctionEntry.nom_complet.ilike(search_value),
            SanctionEntry.num_passeport.ilike(search_value),
        ))

    if source_liste:
        query = query.filter(SanctionEntry.source_liste == source_liste.strip().upper())

    if statut:
        query = query.filter(SanctionEntry.statut == statut.strip().upper())

    sanctions = query.order_by(SanctionEntry.created_at.desc()).all()

    return templates.TemplateResponse(
        request=request,
        name="sanctions.html",
        context={"request": request, "sanctions": sanctions, "q": q, "source_liste": source_liste, "statut": statut},
    )


@router.get("/import-history")
def web_import_history(
    request: Request,
    source_liste: str | None = Query(None),
    status: str | None = Query(None),
    imported_by: str | None = Query(None),
    db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN", "SUPERVISEUR"]):
        log_access_denied(db, request, "/web/import-history", "Tentative d'accès refusée à l'historique des imports.")
        return forbidden_page(request)

    query = db.query(ImportBatch)
    current_source = None
    current_status = None
    current_imported_by = None

    if source_liste:
        current_source = source_liste.strip().upper()
        query = query.filter(ImportBatch.source_liste == current_source)

    if status:
        current_status = status.strip().upper()
        query = query.filter(ImportBatch.status == current_status)

    if imported_by:
        current_imported_by = imported_by.strip()
        query = query.filter(ImportBatch.imported_by.ilike(f"%{current_imported_by}%"))

    imports = query.order_by(ImportBatch.imported_at.desc()).all()

    return templates.TemplateResponse(
        request=request,
        name="import_history.html",
        context={
            "request": request,
            "imports": imports,
            "source_liste": current_source,
            "status": current_status,
            "imported_by": current_imported_by,
        },
    )


@router.get("/audit-logs")
def web_audit_logs(
    request: Request,
    action: str | None = Query(None),
    user_identifier: str | None = Query(None),
    entity_type: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN", "SUPERVISEUR"]):
        log_access_denied(db, request, "/web/audit-logs", "Tentative d'accès refusée au journal d'audit.")
        return forbidden_page(request)

    query = db.query(AuditLog)
    current_action = None
    current_user = None
    current_entity_type = None
    current_date_from = None
    current_date_to = None

    if action:
        current_action = action.upper().strip()
        query = query.filter(AuditLog.action.ilike(f"%{current_action}%"))

    if user_identifier:
        current_user = user_identifier.strip()
        query = query.filter(AuditLog.user_identifier.ilike(f"%{current_user}%"))

    if entity_type:
        current_entity_type = entity_type.strip()
        query = query.filter(AuditLog.entity_type.ilike(f"%{current_entity_type}%"))

    if date_from:
        try:
            current_date_from = date_from
            parsed_from = datetime.strptime(date_from, "%Y-%m-%d")
            query = query.filter(AuditLog.created_at >= parsed_from)
        except ValueError:
            pass

    if date_to:
        try:
            current_date_to = date_to
            parsed_to = datetime.strptime(date_to, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            query = query.filter(AuditLog.created_at <= parsed_to)
        except ValueError:
            pass

    logs = query.order_by(AuditLog.created_at.desc()).limit(500).all()

    return templates.TemplateResponse(
        request=request,
        name="audit_logs.html",
        context={
            "request": request,
            "logs": logs,
            "action": current_action,
            "user_identifier": current_user,
            "entity_type": current_entity_type,
            "date_from": current_date_from,
            "date_to": current_date_to,
        },
    )


@router.get("/users")
def web_users(request: Request, message: str | None = Query(None), db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/users", "Tentative d'accès refusée à la gestion des utilisateurs.")
    if denied_response:
        return denied_response

    users = db.query(User).order_by(User.created_at.desc()).all()
    return templates.TemplateResponse(request=request, name="users.html", context={"request": request, "users": users, "message": message})


@router.post("/users/create")
def web_create_user(
    request: Request,
    username: str = Form(...),
    full_name: str = Form(None),
    email: str = Form(None),
    password: str = Form(...),
    role: str = Form(...),
    db: Session = Depends(get_db),
):
    denied_response = require_admin_or_403(request, db, "/web/users/create", "Tentative d'accès refusée à la création d'utilisateur.")
    if denied_response:
        return denied_response

    allowed_roles = ["ADMIN", "SUPERVISEUR", "OPERATEUR", "LECTEUR"]
    role = role.upper()
    if role not in allowed_roles:
        raise HTTPException(status_code=400, detail="Rôle invalide.")

    if db.query(User).filter(User.username == username.strip()).first():
        return RedirectResponse(url="/web/users?message=Nom utilisateur déjà utilisé", status_code=303)

    if email and db.query(User).filter(User.email == email.strip()).first():
        return RedirectResponse(url="/web/users?message=Email déjà utilisé", status_code=303)

    new_user = User(
        username=username.strip(),
        full_name=full_name.strip() if full_name else None,
        email=email.strip() if email else None,
        password_hash=hash_password(password),
        role=role,
        statut="ACTIF",
    )

    db.add(new_user)
    db.flush()

    write_audit_log(
        db=db,
        user_identifier=current_username(request),
        action="CREATE_USER",
        entity_type="User",
        entity_id=str(new_user.id),
        description=f"Création de l'utilisateur {new_user.username} avec le rôle {new_user.role}.",
        ip_address=request.client.host if request.client else None,
    )
    db.commit()

    return RedirectResponse(url="/web/users?message=Utilisateur créé avec succès", status_code=303)


@router.post("/users/{user_id}/toggle-status")
def web_toggle_user_status(user_id: UUID, request: Request, db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, f"/web/users/{user_id}/toggle-status", "Tentative d'accès refusée à la modification du statut utilisateur.")
    if denied_response:
        return denied_response

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")

    current_user = get_current_user(request)
    if current_user and current_user.get("id") == str(user.id):
        return RedirectResponse(url="/web/users?message=Impossible de désactiver votre propre compte", status_code=303)

    user.statut = "INACTIF" if user.statut == "ACTIF" else "ACTIF"

    write_audit_log(
        db=db,
        user_identifier=current_username(request),
        action="TOGGLE_USER_STATUS",
        entity_type="User",
        entity_id=str(user.id),
        description=f"Changement du statut de l'utilisateur {user.username} vers {user.statut}.",
        ip_address=request.client.host if request.client else None,
    )
    db.commit()

    return RedirectResponse(url="/web/users?message=Statut utilisateur mis à jour", status_code=303)


@router.get("/users/{user_id}/edit")
def web_edit_user_page(user_id: UUID, request: Request, db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, f"/web/users/{user_id}/edit", "Tentative d'accès refusée à la modification utilisateur.")
    if denied_response:
        return denied_response

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")

    return templates.TemplateResponse(request=request, name="edit_user.html", context={"request": request, "user": user})


@router.post("/users/{user_id}/edit")
def web_edit_user_submit(
    user_id: UUID,
    request: Request,
    full_name: str = Form(None),
    email: str = Form(None),
    role: str = Form(...),
    statut: str = Form(...),
    db: Session = Depends(get_db),
):
    denied_response = require_admin_or_403(request, db, f"/web/users/{user_id}/edit", "Tentative d'accès refusée à la modification utilisateur.")
    if denied_response:
        return denied_response

    allowed_roles = ["ADMIN", "SUPERVISEUR", "OPERATEUR", "LECTEUR"]
    allowed_statuses = ["ACTIF", "INACTIF"]
    role = role.upper()
    statut = statut.upper()

    if role not in allowed_roles:
        raise HTTPException(status_code=400, detail="Rôle invalide.")
    if statut not in allowed_statuses:
        raise HTTPException(status_code=400, detail="Statut invalide.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")

    current_user = get_current_user(request)
    if current_user and current_user.get("id") == str(user.id) and statut == "INACTIF":
        return RedirectResponse(url="/web/users?message=Impossible de désactiver votre propre compte", status_code=303)

    old_role = user.role
    old_status = user.statut
    user.full_name = full_name.strip() if full_name else None
    user.email = email.strip() if email else None
    user.role = role
    user.statut = statut

    write_audit_log(
        db=db,
        user_identifier=current_username(request),
        action="UPDATE_USER",
        entity_type="User",
        entity_id=str(user.id),
        description=(
            f"Modification de l'utilisateur {user.username}. "
            f"Ancien rôle : {old_role}, nouveau rôle : {role}. "
            f"Ancien statut : {old_status}, nouveau statut : {statut}."
        ),
        ip_address=request.client.host if request.client else None,
    )
    db.commit()

    return RedirectResponse(url="/web/users?message=Utilisateur modifié avec succès", status_code=303)


@router.get("/change-password")
def change_password_page(request: Request):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    return templates.TemplateResponse(request=request, name="change_password.html", context={"request": request, "message": None, "success": None})


@router.post("/change-password")
def change_password_submit(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/web/login", status_code=303)

    user = db.query(User).filter(User.id == current_user.get("id")).first()
    if not user:
        request.session.clear()
        return RedirectResponse(url="/web/login", status_code=303)

    if not verify_password(old_password, user.password_hash):
        return templates.TemplateResponse(request=request, name="change_password.html", context={"request": request, "message": "Ancien mot de passe incorrect.", "success": False})
    if new_password != confirm_password:
        return templates.TemplateResponse(request=request, name="change_password.html", context={"request": request, "message": "Les deux nouveaux mots de passe ne correspondent pas.", "success": False})
    if len(new_password) < 6:
        return templates.TemplateResponse(request=request, name="change_password.html", context={"request": request, "message": "Le nouveau mot de passe doit contenir au moins 6 caractères.", "success": False})

    user.password_hash = hash_password(new_password)
    write_audit_log(
        db=db,
        user_identifier=user.username,
        action="CHANGE_PASSWORD",
        entity_type="User",
        entity_id=str(user.id),
        description=f"Modification du mot de passe de l'utilisateur {user.username}.",
        ip_address=request.client.host if request.client else None,
    )
    db.commit()

    return templates.TemplateResponse(request=request, name="change_password.html", context={"request": request, "message": "Mot de passe modifié avec succès.", "success": True})


@router.get("/list-updates")
def web_list_updates_page(request: Request, db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/list-updates", "Tentative d'accès refusée à la page de mise à jour des listes.")
    if denied_response:
        return denied_response
    return templates.TemplateResponse(request=request, name="list_updates.html", context={"request": request, "message": None, "success": None, "result": None})


@router.post("/list-updates/ofac-sdn")
def web_update_ofac_sdn(request: Request, db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/list-updates/ofac-sdn", "Tentative d'accès refusée à la mise à jour OFAC SDN.")
    if denied_response:
        return denied_response

    try:
        result = auto_update_ofac_sdn(db=db, imported_by=current_username(request))
        return templates.TemplateResponse(request=request, name="list_updates.html", context={"request": request, "message": "Mise à jour OFAC SDN exécutée avec succès.", "success": True, "result": result})
    except Exception as e:
        return templates.TemplateResponse(request=request, name="list_updates.html", context={"request": request, "message": f"Erreur pendant la mise à jour OFAC SDN : {str(e)}", "success": False, "result": None})


@router.post("/list-updates/ofac-consolidated")
def web_update_ofac_consolidated(request: Request, db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/list-updates/ofac-consolidated", "Tentative d'accès refusée à la mise à jour OFAC Consolidated.")
    if denied_response:
        return denied_response

    try:
        result = auto_update_ofac_consolidated(db=db, imported_by=current_username(request))
        return templates.TemplateResponse(request=request, name="list_updates.html", context={"request": request, "message": "Mise à jour OFAC Consolidated exécutée avec succès.", "success": True, "result": result})
    except Exception as e:
        return templates.TemplateResponse(request=request, name="list_updates.html", context={"request": request, "message": f"Erreur pendant la mise à jour OFAC Consolidated : {str(e)}", "success": False, "result": None})


@router.get("/scheduler-status")
def web_scheduler_status(
    request: Request,
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN"]):
        log_access_denied(
            db=db,
            request=request,
            route="/web/scheduler-status",
            description="Tentative d'accès refusée à la page état scheduler."
        )
        return forbidden_page(request)

    scheduler_status = get_scheduler_status()

    latest_imports = db.query(ImportBatch).filter(
        ImportBatch.source_liste.in_([
            "OFAC_SDN",
            "OFAC_CONSOLIDATED",
            "FR_GEL",
            "UE",
            "ONU",
            "OFSI"
        ])
    ).order_by(
        ImportBatch.imported_at.desc()
    ).limit(10).all()

    monitored_lists = [
        {
            "source": "OFAC_SDN",
            "format": "XML",
            "frequence": "Quotidienne",
            "heure": "02:00 UTC",
            "mode": "Automatique + manuel"
        },
        {
            "source": "OFAC_CONSOLIDATED",
            "format": "XML Advanced",
            "frequence": "Quotidienne",
            "heure": "02:15 UTC",
            "mode": "Automatique + manuel"
        },
        {
            "source": "FR_GEL",
            "format": "JSON / XML",
            "frequence": "Quotidienne",
            "heure": "02:30 UTC",
            "mode": "Automatique + manuel"
        },
        {
            "source": "UE",
            "format": "XML / CSV",
            "frequence": "Hebdomadaire",
            "heure": "Lundi 03:00 UTC",
            "mode": "Automatique + manuel"
        },
        {
            "source": "ONU",
            "format": "XML",
            "frequence": "Hebdomadaire",
            "heure": "Lundi 03:15 UTC",
            "mode": "Automatique + manuel"
        },
        {
            "source": "OFSI / UKSL",
            "format": "Excel / CSV",
            "frequence": "Mensuelle",
            "heure": "1er du mois 03:30 UTC",
            "mode": "À finaliser"
        }
    ]

    return templates.TemplateResponse(
        request=request,
        name="scheduler_status.html",
        context={
            "request": request,
            "scheduler_status": scheduler_status,
            "latest_imports": latest_imports,
            "monitored_lists": monitored_lists
        }
    )

@router.post("/imports/eu-xml")
async def web_import_eu_xml(
    request: Request,
    imported_by: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN"]):
        log_access_denied(
            db=db,
            request=request,
            route="/web/imports/eu-xml",
            description="Tentative d'accès refusée à l'import UE XML."
        )
        return forbidden_page(request)

    current_user = get_current_user(request)
    imported_by = current_user.get("username") if current_user else imported_by

    if not file.filename.lower().endswith(".xml"):
        return templates.TemplateResponse(
            request=request,
            name="imports.html",
            context={
                "request": request,
                "message": "Format invalide. Veuillez importer un fichier XML Union Européenne.",
                "success": False,
                "result": None
            }
        )

    import_batch = ImportBatch(
        source_liste="UE",
        filename=file.filename,
        file_type="XML",
        status="PENDING",
        imported_by=imported_by
    )

    db.add(import_batch)
    db.flush()

    try:
        file_content = await file.read()

        result = import_eu_xml(
            db=db,
            file_content=file_content
        )

        import_batch.total_records = result["total_records"]
        import_batch.inserted_records = result["inserted_records"]
        import_batch.updated_records = result["updated_records"]
        import_batch.duplicate_records = result["duplicate_records"]
        import_batch.rejected_records = result["rejected_records"]
        import_batch.status = "SUCCESS"

        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="WEB_IMPORT_EU_XML",
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=(
                f"Import XML UE depuis l'interface web terminé. "
                f"Total : {import_batch.total_records}, "
                f"Insérés : {import_batch.inserted_records}, "
                f"Mis à jour : {import_batch.updated_records}, "
                f"Rejetés : {import_batch.rejected_records}."
            ),
            ip_address=request.client.host if request.client else None
        )

        db.commit()
        db.refresh(import_batch)

        return templates.TemplateResponse(
            request=request,
            name="imports.html",
            context={
                "request": request,
                "message": "Import XML Union Européenne effectué avec succès.",
                "success": True,
                "result": import_batch
            }
        )

    except Exception as e:
        db.rollback()

        failed_batch = ImportBatch(
            source_liste="UE",
            filename=file.filename,
            file_type="XML",
            status="FAILED",
            imported_by=imported_by,
            error_message=str(e)[:1000]
        )

        db.add(failed_batch)
        db.flush()

        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="WEB_IMPORT_EU_XML_FAILED",
            entity_type="ImportBatch",
            entity_id=str(failed_batch.id),
            description=f"Échec import XML UE : {str(e)[:500]}",
            ip_address=request.client.host if request.client else None
        )

        db.commit()
        db.refresh(failed_batch)

        return templates.TemplateResponse(
            request=request,
            name="imports.html",
            context={
                "request": request,
                "message": f"Erreur pendant l'import UE XML : {str(e)}",
                "success": False,
                "result": failed_batch
            }
        )

@router.get("/data-quality")
def web_data_quality(
    request: Request,
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN", "SUPERVISEUR"]):
        log_access_denied(
            db=db,
            request=request,
            route="/web/data-quality",
            description="Tentative d'accès refusée à la page qualité des données."
        )
        return forbidden_page(request)

    total_sanctions = db.query(SanctionEntry).count()

    missing_full_name = db.query(SanctionEntry).filter(
        (SanctionEntry.nom_complet == None) |
        (SanctionEntry.nom_complet == "")
    ).count()

    missing_source = db.query(SanctionEntry).filter(
        (SanctionEntry.source_liste == None) |
        (SanctionEntry.source_liste == "")
    ).count()

    missing_status = db.query(SanctionEntry).filter(
        (SanctionEntry.statut == None) |
        (SanctionEntry.statut == "")
    ).count()

    missing_hash = db.query(SanctionEntry).filter(
        (SanctionEntry.hash_signature == None) |
        (SanctionEntry.hash_signature == "")
    ).count()

    short_names = db.query(SanctionEntry).filter(
        SanctionEntry.nom_complet != None,
        SanctionEntry.nom_complet != "",
        func.length(SanctionEntry.nom_complet) < 3
    ).count()

    duplicate_hash_rows = db.query(
        SanctionEntry.hash_signature,
        func.count(SanctionEntry.id).label("count")
    ).filter(
        SanctionEntry.hash_signature != None,
        SanctionEntry.hash_signature != ""
    ).group_by(
        SanctionEntry.hash_signature
    ).having(
        func.count(SanctionEntry.id) > 1
    ).all()

    source_stats = db.query(
        SanctionEntry.source_liste,
        func.count(SanctionEntry.id).label("count")
    ).group_by(
        SanctionEntry.source_liste
    ).order_by(
        func.count(SanctionEntry.id).desc()
    ).all()

    recent_problem_entries = db.query(SanctionEntry).filter(
        (
            (SanctionEntry.nom_complet == None) |
            (SanctionEntry.nom_complet == "") |
            (SanctionEntry.source_liste == None) |
            (SanctionEntry.source_liste == "") |
            (SanctionEntry.statut == None) |
            (SanctionEntry.statut == "") |
            (SanctionEntry.hash_signature == None) |
            (SanctionEntry.hash_signature == "")
        )
    ).order_by(
        SanctionEntry.created_at.desc()
    ).limit(50).all()

    quality_score = 100

    if total_sanctions > 0:
        anomaly_total = (
            missing_full_name +
            missing_source +
            missing_status +
            missing_hash +
            short_names +
            len(duplicate_hash_rows)
        )

        quality_score = max(
            0,
            round(100 - ((anomaly_total / total_sanctions) * 100), 2)
        )

    return templates.TemplateResponse(
        request=request,
        name="data_quality.html",
        context={
            "request": request,
            "total_sanctions": total_sanctions,
            "missing_full_name": missing_full_name,
            "missing_source": missing_source,
            "missing_status": missing_status,
            "missing_hash": missing_hash,
            "short_names": short_names,
            "duplicate_hash_count": len(duplicate_hash_rows),
            "source_stats": source_stats,
            "recent_problem_entries": recent_problem_entries,
            "quality_score": quality_score
        }
    )

@router.get("/matching-settings")
def web_matching_settings_page(
    request: Request,
    message: str | None = Query(None),
    success: bool | None = Query(None),
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN", "SUPERVISEUR"]):
        log_access_denied(
            db=db,
            request=request,
            route="/web/matching-settings",
            description="Tentative d'accès refusée aux paramètres de matching."
        )
        return forbidden_page(request)

    settings = get_or_create_matching_settings(db)

    history_logs = db.query(AuditLog).filter(
        AuditLog.action == "UPDATE_MATCHING_SETTINGS"
    ).order_by(
        AuditLog.created_at.desc()
    ).limit(10).all()

    return templates.TemplateResponse(
        request=request,
        name="matching_settings.html",
        context={
            "request": request,
            "settings": settings,
            "message": message,
            "success": success,
            "history_logs": history_logs
        }
    )


@router.post("/matching-settings")
def web_matching_settings_submit(
    request: Request,
    exact_threshold: float = Form(...),
    probable_threshold: float = Form(...),
    possible_threshold: float = Form(...),
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN", "SUPERVISEUR"]):
        log_access_denied(
            db=db,
            request=request,
            route="/web/matching-settings",
            description="Tentative d'accès refusée à la modification des paramètres de matching."
        )
        return forbidden_page(request)

    if not (0 <= possible_threshold <= probable_threshold <= exact_threshold <= 100):
        settings = get_or_create_matching_settings(db)

        history_logs = db.query(AuditLog).filter(
            AuditLog.action == "UPDATE_MATCHING_SETTINGS"
        ).order_by(
            AuditLog.created_at.desc()
        ).limit(10).all()

        return templates.TemplateResponse(
            request=request,
            name="matching_settings.html",
            context={
                "request": request,
                "settings": settings,
                "message": "Paramètres de matching mis à jour avec succès.",
                "success": True,
                "history_logs": history_logs
            }
        )

    current_user = get_current_user(request)
    username = current_user.get("username") if current_user else "SYSTEM"

    old_settings = get_or_create_matching_settings(db)

    old_values = (
        f"Exacte={old_settings.exact_threshold}, "
        f"Probable={old_settings.probable_threshold}, "
        f"Possible={old_settings.possible_threshold}"
    )

    settings = update_matching_settings(
        db=db,
        exact_threshold=exact_threshold,
        probable_threshold=probable_threshold,
        possible_threshold=possible_threshold,
        updated_by=username
    )

    write_audit_log(
        db=db,
        user_identifier=username,
        action="UPDATE_MATCHING_SETTINGS",
        entity_type="MatchingSetting",
        entity_id=str(settings.id),
        description=(
            f"Modification des seuils de matching. "
            f"Anciennes valeurs : {old_values}. "
            f"Nouvelles valeurs : Exacte={exact_threshold}, "
            f"Probable={probable_threshold}, Possible={possible_threshold}."
        ),
        ip_address=request.client.host if request.client else None
    )

    db.commit()

    history_logs = db.query(AuditLog).filter(
        AuditLog.action == "UPDATE_MATCHING_SETTINGS"
    ).order_by(
        AuditLog.created_at.desc()
    ).limit(10).all()

    return templates.TemplateResponse(
        request=request,
        name="matching_settings.html",
        context={
            "request": request,
            "settings": settings,
            "message": "Paramètres de matching mis à jour avec succès.",
            "success": True,
            "history_logs": history_logs
        }
    )

@router.get("/critical-alerts")
def web_critical_alerts(
    request: Request,
    niveau_alerte: str | None = Query(None),
    statut: str | None = Query(None),
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN", "SUPERVISEUR"]):
        log_access_denied(
            db=db,
            request=request,
            route="/web/critical-alerts",
            description="Tentative d'accès refusée à la supervision des alertes critiques."
        )
        return forbidden_page(request)

    query = db.query(Alert).filter(
        Alert.niveau_alerte.in_(["ALERTE_EXACTE", "ALERTE_PROBABLE"]),
        Alert.statut.in_(["GENEREE", "EN_COURS", "ESCALADEE", "CONFIRMEE"])
    )

    current_niveau = None
    current_status = None

    if niveau_alerte:
        current_niveau = niveau_alerte.strip().upper()
        query = query.filter(Alert.niveau_alerte == current_niveau)

    if statut:
        current_status = statut.strip().upper()
        query = query.filter(Alert.statut == current_status)

    critical_alerts = query.order_by(
        Alert.created_at.desc()
    ).all()

    total_critical = len(critical_alerts)

    exact_count = sum(
        1 for alert in critical_alerts
        if alert.niveau_alerte == "ALERTE_EXACTE"
    )

    probable_count = sum(
        1 for alert in critical_alerts
        if alert.niveau_alerte == "ALERTE_PROBABLE"
    )

    return templates.TemplateResponse(
        request=request,
        name="critical_alerts.html",
        context={
            "request": request,
            "alerts": critical_alerts,
            "total_critical": total_critical,
            "exact_count": exact_count,
            "probable_count": probable_count,
            "niveau_alerte": current_niveau,
            "statut": current_status
        }
    )

@router.post("/matching-settings/reset")
def web_matching_settings_reset(
    request: Request,
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN", "SUPERVISEUR"]):
        log_access_denied(
            db=db,
            request=request,
            route="/web/matching-settings/reset",
            description="Tentative d'accès refusée à la réinitialisation des paramètres de matching."
        )
        return forbidden_page(request)

    current_user = get_current_user(request)
    username = current_user.get("username") if current_user else "SYSTEM"

    old_settings = get_or_create_matching_settings(db)

    old_values = (
        f"Exacte={old_settings.exact_threshold}, "
        f"Probable={old_settings.probable_threshold}, "
        f"Possible={old_settings.possible_threshold}"
    )

    settings = update_matching_settings(
        db=db,
        exact_threshold=90.0,
        probable_threshold=75.0,
        possible_threshold=60.0,
        updated_by=username
    )

    write_audit_log(
        db=db,
        user_identifier=username,
        action="RESET_MATCHING_SETTINGS",
        entity_type="MatchingSetting",
        entity_id=str(settings.id),
        description=(
            f"Réinitialisation des seuils de matching aux valeurs par défaut. "
            f"Anciennes valeurs : {old_values}. "
            f"Nouvelles valeurs : Exacte=90.0, Probable=75.0, Possible=60.0."
        ),
        ip_address=request.client.host if request.client else None
    )

    db.commit()

    return RedirectResponse(
        url="/web/matching-settings?message=Seuils restaurés aux valeurs par défaut&success=True",
        status_code=303
    )

@router.get("/profile")
def web_profile(
    request: Request,
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    current_user = get_current_user(request)

    user = db.query(User).filter(
        User.id == current_user.get("id")
    ).first()

    if not user:
        request.session.clear()
        return RedirectResponse(url="/web/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="profile.html",
        context={
            "request": request,
            "user": user
        }
    )

@router.post("/list-updates/france-gel")
def web_update_france_gel(
    request: Request,
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN"]):
        log_access_denied(
            db=db,
            request=request,
            route="/web/list-updates/france-gel",
            description="Tentative d'accès refusée à la mise à jour France Gel."
        )
        return forbidden_page(request)

    current_user = get_current_user(request)
    username = current_user.get("username") if current_user else "SYSTEM"

    try:
        result = auto_update_france_gel(
            db=db,
            imported_by=username
        )

        return templates.TemplateResponse(
            request=request,
            name="list_updates.html",
            context={
                "request": request,
                "message": "Mise à jour France Gel exécutée. Vérifiez l’historique pour le statut détaillé.",
                "success": result.status == "SUCCESS",
                "result": result
            }
        )

    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="list_updates.html",
            context={
                "request": request,
                "message": (
                    "Erreur pendant la mise à jour France Gel. "
                    "Source officielle probablement inaccessible depuis le réseau actuel. "
                    f"Détail : {str(e)}"
                ),
                "success": False,
                "result": None
            }
        )


@router.post("/list-updates/eu")
def web_update_eu(
    request: Request,
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN"]):
        log_access_denied(
            db=db,
            request=request,
            route="/web/list-updates/eu",
            description="Tentative d'accès refusée à la mise à jour UE."
        )
        return forbidden_page(request)

    current_user = get_current_user(request)
    username = current_user.get("username") if current_user else "SYSTEM"

    try:
        result = auto_update_eu_xml(
            db=db,
            imported_by=username
        )

        return templates.TemplateResponse(
            request=request,
            name="list_updates.html",
            context={
                "request": request,
                "message": "Mise à jour UE exécutée avec succès.",
                "success": True,
                "result": result
            }
        )

    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="list_updates.html",
            context={
                "request": request,
                "message": f"Erreur pendant la mise à jour UE : {str(e)}",
                "success": False,
                "result": None
            }
        )


@router.post("/list-updates/un")
def web_update_un(
    request: Request,
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN"]):
        log_access_denied(
            db=db,
            request=request,
            route="/web/list-updates/un",
            description="Tentative d'accès refusée à la mise à jour ONU."
        )
        return forbidden_page(request)

    current_user = get_current_user(request)
    username = current_user.get("username") if current_user else "SYSTEM"

    try:
        result = auto_update_un_xml(
            db=db,
            imported_by=username
        )

        return templates.TemplateResponse(
            request=request,
            name="list_updates.html",
            context={
                "request": request,
                "message": "Mise à jour ONU exécutée avec succès.",
                "success": True,
                "result": result
            }
        )

    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="list_updates.html",
            context={
                "request": request,
                "message": f"Erreur pendant la mise à jour ONU : {str(e)}",
                "success": False,
                "result": None
            }
        )

@router.get("/external-api")
def web_external_api_page(
    request: Request,
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_role(request, ["ADMIN"]):
        log_access_denied(
            db=db,
            request=request,
            route="/web/external-api",
            description="Tentative d'accès refusée à la page API externe."
        )
        return forbidden_page(request)

    recent_api_logs = db.query(AuditLog).filter(
        AuditLog.action.in_([
            "API_MATCHING_CLIENT",
            "API_GET_ALERTS",
            "API_STATUS_CHECK",
            "API_DOCUMENTATION_ACCESS"
        ])
    ).order_by(
        AuditLog.created_at.desc()
    ).limit(10).all()

    endpoints = [
        {
            "method": "GET",
            "path": "/api/external/status",
            "description": "Vérifier l’état de disponibilité de l’API externe."
        },
        {
            "method": "GET",
            "path": "/api/external/documentation",
            "description": "Consulter la documentation technique intégrée."
        },
        {
            "method": "POST",
            "path": "/api/external/check-client",
            "description": "Lancer une vérification client via API."
        },
        {
            "method": "GET",
            "path": "/api/external/alerts/{client_reference}",
            "description": "Consulter les alertes associées à une référence client."
        }
    ]

    total_api_calls = db.query(AuditLog).filter(
        AuditLog.action.in_([
            "API_MATCHING_CLIENT",
            "API_GET_ALERTS",
            "API_STATUS_CHECK",
            "API_DOCUMENTATION_ACCESS"
        ])
    ).count()

    total_api_screenings = db.query(AuditLog).filter(
        AuditLog.action == "API_MATCHING_CLIENT"
    ).count()

    total_api_alerts_views = db.query(AuditLog).filter(
        AuditLog.action == "API_GET_ALERTS"
    ).count()

    total_api_technical_views = db.query(AuditLog).filter(
        AuditLog.action.in_([
            "API_STATUS_CHECK",
            "API_DOCUMENTATION_ACCESS"
        ])
    ).count()

    last_api_call = db.query(AuditLog).filter(
        AuditLog.action.in_([
            "API_MATCHING_CLIENT",
            "API_GET_ALERTS",
            "API_STATUS_CHECK",
            "API_DOCUMENTATION_ACCESS"
        ])
    ).order_by(
        AuditLog.created_at.desc()
    ).first()

    return templates.TemplateResponse(
        request=request,
        name="external_api.html",
        context={
            "request": request,
            "endpoints": endpoints,
            "recent_api_logs": recent_api_logs,
            "api_key_label": "X-API-KEY",
            "api_key_value": "***************",
            "total_api_calls": total_api_calls,
            "total_api_screenings": total_api_screenings,
            "total_api_alerts_views": total_api_alerts_views,
            "total_api_technical_views": total_api_technical_views,
            "last_api_call": last_api_call,
        }
    )