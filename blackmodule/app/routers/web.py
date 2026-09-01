import json
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Form, HTTPException, Query, UploadFile, File
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import func

from app.database import get_db
from app.models import ApprovalRequest, SanctionEntry, SanctionAlias, Alert, AlertDecisionHistory, AuditLog, ImportBatch, ListVersion, ListVersionActivation, ListVersionEntry, User, MatchingSetting, InternalListHistory
from app.schemas import ClientCheckRequest
from app.services.auth_service import authenticate_user, hash_password, verify_password
from app.services.authorization_service import (
    ALL_ROLES, PERMISSION_LISTS_IMPORT, PERMISSION_MANAGE_LISTS, PERMISSION_MANAGE_MATCHING_SETTINGS,
    PERMISSION_MANAGE_TECHNICAL_CONFIGURATION, PERMISSION_MANAGE_USERS,
    PERMISSION_REVIEW_FOUR_EYES, PERMISSION_SCREEN_CLIENT, PERMISSION_TREAT_ALERTS,
    PERMISSION_VIEW_ALERTS, PERMISSION_VIEW_APPROVALS, PERMISSION_VIEW_AUDIT, PERMISSION_VIEW_CRITICAL_ALERTS,
    PERMISSION_VIEW_LISTS, PERMISSION_LISTS_VIEW, PERMISSION_SANCTIONS_VIEW, ROLE_ADMIN_TECHNIQUE,
    PERMISSION_INTERNAL_LISTS_VIEW, PERMISSION_INTERNAL_LISTS_CREATE, PERMISSION_INTERNAL_LISTS_EDIT,
    PERMISSION_INTERNAL_LISTS_SUBMIT, PERMISSION_INTERNAL_LISTS_VALIDATE,
    PERMISSION_INTERNAL_LISTS_SENSITIVE_VIEW,
    has_permission, permissions_for_role, refresh_session_user, role_label, session_user_payload,
)
from app.services.approval_service import (
    OP_ALERT_TREATMENT, OP_LIST_VERSION_RESTORE, OP_MATCHING_SETTINGS, PENDING, create_approval_request,
    queue_restore_approval, review_approval_request,
)
from app.services.list_version_service import get_active_version, is_version_restorable
from app.services.matching_service import (
    build_full_name, classify_alert, evaluate_candidate, select_matching_candidates,
)
from app.services.audit_service import write_audit_log
from app.services.alert_analysis_service import build_alert_analysis
from app.services.alert_decision_service import (
    AlertDecisionConflict, PENDING_DECISION, request_alert_decision,
)
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
    import_france_gel_xml,
    import_uksl_csv
)
from app.services.list_update_service import (
    auto_update_ofac_sdn,
    auto_update_ofac_consolidated,
    auto_update_france_gel,
    auto_update_eu_xml,
    auto_update_un_xml,
    auto_update_uksl_csv,
    get_list_freshness,
    queue_official_update,
)
from app.scheduler import enqueue_manual_update, enqueue_restore_approval, get_scheduler_status
from app.security import get_csrf_token
from app.services.performance import log_slow_operation, performance_timer
from app.services.matching_settings_service import (
    get_or_create_matching_settings,
    update_matching_settings
)
from app.services.internal_list_service import (
    ACTIVE as INTERNAL_ACTIVE, DRAFT as INTERNAL_DRAFT, INTERNAL_CATEGORIES,
    category_label, create_internal_entry, request_entry_change, serialize_internal_entry,
    submit_internal_entry, OP_INTERNAL_LIST_CHANGE,
)

router = APIRouter(prefix="/web", tags=["Web Interface"])
templates = Jinja2Templates(directory="app/templates")
templates.env.globals["csrf_token"] = get_csrf_token
templates.env.globals["permissions_for_role"] = permissions_for_role
templates.env.globals["role_label"] = role_label

LIST_SOURCE_LABELS = {"OFAC_CONSOLIDATED": "OFAC Consolidated", "OFAC_SDN": "OFAC SDN", "FR_GEL": "France Gel", "UN": "ONU", "ONU": "ONU", "EU": "Union européenne", "UE": "Union européenne", "UKSL": "UK Sanctions List"}
VERSION_STATUS_LABELS = {"ACTIVE": "Active", "ARCHIVED": "Archivée"}
CHANGE_TYPE_LABELS = {"ADDED": "Ajout", "AJOUT": "Ajout", "MODIFIED": "Modification", "MODIFICATION": "Modification", "DELISTED": "Radiation", "RADIATION": "Radiation", "REACTIVATED": "Réactivation", "REACTIVATION": "Réactivation"}
INTERNAL_RISK_LABELS = {"ELEVE": "Élevé", "MOYEN": "Moyen", "FAIBLE": "Faible"}


def list_source_label(source_liste: str | None) -> str:
    return LIST_SOURCE_LABELS.get(source_liste or "", category_label(source_liste or ""))


def format_web_datetime(value) -> str:
    return value.strftime("%d/%m/%Y %H:%M") if value else "Non disponible"


def format_file_size(value) -> str:
    if value is None:
        return "Non disponible"
    if value < 1024:
        return f"{value} o"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} Ko"
    return f"{value / (1024 * 1024):.2f} Mo"


def approval_target_labels(db: Session, approvals: list[ApprovalRequest]) -> dict[str, str]:
    """Return business labels only; technical identifiers stay out of the main table."""
    internal_ids = [
        approval.target_entity_id for approval in approvals
        if approval.target_entity_type == "InternalSanctionEntry"
    ]
    internal_entries = {
        str(entry.id): entry
        for entry in db.query(SanctionEntry).filter(
            SanctionEntry.id.in_(internal_ids), SanctionEntry.is_internal_list.is_(True)
        ).all()
    } if internal_ids else {}
    alert_ids = []
    for approval in approvals:
        if approval.target_entity_type == "Alert":
            try:
                alert_ids.append(UUID(str(approval.target_entity_id)))
            except (TypeError, ValueError, AttributeError):
                continue
    alert_targets = {
        str(alert.id): alert
        for alert in db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
    } if alert_ids else {}
    generic_labels = {
        "Alert": "Alerte", "MatchingSetting": "Paramètres de matching",
        "ListVersion": "Version de liste", "InternalSanctionEntry": "Fiche interne",
    }
    labels = {}
    for approval in approvals:
        if approval.target_entity_type == "InternalSanctionEntry":
            entry = internal_entries.get(str(approval.target_entity_id))
            if entry:
                full_name = (entry.nom_complet or " ".join(
                    part for part in (entry.nom, entry.prenom) if part
                )).strip()
                labels[str(approval.id)] = f"{full_name or 'Fiche interne'} \u2014 {category_label(entry.source_liste)}"
                continue
        if approval.target_entity_type == "Alert":
            alert = alert_targets.get(str(approval.target_entity_id))
            if alert:
                reference = alert.client_reference or "Sans référence"
                source = alert.source_liste or "Source inconnue"
                labels[str(approval.id)] = f"Alerte {reference} — {source}"
                continue
        labels[str(approval.id)] = generic_labels.get(
            approval.target_entity_type, "Cible associée"
        )
    return labels


def approval_alert_links(db: Session, approvals: list[ApprovalRequest]) -> dict[str, str]:
    alert_ids = []
    for approval in approvals:
        if approval.target_entity_type == "Alert":
            try:
                alert_ids.append(UUID(str(approval.target_entity_id)))
            except (TypeError, ValueError, AttributeError):
                continue
    existing_ids = {
        str(alert.id) for alert in db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
    } if alert_ids else set()
    return {
        str(approval.id): str(approval.target_entity_id)
        for approval in approvals
        if approval.target_entity_type == "Alert"
        and str(approval.target_entity_id) in existing_ids
    }


def approval_internal_entry_links(db: Session, approvals: list[ApprovalRequest]) -> dict[str, str]:
    """Expose a detail link only for an existing internal-list target."""
    internal_ids = [
        approval.target_entity_id for approval in approvals
        if approval.target_entity_type == "InternalSanctionEntry"
    ]
    existing_ids = {
        str(entry.id)
        for entry in db.query(SanctionEntry).filter(
            SanctionEntry.id.in_(internal_ids), SanctionEntry.is_internal_list.is_(True)
        ).all()
    } if internal_ids else set()
    return {
        str(approval.id): str(approval.target_entity_id)
        for approval in approvals
        if approval.target_entity_type == "InternalSanctionEntry"
        and str(approval.target_entity_id) in existing_ids
    }


def approval_operation_labels(approvals: list[ApprovalRequest]) -> dict[str, str]:
    """Present the business operation, including the specific internal transition."""
    labels = {
        "MATCHING_SETTINGS_UPDATE": "Modification des seuils",
        "ALERT_TREATMENT": "Décision sur alerte",
        "LIST_VERSION_RESTORE": "Restauration d'une version de liste",
    }
    internal_actions = {
        "ACTIVATE": "Cr\u00e9ation", "UPDATE": "Modification", "SUSPEND": "Suspension",
        "REACTIVATE": "R\u00e9activation", "RADIATE": "Radiation",
    }
    rendered = {}
    for approval in approvals:
        if approval.operation_type == OP_INTERNAL_LIST_CHANGE:
            try:
                action = json.loads(approval.new_values or "{}").get("action")
            except (TypeError, json.JSONDecodeError):
                action = None
            rendered[str(approval.id)] = internal_actions.get(action, "Modification")
        else:
            rendered[str(approval.id)] = labels.get(approval.operation_type, approval.operation_type)
    return rendered


_INTERNAL_HISTORY_FIELDS = {
    "nom": "Nom", "prenom": "Prénom", "nom_complet": "Nom complet", "aliases": "Alias",
    "type_entite": "Type de personne", "date_naissance": "Date de naissance",
    "lieu_naissance": "Lieu de naissance", "nationalite": "Nationalité", "pays": "Pays",
    "document_type": "Type de pièce", "document_number": "Numéro de pièce", "num_passeport": "Passeport",
    "autres_documents": "Autres documents", "source_reference": "Référence source",
    "risk_level": "Niveau de risque", "motif_sanction": "Motif d'inscription",
    "compliance_comment": "Commentaire conformité", "date_inscription": "Date d'inscription",
    "date_suppression": "Date de fin", "ppe_type": "Type PPE", "ppe_function": "Fonction PPE",
    "ppe_institution": "Institution PPE", "ppe_country": "Pays d'exercice PPE",
    "ppe_function_start_date": "Début de fonction PPE", "ppe_function_end_date": "Fin de fonction PPE",
    "ppe_status": "Statut PPE", "ppe_relationship": "Proche / associé",
}
_INTERNAL_HISTORY_VALUES = {
    "PERSONNE_PHYSIQUE": "Personne physique", "PERSONNE_MORALE": "Personne morale",
    "BROUILLON": "Brouillon", "EN_ATTENTE_VALIDATION": "En attente de validation",
    "ACTIF": "Actif", "SUSPENDUE": "Suspendue", "RADIEE": "Radiée",
    "FAIBLE": "Faible", "MOYEN": "Moyen", "ELEVE": "Élevé",
    "ACTUELLE": "Actuelle", "ANCIENNE": "Ancienne",
    "ACTIVATE": "Activation", "UPDATE": "Modification", "SUSPEND": "Suspension",
    "REACTIVATE": "Réactivation", "RADIATE": "Radiation",
}
_INTERNAL_HISTORY_ACTIONS = {
    "CREATION": "Création", "MODIFICATION_BROUILLON": "Modification du brouillon",
    "SOUMISSION": "Demande de validation", "REJET": "Demande rejetée",
    "VALIDATION_ACTIVATE": "Activation validée", "VALIDATION_UPDATE": "Modification validée",
    "VALIDATION_SUSPEND": "Suspension validée", "VALIDATION_REACTIVATE": "Réactivation validée",
    "VALIDATION_RADIATE": "Radiation validée",
}


def _history_json(value):
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value) if value else {}
    except (TypeError, json.JSONDecodeError):
        return {}


def _history_value(value):
    if value in (None, "", [], {}):
        return "Non renseigné"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "Non renseigné"
    if isinstance(value, datetime):
        return value.strftime("%d/%m/%Y %H:%M")
    if isinstance(value, str):
        if value.strip().casefold() in {"none", "null"}:
            return "Non renseigné"
        try:
            parsed = datetime.fromisoformat(value)
            return parsed.strftime("%d/%m/%Y %H:%M" if "T" in value or " " in value else "%d/%m/%Y")
        except ValueError:
            pass
    return _INTERNAL_HISTORY_VALUES.get(str(value), str(value))


def _history_comparable(value):
    if value in (None, "", [], {}):
        return None
    if isinstance(value, str) and value.strip().casefold() in {"none", "null"}:
        return None
    return value


def _present_internal_history(history: list[dict]) -> list[dict]:
    """Presentation-only view of persisted history JSON for the sensitive web page."""
    presented = []
    for item in history:
        old, new = _history_json(item.get("old_values")), _history_json(item.get("new_values"))
        action = item.get("action", "")
        proposed = new.get("values") if isinstance(new.get("values"), dict) else None
        if proposed is not None:
            compared = {key: proposed[key] for key in proposed if key in _INTERNAL_HISTORY_FIELDS}
            if "aliases" in new:
                compared["aliases"] = new["aliases"]
            new = {**old, **compared}
            fields = compared.keys()
        else:
            fields = _INTERNAL_HISTORY_FIELDS.keys()
        changes = [
            {"field": _INTERNAL_HISTORY_FIELDS[key], "old": _history_value(old.get(key)), "new": _history_value(new.get(key))}
            for key in fields
            if action == "CREATION" and _history_comparable(new.get(key)) is not None
            or action != "CREATION" and _history_comparable(old.get(key)) != _history_comparable(new.get(key))
        ]
        summary = None
        if action == "CREATION":
            details = "; ".join(f"{change['field']} : {change['new']}" for change in changes[:6])
            summary = f"Fiche créée en brouillon{f' — {details}' if details else '.'}"
            changes = []
        summary = summary or {
            "CREATION": "Fiche créée en brouillon.",
            "REJET": "Demande rejetée : les valeurs en vigueur restent inchangées.",
            "VALIDATION_ACTIVATE": "Fiche activée après validation par un second utilisateur habilité.",
            "VALIDATION_SUSPEND": "Fiche suspendue après validation.",
            "VALIDATION_REACTIVATE": "Fiche réactivée après validation.",
            "VALIDATION_RADIATE": "Fiche radiée après validation.",
        }.get(action)
        if not changes and action == "SOUMISSION":
            requested = _INTERNAL_HISTORY_VALUES.get(str(_history_json(item.get("new_values")).get("action", "")), "Validation demandée")
            summary = f"{requested} demandée."
        presented.append({
            **item, "action_label": _INTERNAL_HISTORY_ACTIONS.get(action, action.replace("_", " ").title()),
            "created_at_display": _history_value(item.get("created_at")),
            "changes": changes, "summary": summary or "Aucune donnée métier modifiée.",
        })
    return presented


def _format_trace_datetime(value) -> str:
    return value.strftime("%d/%m/%Y %H:%M") if isinstance(value, datetime) else "\u2014"


def _internal_traceability(entry: dict) -> list[dict]:
    """Presentation-only traceability from persisted entry fields and history."""
    rejection = next(
        (item for item in reversed(entry.get("history", [])) if item.get("action") == "REJET"),
        None,
    )
    return [
        {"action": "Cr\u00e9ation", "user": entry.get("created_by") or "\u2014", "when": _format_trace_datetime(entry.get("created_at"))},
        {"action": "Soumission", "user": entry.get("submitted_by") or "\u2014", "when": _format_trace_datetime(entry.get("submitted_at"))},
        {"action": "Validation", "user": entry.get("validated_by") or "\u2014", "when": _format_trace_datetime(entry.get("validated_at"))},
        {"action": "Derni\u00e8re modification", "user": entry.get("updated_by") or "\u2014", "when": _format_trace_datetime(entry.get("updated_at"))},
        {
            "action": "Rejet", "user": (rejection or {}).get("performed_by") or "\u2014",
            "when": _format_trace_datetime((rejection or {}).get("created_at")),
        },
    ]


def _queue_web_official_update(request: Request, db: Session, source_key: str):
    """Return immediately; the existing scheduler performs the long import."""
    username = current_username(request)
    try:
        batch = queue_official_update(db, source_key, username)
        enqueue_manual_update(source_key, str(batch.id), username)
        return templates.TemplateResponse(
            request=request, name="list_updates.html", context={
                "request": request,
                "message": "Mise a jour programmee. Consultez l'historique pour son statut.",
                "success": True, "result": batch,
            },
        )
    except Exception as error:
        db.rollback()
        return templates.TemplateResponse(
            request=request, name="list_updates.html", context={
                "request": request, "message": f"Impossible de programmer la mise a jour : {error}",
                "success": False, "result": None,
            },
        )


def require_login(request: Request) -> bool:
    return bool(get_current_user(request))


def get_current_user(request: Request):
    stored_user = request.session.get("user")
    user = refresh_session_user(stored_user)
    if user and user != stored_user:
        request.session["user"] = user
    return user


def require_permission(request: Request, permission: str) -> bool:
    return has_permission(get_current_user(request), permission)


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


def not_found_page(
    request: Request,
    *,
    title: str,
    message: str,
    return_url: str,
    return_label: str,
):
    """Return a user-facing web 404 instead of an API-style JSON response."""
    return templates.TemplateResponse(
        request=request,
        name="404.html",
        context={
            "request": request,
            "title": title,
            "message": message,
            "return_url": return_url,
            "return_label": return_label,
        },
        status_code=404,
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

    if route.startswith("/web/users"):
        permission = PERMISSION_MANAGE_USERS
    elif route.startswith("/web/import"):
        permission = PERMISSION_LISTS_IMPORT
    elif route.startswith("/web/list-updates"):
        permission = PERMISSION_MANAGE_LISTS
    else:
        permission = PERMISSION_MANAGE_TECHNICAL_CONFIGURATION

    if not require_permission(request, permission):
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
    result = authenticate_user(db=db, username=username, password=password)

    if not result.user:
        write_audit_log(
            db=db,
            user_identifier=username.strip() or None,
            action="LOGIN_FAILED",
            entity_type="User",
            entity_id=None,
            description="Tentative de connexion refusée.",
            ip_address=request.client.host if request.client else None,
        )
        if result.locked_now:
            write_audit_log(
                db=db,
                user_identifier=username.strip() or None,
                action="ACCOUNT_LOCKED",
                entity_type="User",
                entity_id=None,
                description="Compte verrouillé après cinq échecs de connexion.",
                ip_address=request.client.host if request.client else None,
            )
        db.commit()
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"request": request, "error": "Identifiants incorrects ou compte désactivé."},
        )

    user = result.user

    request.session["user"] = session_user_payload(user)
    request.session["last_activity_at"] = user.last_activity_at.isoformat()
    request.session["last_activity_persisted_at"] = user.last_activity_at.isoformat()

    write_audit_log(
        db=db,
        user_identifier=user.username,
        action="LOGIN_SUCCESS",
        entity_type="User",
        entity_id=str(user.id),
        description=f"Connexion réussie pour l'utilisateur {user.username}.",
        ip_address=request.client.host if request.client else None,
    )
    if user.username == "admin":
        write_audit_log(
            db=db,
            user_identifier=user.username,
            action="BOOTSTRAP_ADMIN_LOGIN",
            entity_type="User",
            entity_id=str(user.id),
            description="Utilisation du compte technique bootstrap.",
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


def build_daily_alert_trend(db: Session, days: int = 30):
    today = datetime.utcnow().date()
    start_date = today - timedelta(days=days - 1)

    rows = (
        db.query(
            func.date(Alert.created_at).label("day"),
            func.count(Alert.id).label("count"),
        )
        .filter(Alert.created_at >= start_date)
        .group_by(func.date(Alert.created_at))
        .all()
    )

    counts_by_day = {row.day: row.count for row in rows}

    trend = []
    for i in range(days):
        day = start_date + timedelta(days=i)
        trend.append({"date": day.isoformat(), "count": counts_by_day.get(day, 0)})

    return trend


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
        "alert_trend": build_daily_alert_trend(db),
    }

    return templates.TemplateResponse(request=request, name="dashboard.html", context=context)


def calculate_age(birth_date):
    if not birth_date:
        return None

    today = datetime.utcnow().date()

    return (
        today.year
        - birth_date.year
        - ((today.month, today.day) < (birth_date.month, birth_date.day))
    )


@router.get("/check-client")
def check_client_page(
    request: Request,
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_permission(request, PERMISSION_SCREEN_CLIENT):
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
    type_piece: Optional[str] = Form(None),
    num_piece: Optional[str] = Form(None),
    date_naissance: Optional[str] = Form(None),
    age: Optional[str] = Form(None),
    ville_residence: Optional[str] = Form(None),
    nationalite: Optional[str] = Form(None),
    pays_residence: Optional[str] = Form(None),
    num_passeport: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    started_at = performance_timer()
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_permission(request, PERMISSION_SCREEN_CLIENT):
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

    computed_age = calculate_age(parsed_date)

    if age:
        try:
            client_age = int(age)
        except ValueError:
            client_age = computed_age
    else:
        client_age = computed_age

    # Génération automatique référence client si vide
    if not client_reference or not client_reference.strip():
        client_reference = f"WEB-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    passport_reference = num_passeport
    document_reference = num_piece
    if not passport_reference and (type_piece or "").strip().upper() == "PASSEPORT":
        passport_reference = num_piece
        document_reference = None

    client = ClientCheckRequest(
        client_reference=client_reference,
        nom=nom,
        prenom=prenom,
        date_naissance=parsed_date,
        nationalite=nationalite,
        num_passeport=passport_reference,
        document_number=document_reference,
    )

    client_full_name = build_full_name(client.prenom, client.nom)

    candidates = select_matching_candidates(
        db, client_full_name, client.num_passeport, client.document_number
    )

    matches = []
    highest_score = 0.0
    global_status = "AUCUNE_ALERTE"
    global_action = "OPERATION_AUTORISEE"
    generated_alerts_count = 0
    existing_alerts_count = 0

    active_alert_keys = set()
    if candidates:
        active_alert_keys = set(db.query(
            Alert.sanction_entry_id, Alert.matching_type
        ).filter(
            Alert.client_reference == client.client_reference,
            Alert.sanction_entry_id.in_([entry.id for entry, _, _ in candidates]),
            Alert.statut.in_(["GENEREE", "EN_COURS", "ESCALADEE", "CONFIRMEE"]),
        ).all())

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

        # On garde les résultats visibles si le score atteint le seuil possible
        if final_score >= settings.possible_threshold:
            matches.append({
                "sanction_id": sanction.id,
                "source_liste": sanction.source_liste,
                "listed_name": listed_name,
                "sanction_nom": sanction.nom,
                "sanction_prenom": sanction.prenom,
                "sanction_nom_complet": sanction.nom_complet,
                "sanction_type_entite": sanction.type_entite,
                "sanction_date_naissance": sanction.date_naissance.isoformat() if sanction.date_naissance else None,
                "sanction_nationalite": sanction.nationalite,
                "sanction_pays": sanction.pays,
                "sanction_num_passeport": sanction.num_passeport,
                "sanction_motif": sanction.motif_sanction,
                "score": final_score,
                "matching_type": matching_type,
                "niveau_alerte": niveau_alerte,
                "action_recommandee": action_recommandee,
                "explanation": list(evaluation.explanation),
                "name_score": evaluation.name_score,
            })

            # Prévention des alertes doublons
            if (sanction.id, matching_type) not in active_alert_keys:
                alert = Alert(
                    client_reference=client.client_reference,
                    client_nom=client.nom.upper(),
                    client_prenom=client.prenom.upper() if client.prenom else None,
                    client_date_naissance=client.date_naissance,
                    client_nationalite=nationalite.upper() if nationalite else None,
                    client_pays_residence=pays_residence.upper() if pays_residence else None,
                    client_ville_residence=ville_residence.upper() if ville_residence else None,
                    client_type_piece=type_piece.upper() if type_piece else None,
                    client_num_piece=num_piece.upper() if num_piece else None,
                    client_num_passeport=num_passeport.upper() if num_passeport else None,
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

    log_slow_operation(
        "web_matching_check_client",
        started_at,
        result_count=len(matches),
        candidate_count=len(candidates),
    )

    result = {
        "client_reference": client.client_reference,
        "client_name": client_full_name,
        "client_details": {
            "client_reference": client.client_reference,
            "nom": nom.upper() if nom else None,
            "prenom": prenom.upper() if prenom else None,
            "type_piece": type_piece.upper() if type_piece else None,
            "num_piece": num_piece.upper() if num_piece else None,
            "num_passeport": num_passeport.upper() if num_passeport else None,
            "date_naissance": parsed_date.isoformat() if parsed_date else None,
            "age": client_age,
            "ville_residence": ville_residence.upper() if ville_residence else None,
            "nationalite": nationalite.upper() if nationalite else None,
            "pays_residence": pays_residence.upper() if pays_residence else None,
        },
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
        "type_piece": type_piece,
        "num_piece": num_piece,
        "date_naissance": date_naissance,
        "age": age,
        "ville_residence": ville_residence,
        "nationalite": nationalite,
        "pays_residence": pays_residence,
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
    sort_by: str | None = Query(None),
    sort_dir: str | None = Query(None),
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_permission(request, PERMISSION_VIEW_ALERTS):
        log_access_denied(db, request, "/web/alerts", "Tentative d'accès refusée aux alertes.")
        return forbidden_page(request)

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

    sort_columns = {
        "reference": Alert.client_reference,
        "score": Alert.matching_score,
        "niveau": Alert.niveau_alerte,
        "statut": Alert.statut,
        "source": Alert.source_liste,
        "date": Alert.created_at,
    }
    current_sort_by = sort_by if sort_by in sort_columns else "date"
    current_sort_dir = "asc" if sort_dir == "asc" else "desc"
    sort_column = sort_columns[current_sort_by]
    query = query.order_by(sort_column.asc() if current_sort_dir == "asc" else sort_column.desc())

    alerts = query.all()

    counts_by_niveau = {"ALERTE_EXACTE": 0, "ALERTE_PROBABLE": 0, "ALERTE_POSSIBLE": 0}
    for alert in alerts:
        if alert.niveau_alerte in counts_by_niveau:
            counts_by_niveau[alert.niveau_alerte] += 1

    active_filters = {
        "statut": current_status,
        "niveau_alerte": current_niveau,
        "source_liste": current_source,
        "client_reference": current_client_reference,
        "date_from": current_date_from,
        "date_to": current_date_to,
    }

    def sort_url(field: str) -> str:
        next_dir = "desc" if (current_sort_by == field and current_sort_dir == "asc") else "asc"
        query_params = {k: v for k, v in active_filters.items() if v}
        query_params["sort_by"] = field
        query_params["sort_dir"] = next_dir
        return "/web/alerts?" + urlencode(query_params)

    sort_links = {field: sort_url(field) for field in sort_columns}
    sort_arrows = {
        field: ("▲" if current_sort_dir == "asc" else "▼") if current_sort_by == field else ""
        for field in sort_columns
    }

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
            "message": message,
            "total_count": len(alerts),
            "counts_by_niveau": counts_by_niveau,
            "sort_links": sort_links,
            "sort_arrows": sort_arrows,
        }
    )


@router.get("/alerts/{alert_id}/treat")
def web_treat_alert_page(alert_id: UUID, request: Request, db: Session = Depends(get_db)):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_permission(request, PERMISSION_TREAT_ALERTS):
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

    sanction_entry = None
    if alert.sanction_entry_id:
        sanction_entry = db.query(SanctionEntry).options(
            selectinload(SanctionEntry.aliases)
        ).filter(SanctionEntry.id == alert.sanction_entry_id).first()
        if sanction_entry:
            write_audit_log(
                db=db,
                user_identifier=current_username(request),
                action="VIEW_SANCTION_DETAIL",
                entity_type="SanctionEntry",
                entity_id=str(sanction_entry.id),
                description="Consultation détaillée d'une entrée de sanction depuis une alerte.",
                ip_address=request.client.host if request.client else None,
            )
            db.commit()

    previous_alerts_count = db.query(Alert).filter(
        Alert.client_reference == alert.client_reference,
        Alert.id != alert.id
    ).count() if alert.client_reference else 0
    alert_analysis = build_alert_analysis(db, alert)
    decision_history = db.query(AlertDecisionHistory).filter(
        AlertDecisionHistory.alert_id == alert.id,
    ).order_by(AlertDecisionHistory.initiated_at.desc()).all()
    pending_decision = next(
        (item for item in decision_history if item.decision_status == PENDING_DECISION), None,
    )
    write_audit_log(
        db, current_username(request), "VIEW_ALERT_ANALYSIS", "Alert", str(alert.id),
        "Consultation de l'analyse consolidée; chaque source reste indépendante.",
        request.client.host if request.client else None,
    )
    db.commit()

    return templates.TemplateResponse(
        request=request,
        name="treat_alert.html",
        context={
            "request": request,
            "alert": alert,
            "sanction_entry": sanction_entry,
            "client_age": calculate_age(alert.client_date_naissance),
            "sanction_age": calculate_age(sanction_entry.date_naissance) if sanction_entry else None,
            "previous_alerts_count": previous_alerts_count,
            "alert_analysis": alert_analysis,
            "decision_history": decision_history,
            "pending_decision": pending_decision,
        },
    )


@router.post("/alerts/{alert_id}/treat")
def web_treat_alert_submit(
    alert_id: UUID,
    request: Request,
    statut: str = Form(...),
    treated_by: str = Form(...),
    treatment_comment: str = Form(...),
    return_to: str = Form(None),
    db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_permission(request, PERMISSION_TREAT_ALERTS):
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

    alert = db.query(Alert).filter(Alert.id == alert_id).with_for_update().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte introuvable")

    try:
        outcome, _ = request_alert_decision(
            db, alert=alert, new_status=new_status, reason=treatment_comment,
            actor=get_current_user(request),
            ip_address=request.client.host if request.client else None,
        )
        db.commit()
    except (AlertDecisionConflict, ValueError) as exc:
        db.rollback()
        return RedirectResponse(
            url=f"/web/alerts/{alert_id}/treat?{urlencode({'message': str(exc)})}",
            status_code=303,
        )

    redirect_base = return_to if return_to and return_to.startswith("/web/") else "/web/alerts"

    return RedirectResponse(
        url=(
            f"{redirect_base}?message=Décision soumise à validation par un second utilisateur"
            if outcome == PENDING_DECISION
            else f"{redirect_base}?message=Alerte traitée avec succès : {new_status}"
        ),
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


@router.post("/imports/uksl-csv")
async def web_import_uksl_csv(
    request: Request,
    imported_by: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_permission(request, PERMISSION_LISTS_IMPORT):
        log_access_denied(
            db=db,
            request=request,
            route="/web/imports",
            description="Tentative d'accès refusée à l'import UKSL."
        )
        return forbidden_page(request)

    current_user = get_current_user(request)
    imported_by = current_user.get("username") if current_user else imported_by

    if not file.filename.lower().endswith(".csv"):
        return templates.TemplateResponse(
            request=request,
            name="imports.html",
            context={
                "request": request,
                "message": "Format invalide. Veuillez importer un fichier CSV UK Sanctions List.",
                "success": False,
                "result": None
            }
        )

    import_batch = ImportBatch(
        source_liste="UKSL",
        filename=file.filename,
        file_type="CSV",
        status="PENDING",
        imported_by=imported_by
    )

    db.add(import_batch)
    db.flush()

    try:
        file_content = await file.read()

        result = import_uksl_csv(
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
            action="WEB_IMPORT_UKSL_CSV",
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=(
                f"Import CSV UK Sanctions List depuis l'interface web terminé. "
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
                "message": "Import CSV UK Sanctions List effectué avec succès.",
                "success": True,
                "result": import_batch
            }
        )

    except Exception as e:
        db.rollback()

        failed_batch = ImportBatch(
            source_liste="UKSL",
            filename=file.filename,
            file_type="CSV",
            status="FAILED",
            imported_by=imported_by,
            error_message=str(e)[:1000]
        )

        db.add(failed_batch)
        db.flush()

        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="WEB_IMPORT_UKSL_CSV_FAILED",
            entity_type="ImportBatch",
            entity_id=str(failed_batch.id),
            description=f"Échec import CSV UKSL depuis l'interface web : {str(e)[:500]}",
            ip_address=request.client.host if request.client else None
        )

        db.commit()
        db.refresh(failed_batch)

        return templates.TemplateResponse(
            request=request,
            name="imports.html",
            context={
                "request": request,
                "message": f"Erreur pendant l'import UKSL : {str(e)}",
                "success": False,
                "result": failed_batch
            }
        )

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


SANCTIONS_PAGE_SIZE = 50


@router.get("/internal-lists")
def web_internal_lists(
    request: Request, category: str | None = Query(None), status: str | None = Query(None),
    q: str | None = Query(None), db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_INTERNAL_LISTS_VIEW):
        log_access_denied(db, request, "/web/internal-lists", "Accès refusé aux listes internes.")
        return forbidden_page(request)
    query = db.query(SanctionEntry).filter(SanctionEntry.is_internal_list.is_(True))
    current = get_current_user(request)
    can_view_sensitive = has_permission(current, PERMISSION_INTERNAL_LISTS_SENSITIVE_VIEW)
    if category:
        query = query.filter(SanctionEntry.source_liste == category.upper())
    if status:
        query = query.filter(SanctionEntry.internal_status == status.upper())
    if q:
        value = f"%{q.strip()}%"
        searchable = [SanctionEntry.nom.ilike(value), SanctionEntry.nom_complet.ilike(value)]
        if can_view_sensitive:
            searchable.append(SanctionEntry.source_reference.ilike(value))
        query = query.filter(or_(*searchable))
    records = query.options(selectinload(SanctionEntry.aliases)).order_by(SanctionEntry.updated_at.desc()).all()
    entries = [serialize_internal_entry(entry, include_sensitive=can_view_sensitive) for entry in records]
    all_entries = db.query(SanctionEntry).filter(SanctionEntry.is_internal_list.is_(True)).all()
    return templates.TemplateResponse(request=request, name="internal_lists.html", context={
        "request": request, "entries": entries, "categories": INTERNAL_CATEGORIES,
        "selected_category": category or "", "selected_status": status or "", "q": q or "",
        "summary": {"total": len(all_entries), "active": sum(e.internal_status == INTERNAL_ACTIVE for e in all_entries),
                    "pending": sum(e.internal_status == "EN_ATTENTE_VALIDATION" for e in all_entries),
                    "suspended": sum(e.internal_status == "SUSPENDUE" for e in all_entries),
                    "delisted": sum(e.internal_status == "RADIEE" for e in all_entries)},
        "can_create": has_permission(current, PERMISSION_INTERNAL_LISTS_CREATE),
        "can_edit": has_permission(current, PERMISSION_INTERNAL_LISTS_EDIT),
        "can_submit": has_permission(current, PERMISSION_INTERNAL_LISTS_SUBMIT),
        "can_view_sensitive": can_view_sensitive,
        "risk_labels": INTERNAL_RISK_LABELS,
    })


@router.get("/internal-lists/new")
def web_new_internal_list(request: Request, db: Session = Depends(get_db)):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_INTERNAL_LISTS_CREATE):
        log_access_denied(db, request, "/web/internal-lists/new", "Création interne refusée.")
        return forbidden_page(request)
    current = get_current_user(request)
    return templates.TemplateResponse(request=request, name="internal_list_form.html", context={
        "request": request,
        "categories": INTERNAL_CATEGORIES,
        "can_view_sensitive": has_permission(current, PERMISSION_INTERNAL_LISTS_SENSITIVE_VIEW),
    })


@router.get("/internal-lists/import")
def web_import_internal_lists(request: Request, db: Session = Depends(get_db)):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_INTERNAL_LISTS_CREATE):
        log_access_denied(db, request, "/web/internal-lists/import", "Import interne refusé.")
        return forbidden_page(request)
    return templates.TemplateResponse(request=request, name="internal_list_import.html", context={
        "request": request,
        "categories": INTERNAL_CATEGORIES,
    })


@router.post("/internal-lists")
def web_create_internal_list(
    request: Request, category: str = Form(...), nom: str = Form(...), prenom: str | None = Form(None),
    aliases: str | None = Form(None), type_entite: str | None = Form(None),
    date_naissance: str | None = Form(None), lieu_naissance: str | None = Form(None),
    nationalite: str | None = Form(None), pays: str | None = Form(None),
    document_type: str | None = Form(None), document_number: str | None = Form(None),
    num_passeport: str | None = Form(None), reference: str | None = Form(None),
    risk_level: str | None = Form(None), motif: str | None = Form(None),
    compliance_comment: str | None = Form(None), date_inscription: str | None = Form(None),
    date_suppression: str | None = Form(None), ppe_type: str | None = Form(None),
    ppe_function: str | None = Form(None), ppe_institution: str | None = Form(None),
    ppe_country: str | None = Form(None), ppe_function_start_date: str | None = Form(None),
    ppe_function_end_date: str | None = Form(None), ppe_status: str | None = Form(None),
    ppe_relationship: str | None = Form(None),
    db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_INTERNAL_LISTS_CREATE):
        log_access_denied(db, request, "/web/internal-lists", "Création interne refusée.")
        return forbidden_page(request)
    try:
        entry = create_internal_entry(
            db, category=category, actor=current_username(request),
            aliases=[item.strip() for item in (aliases or "").replace("\n", ",").split(",") if item.strip()],
            values={
                "nom": nom, "prenom": prenom, "type_entite": type_entite,
                "date_naissance": date_naissance, "lieu_naissance": lieu_naissance,
                "nationalite": nationalite, "pays": pays,
                "document_type": document_type, "document_number": document_number,
                "num_passeport": num_passeport, "source_reference": reference,
                "risk_level": risk_level, "motif_sanction": motif,
                "compliance_comment": compliance_comment, "date_inscription": date_inscription,
                "date_suppression": date_suppression, "ppe_type": ppe_type,
                "ppe_function": ppe_function, "ppe_institution": ppe_institution,
                "ppe_country": ppe_country, "ppe_function_start_date": ppe_function_start_date,
                "ppe_function_end_date": ppe_function_end_date, "ppe_status": ppe_status,
                "ppe_relationship": ppe_relationship,
            },
        )
        db.commit()
        return RedirectResponse(url=f"/web/internal-lists/{entry.id}?message=Fiche+brouillon+créée", status_code=303)
    except ValueError as exc:
        db.rollback()
        return RedirectResponse(url=f"/web/internal-lists/new?message={str(exc)}", status_code=303)


@router.get("/internal-lists/{entry_id}/edit")
def web_edit_internal_list(entry_id: UUID, request: Request, db: Session = Depends(get_db)):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_INTERNAL_LISTS_EDIT):
        log_access_denied(db, request, f"/web/internal-lists/{entry_id}/edit", "Modification interne refusée.")
        return forbidden_page(request)
    entry = db.query(SanctionEntry).options(selectinload(SanctionEntry.aliases)).filter(
        SanctionEntry.id == entry_id, SanctionEntry.is_internal_list.is_(True)
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Fiche interne introuvable.")
    if entry.internal_status not in {INTERNAL_DRAFT, INTERNAL_ACTIVE}:
        raise HTTPException(status_code=409, detail="Cette fiche ne peut pas être modifiée dans son statut actuel.")
    return templates.TemplateResponse(request=request, name="internal_list_form.html", context={
        "request": request, "categories": INTERNAL_CATEGORIES,
        "entry": serialize_internal_entry(entry, include_sensitive=True),
        "is_edit": True, "form_action": f"/web/internal-lists/{entry.id}/edit",
        "page_title": "Modifier la fiche interne",
        "page_subtitle": "Les modifications d'une fiche active sont soumises à validation.",
        "submit_label": "Enregistrer les modifications",
        "can_view_sensitive": True,
    })


@router.post("/internal-lists/{entry_id}/edit")
def web_update_internal_list(
    entry_id: UUID, request: Request, nom: str = Form(...), prenom: str | None = Form(None),
    aliases: str | None = Form(None), type_entite: str | None = Form(None),
    date_naissance: str | None = Form(None), lieu_naissance: str | None = Form(None),
    nationalite: str | None = Form(None), pays: str | None = Form(None),
    document_type: str | None = Form(None), document_number: str | None = Form(None),
    num_passeport: str | None = Form(None), reference: str | None = Form(None),
    risk_level: str | None = Form(None), motif: str | None = Form(None),
    compliance_comment: str | None = Form(None), date_inscription: str | None = Form(None),
    date_suppression: str | None = Form(None), ppe_type: str | None = Form(None),
    ppe_function: str | None = Form(None), ppe_institution: str | None = Form(None),
    ppe_country: str | None = Form(None), ppe_function_start_date: str | None = Form(None),
    ppe_function_end_date: str | None = Form(None), ppe_status: str | None = Form(None),
    ppe_relationship: str | None = Form(None), db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_INTERNAL_LISTS_EDIT):
        log_access_denied(db, request, f"/web/internal-lists/{entry_id}/edit", "Modification interne refusée.")
        return forbidden_page(request)
    entry = db.query(SanctionEntry).options(selectinload(SanctionEntry.aliases)).filter(
        SanctionEntry.id == entry_id, SanctionEntry.is_internal_list.is_(True)
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Fiche interne introuvable.")
    if entry.internal_status not in {INTERNAL_DRAFT, INTERNAL_ACTIVE}:
        raise HTTPException(status_code=409, detail="Cette fiche ne peut pas être modifiée dans son statut actuel.")
    values = {
        "nom": nom, "prenom": prenom, "type_entite": type_entite,
        "date_naissance": date_naissance, "lieu_naissance": lieu_naissance,
        "nationalite": nationalite, "pays": pays,
        "document_type": document_type, "document_number": document_number,
        "num_passeport": num_passeport, "source_reference": reference,
        "risk_level": risk_level, "motif_sanction": motif,
        "compliance_comment": compliance_comment, "date_inscription": date_inscription,
        "date_suppression": date_suppression, "ppe_type": ppe_type,
        "ppe_function": ppe_function, "ppe_institution": ppe_institution,
        "ppe_country": ppe_country, "ppe_function_start_date": ppe_function_start_date,
        "ppe_function_end_date": ppe_function_end_date, "ppe_status": ppe_status,
        "ppe_relationship": ppe_relationship,
    }
    try:
        request_entry_change(
            db, entry=entry, actor=get_current_user(request), action="UPDATE", values=values,
            aliases=[item.strip() for item in (aliases or "").replace("\n", ",").split(",") if item.strip()],
            comment=None, ip_address=request.client.host if request.client else None,
        )
        db.commit()
        message = "Modifications enregistrées" if entry.internal_status == INTERNAL_DRAFT else "Modifications soumises à validation"
        return RedirectResponse(url=f"/web/internal-lists/{entry.id}?message={message.replace(' ', '+')}", status_code=303)
    except ValueError as exc:
        db.rollback()
        return RedirectResponse(url=f"/web/internal-lists/{entry_id}/edit?message={str(exc)}", status_code=303)


@router.get("/internal-lists/{entry_id}")
def web_internal_list_detail(entry_id: UUID, request: Request, db: Session = Depends(get_db)):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_INTERNAL_LISTS_VIEW):
        log_access_denied(db, request, f"/web/internal-lists/{entry_id}", "Consultation interne refusée.")
        return forbidden_page(request)
    current = get_current_user(request)
    can_view_sensitive = has_permission(current, PERMISSION_INTERNAL_LISTS_SENSITIVE_VIEW)
    options = [selectinload(SanctionEntry.aliases)]
    if can_view_sensitive:
        options.append(selectinload(SanctionEntry.internal_history))
    entry = db.query(SanctionEntry).options(*options).filter(
        SanctionEntry.id == entry_id, SanctionEntry.is_internal_list.is_(True)
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Fiche interne introuvable.")
    return_context = request.query_params.get("from")
    if return_context not in {"sanctions", "internal-lists"}:
        return_context = "internal-lists"
    write_audit_log(db, current_username(request), "VIEW_INTERNAL_LIST_DETAIL", "InternalSanctionEntry", str(entry.id),
                    f"Consultation fiche interne; rôle={current.get('role')}; catégorie={entry.source_liste}.",
                    request.client.host if request.client else None)
    db.commit()
    detail_entry = serialize_internal_entry(entry, include_sensitive=can_view_sensitive)
    if can_view_sensitive:
        detail_entry["history"] = _present_internal_history(detail_entry["history"])
        detail_entry["traceability"] = _internal_traceability(detail_entry)
    can_edit = has_permission(current, PERMISSION_INTERNAL_LISTS_EDIT)
    can_submit = has_permission(current, PERMISSION_INTERNAL_LISTS_SUBMIT)
    pending_action = None
    if can_edit or can_submit:
        pending_approval = db.query(ApprovalRequest).filter(
            ApprovalRequest.operation_type == OP_INTERNAL_LIST_CHANGE,
            ApprovalRequest.target_entity_id == str(entry.id),
            ApprovalRequest.status == PENDING,
        ).order_by(ApprovalRequest.created_at.desc()).first()
        if pending_approval:
            try:
                pending_action = json.loads(pending_approval.new_values or "{}").get("action")
            except (TypeError, json.JSONDecodeError):
                pending_action = "PENDING"
    return templates.TemplateResponse(request=request, name="internal_list_detail.html", context={
        "request": request,
        "entry": detail_entry,
        "category_label": category_label(entry.source_liste),
        "can_edit": can_edit,
        "can_submit": can_submit,
        "can_view_sensitive": can_view_sensitive,
        "pending_action": pending_action,
        "return_context": return_context,
        "risk_labels": INTERNAL_RISK_LABELS,
    })


@router.post("/internal-lists/{entry_id}/submit")
def web_submit_internal_list(entry_id: UUID, request: Request, comment: str | None = Form(None), db: Session = Depends(get_db)):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_INTERNAL_LISTS_SUBMIT):
        return forbidden_page(request)
    entry = db.query(SanctionEntry).filter(SanctionEntry.id == entry_id, SanctionEntry.is_internal_list.is_(True)).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Fiche interne introuvable.")
    try:
        submit_internal_entry(db, entry=entry, actor=get_current_user(request), comment=comment,
                              ip_address=request.client.host if request.client else None)
        db.commit()
        return RedirectResponse(
            url=f"/web/internal-lists/{entry_id}?{urlencode({'message': 'Demande de soumission envoyée pour validation', 'success': '1'})}",
            status_code=303,
        )
    except ValueError as exc:
        db.rollback()
        return RedirectResponse(url=f"/web/internal-lists/{entry_id}?message={str(exc)}", status_code=303)


@router.post("/internal-lists/{entry_id}/lifecycle")
def web_internal_list_lifecycle(entry_id: UUID, request: Request, action: str = Form(...), comment: str | None = Form(None), db: Session = Depends(get_db)):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_INTERNAL_LISTS_EDIT):
        return forbidden_page(request)
    entry = db.query(SanctionEntry).filter(SanctionEntry.id == entry_id, SanctionEntry.is_internal_list.is_(True)).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Fiche interne introuvable.")
    try:
        request_entry_change(db, entry=entry, actor=get_current_user(request), action=action.upper(), values={}, aliases=None,
                             comment=comment, ip_address=request.client.host if request.client else None)
        db.commit()
        action_labels = {
            "SUSPEND": "suspension", "REACTIVATE": "réactivation", "RADIATE": "radiation",
        }
        action_label = action_labels.get(action.upper(), "transition")
        return RedirectResponse(
            url=f"/web/internal-lists/{entry_id}?{urlencode({'message': f'Demande de {action_label} envoyée pour validation', 'success': '1'})}",
            status_code=303,
        )
    except ValueError as exc:
        db.rollback()
        return RedirectResponse(url=f"/web/internal-lists/{entry_id}?message={str(exc)}", status_code=303)


@router.get("/sanctions")
def web_sanctions(
    request: Request,
    q: str | None = Query(None),
    source_liste: str | None = Query(None),
    statut: str | None = Query(None),
    page: int = Query(1, ge=1),
    db: Session = Depends(get_db),
):
    started_at = performance_timer()
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_permission(request, PERMISSION_SANCTIONS_VIEW):
        log_access_denied(db, request, "/web/sanctions", "Tentative d'acces refusee aux sanctions.")
        return forbidden_page(request)

    query = db.query(SanctionEntry)
    if not require_permission(request, PERMISSION_INTERNAL_LISTS_SENSITIVE_VIEW):
        query = query.filter(SanctionEntry.is_internal_list.is_(False))

    if q:
        search_value = f"%{q.strip()}%"
        query = query.filter(or_(
            SanctionEntry.nom.ilike(search_value),
            SanctionEntry.prenom.ilike(search_value),
            SanctionEntry.nom_complet.ilike(search_value),
            SanctionEntry.num_passeport.ilike(search_value),
            SanctionEntry.aliases.any(SanctionAlias.alias.ilike(search_value)),
        ))

    if source_liste:
        query = query.filter(SanctionEntry.source_liste == source_liste.strip().upper())

    if statut:
        query = query.filter(SanctionEntry.statut == statut.strip().upper())

    total_count = query.count()
    total_pages = max(1, (total_count + SANCTIONS_PAGE_SIZE - 1) // SANCTIONS_PAGE_SIZE)
    page = min(page, total_pages)

    sanctions = (
        query.options(selectinload(SanctionEntry.aliases))
        .order_by(SanctionEntry.created_at.desc())
        .offset((page - 1) * SANCTIONS_PAGE_SIZE)
        .limit(SANCTIONS_PAGE_SIZE)
        .all()
    )

    log_slow_operation(
        "web_sanctions",
        started_at,
        result_count=len(sanctions),
    )

    return templates.TemplateResponse(
        request=request,
        name="sanctions.html",
        context={
            "request": request,
            "sanctions": sanctions,
            "q": q,
            "source_liste": source_liste,
            "statut": statut,
            "page": page,
            "total_pages": total_pages,
            "total_count": total_count,
            "page_size": SANCTIONS_PAGE_SIZE,
        },
    )


@router.get("/sanctions/{sanction_id}")
def web_sanction_detail(
    sanction_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Render a read-only detail page for an official sanction entry."""
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_permission(request, PERMISSION_SANCTIONS_VIEW):
        log_access_denied(
            db, request, f"/web/sanctions/{sanction_id}",
            "Tentative d'acces refusee au detail d'une sanction officielle.",
        )
        return forbidden_page(request)

    try:
        parsed_sanction_id = UUID(sanction_id)
    except ValueError:
        return not_found_page(
            request,
            title="Fiche de sanction introuvable",
            message="Cette fiche n'existe pas, a été retirée ou n'est plus disponible.",
            return_url="/web/sanctions",
            return_label="Retour aux sanctions",
        )

    sanction = db.query(SanctionEntry).options(
        selectinload(SanctionEntry.aliases)
    ).filter(
        SanctionEntry.id == parsed_sanction_id,
        SanctionEntry.is_internal_list.is_(False),
    ).first()
    if not sanction:
        return not_found_page(
            request=request,
            title="Fiche de sanction introuvable",
            message="Cette fiche n'existe pas, a été retirée ou n'est plus disponible.",
            return_url="/web/sanctions",
            return_label="Retour aux sanctions",
        )

    active_version = get_active_version(db, sanction.source_liste)
    latest_import = db.query(ImportBatch).filter(
        ImportBatch.source_liste == sanction.source_liste
    ).order_by(ImportBatch.imported_at.desc()).first()

    write_audit_log(
        db=db,
        user_identifier=current_username(request),
        action="VIEW_SANCTION_DETAIL",
        entity_type="SanctionEntry",
        entity_id=str(sanction.id),
        description="Consultation détaillée d'une entrée de sanction officielle.",
        ip_address=request.client.host if request.client else None,
    )
    db.commit()

    return templates.TemplateResponse(
        request=request,
        name="sanction_detail.html",
        context={
            "request": request,
            "sanction": sanction,
            "source_label": list_source_label(sanction.source_liste),
            "active_version": active_version,
            "latest_import": latest_import,
            "format_datetime": format_web_datetime,
            "format_file_size": format_file_size,
        },
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

    if not require_permission(request, PERMISSION_VIEW_LISTS):
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

    if not require_permission(request, PERMISSION_VIEW_AUDIT):
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

    allowed_roles = ALL_ROLES
    role = role.upper()
    if role not in allowed_roles:
        raise HTTPException(status_code=400, detail="Rôle invalide.")

    if len(password) < 6:
        return RedirectResponse(url="/web/users?message=Le mot de passe doit contenir au moins 6 caractères", status_code=303)

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
        role_assigned_at=datetime.utcnow(),
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

    next_status = "INACTIF" if user.statut == "ACTIF" else "ACTIF"
    if next_status == "INACTIF" and user.role == ROLE_ADMIN_TECHNIQUE:
        remaining_admins = db.query(User).filter(
            User.role == ROLE_ADMIN_TECHNIQUE,
            User.statut == "ACTIF",
            User.id != user.id,
        ).count()
        if remaining_admins == 0:
            return RedirectResponse(url="/web/users?message=Conservez au moins un administrateur technique actif", status_code=303)
    user.statut = next_status

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

    allowed_roles = ALL_ROLES
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

    if (statut == "INACTIF" or role != ROLE_ADMIN_TECHNIQUE) and user.role == ROLE_ADMIN_TECHNIQUE:
        remaining_admins = db.query(User).filter(
            User.role == ROLE_ADMIN_TECHNIQUE,
            User.statut == "ACTIF",
            User.id != user.id,
        ).count()
        if remaining_admins == 0:
            return RedirectResponse(url="/web/users?message=Conservez au moins un administrateur technique actif", status_code=303)

    old_role = user.role
    old_status = user.statut
    user.full_name = full_name.strip() if full_name else None
    user.email = email.strip() if email else None
    user.role = role
    user.statut = statut
    if old_role != role:
        user.role_assigned_at = datetime.utcnow()

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


@router.post("/users/{user_id}/unlock")
def web_unlock_user(user_id: UUID, request: Request, db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(
        request, db, f"/web/users/{user_id}/unlock", "Tentative de déverrouillage non autorisée."
    )


@router.get("/list-versions")
def web_list_versions(
    request: Request,
    source_liste: str | None = Query(None),
    etat: str | None = Query(None),
    restaurable: str | None = Query(None),
    db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_VIEW_LISTS):
        log_access_denied(db, request, "/web/list-versions", "Tentative d'accès refusée aux versions de listes.")
        return forbidden_page(request)

    selected_source = source_liste.strip().upper() if source_liste else None
    selected_status = etat.strip().upper() if etat else None
    selected_restorable = restaurable.strip().lower() if restaurable else None
    all_versions = db.query(ListVersion).order_by(ListVersion.created_at.desc()).limit(200).all()
    all_legacy_batches = db.query(ImportBatch).filter(
        ImportBatch.status == "SUCCESS",
        ImportBatch.file_hash.is_not(None),
    ).order_by(ImportBatch.imported_at.desc()).limit(200).all()
    version_batch_ids = {version.import_batch_id for version in all_versions if version.import_batch_id}
    all_legacy_batches = [batch for batch in all_legacy_batches if batch.id not in version_batch_ids]
    version_rows = []
    for version in all_versions:
        is_restorable = is_version_restorable(version)
        if (selected_source and version.source_liste != selected_source) or (selected_status and selected_status != version.status):
            continue
        if (selected_restorable == "yes" and not is_restorable) or (selected_restorable == "no" and is_restorable):
            continue
        version_rows.append({"version": version, "source_label": list_source_label(version.source_liste), "status_label": VERSION_STATUS_LABELS.get(version.status, version.status), "restorable": is_restorable})
    legacy_rows = []
    if (not selected_status or selected_status == "HISTORIQUE") and selected_restorable != "yes":
        legacy_rows = [{"batch": batch, "source_label": list_source_label(batch.source_liste)} for batch in all_legacy_batches if not selected_source or batch.source_liste == selected_source]
    tracked_sources = {version.source_liste for version in all_versions} | {batch.source_liste for batch in all_legacy_batches}
    summary = {"sources": len(tracked_sources), "active": sum(version.status == "ACTIVE" for version in all_versions), "archived_restorable": sum(version.status == "ARCHIVED" and is_version_restorable(version) for version in all_versions), "not_restorable": sum(not is_version_restorable(version) for version in all_versions) + len(all_legacy_batches)}
    return templates.TemplateResponse(
        request=request,
        name="list_versions.html",
        context={
            "request": request,
            "version_rows": version_rows,
            "legacy_rows": legacy_rows,
            "source_options": sorted(tracked_sources, key=list_source_label),
            "source_labels": LIST_SOURCE_LABELS,
            "selected_source": selected_source,
            "selected_status": selected_status,
            "selected_restorable": selected_restorable,
            "summary": summary,
            "can_restore": require_permission(request, PERMISSION_MANAGE_LISTS),
            "format_datetime": format_web_datetime,
        },
    )


@router.get("/list-versions/{version_id}")
def web_list_version_detail(
    version_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_VIEW_LISTS):
        log_access_denied(db, request, f"/web/list-versions/{version_id}", "Tentative d'accès refusée à une version de liste.")
        return forbidden_page(request)
    version = db.query(ListVersion).filter(ListVersion.id == version_id).first()
    if not version:
        raise HTTPException(status_code=404, detail="Version introuvable.")
    changes = db.query(ListVersionEntry).filter(
        ListVersionEntry.list_version_id == version.id
    ).order_by(ListVersionEntry.change_type, ListVersionEntry.created_at).all()
    activations = db.query(ListVersionActivation).filter(
        ListVersionActivation.version_id == version.id
    ).order_by(ListVersionActivation.created_at.desc()).all()
    restorable = is_version_restorable(version)
    change_rows = []
    for change in changes:
        try:
            snapshot = json.loads(change.entry_snapshot or "{}")
        except (TypeError, ValueError):
            snapshot = {}
        entity_name = snapshot.get("nom_complet") or " ".join(part for part in (snapshot.get("prenom"), snapshot.get("nom")) if part) or "Non disponible"
        change_rows.append({"change": change, "label": CHANGE_TYPE_LABELS.get(change.change_type, change.change_type), "entity_name": entity_name})
    return templates.TemplateResponse(
        request=request,
        name="list_version_detail.html",
        context={
            "request": request,
            "version": version,
            "source_label": list_source_label(version.source_liste),
            "status_label": VERSION_STATUS_LABELS.get(version.status, version.status),
            "change_rows": change_rows,
            # Computing an archive diff can take seconds for a 50k list.
            # The approval path validates the expected active version instead.
            "preview": None,
            "activations": activations,
            "restorable": restorable,
            "can_restore": restorable and require_permission(request, PERMISSION_MANAGE_LISTS),
            "format_datetime": format_web_datetime,
            "format_file_size": format_file_size,
        },
    )


@router.post("/list-versions/{version_id}/restore")
def web_request_list_version_restore(
    version_id: UUID,
    request: Request,
    reason: str = Form(...),
    db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_MANAGE_LISTS):
        log_access_denied(db, request, f"/web/list-versions/{version_id}/restore", "Tentative de restauration non autorisée.")
        return forbidden_page(request)
    if not reason.strip():
        return RedirectResponse(url=f"/web/list-versions/{version_id}?message=Motif obligatoire", status_code=303)
    version = db.query(ListVersion).filter(ListVersion.id == version_id).first()
    if not version:
        raise HTTPException(status_code=404, detail="Version introuvable.")
    if not is_version_restorable(version):
        return RedirectResponse(url=f"/web/list-versions/{version_id}?message=Version non restaurable", status_code=303)
    current_version = get_active_version(db, version.source_liste)
    if not current_version:
        return RedirectResponse(url=f"/web/list-versions/{version_id}?message=Aucune version courante", status_code=303)
    existing = db.query(ApprovalRequest).filter(
        ApprovalRequest.operation_type == OP_LIST_VERSION_RESTORE,
        ApprovalRequest.target_entity_id == str(version.id),
        ApprovalRequest.status == PENDING,
    ).first()
    if existing:
        return RedirectResponse(url=f"/web/list-versions/{version_id}?message=Une demande est déjà en attente", status_code=303)
    user = get_current_user(request)
    create_approval_request(
        db,
        operation_type=OP_LIST_VERSION_RESTORE,
        initiator=user,
        target_entity_type="ListVersion",
        target_entity_id=str(version.id),
        old_values={"preview": "Calculé lors de la validation afin d'éviter une requête Web longue."},
        new_values={
            "target_version_id": str(version.id),
            "expected_current_version_id": str(current_version.id),
            "source_liste": version.source_liste,
            "reason": reason.strip(),
        },
        comment=reason.strip(),
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    return RedirectResponse(url="/web/approvals?message=Demande de restauration créée", status_code=303)
    if denied_response:
        return denied_response
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
    user.failed_login_attempts = 0
    user.locked_at = None
    write_audit_log(
        db, current_username(request), "ACCOUNT_UNLOCKED", "User", str(user.id),
        "Compte déverrouillé par un administrateur technique.", request.client.host if request.client else None,
    )
    db.commit()
    return RedirectResponse(url="/web/users?message=Compte déverrouillé", status_code=303)


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

@router.get("/list-updates/uksl")
def web_auto_update_uksl_get_redirect(
    request: Request
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    return RedirectResponse(
        url="/web/list-updates",
        status_code=303
    )


@router.post("/list-updates/uksl")
def web_update_uksl(
    request: Request,
    db: Session = Depends(get_db)
):
    denied_response = require_admin_or_403(
        request,
        db,
        "/web/list-updates/uksl",
        "Tentative d'accès refusée à la mise à jour UKSL."
    )

    if denied_response:
        return denied_response

    try:
        return _queue_web_official_update(request, db, "UKSL")

        batch = None

        if isinstance(result_data, dict) and result_data.get("batch_id"):
            batch = db.query(ImportBatch).filter(
                ImportBatch.id == result_data.get("batch_id")
            ).first()

        if not batch:
            batch = db.query(ImportBatch).filter(
                ImportBatch.source_liste == "UKSL"
            ).order_by(
                ImportBatch.imported_at.desc()
            ).first()

        if isinstance(result_data, dict) and result_data.get("success") is False:
            return templates.TemplateResponse(
                request=request,
                name="list_updates.html",
                context={
                    "request": request,
                    "message": result_data.get("message", "Erreur pendant la mise à jour UKSL."),
                    "success": False,
                    "result": batch
                }
            )

        return templates.TemplateResponse(
            request=request,
            name="list_updates.html",
            context={
                "request": request,
                "message": "Mise à jour UKSL exécutée avec succès.",
                "success": True,
                "result": batch
            }
        )

    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="list_updates.html",
            context={
                "request": request,
                "message": f"Erreur pendant la mise à jour UKSL : {str(e)}",
                "success": False,
                "result": None
            }
        )

@router.post("/list-updates/ofac-sdn")
def web_update_ofac_sdn(request: Request, db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/list-updates/ofac-sdn", "Tentative d'accès refusée à la mise à jour OFAC SDN.")
    if denied_response:
        return denied_response

    try:
        return _queue_web_official_update(request, db, "OFAC_SDN")
    except Exception as e:
        return templates.TemplateResponse(request=request, name="list_updates.html", context={"request": request, "message": f"Erreur pendant la mise à jour OFAC SDN : {str(e)}", "success": False, "result": None})


@router.post("/list-updates/ofac-consolidated")
def web_update_ofac_consolidated(request: Request, db: Session = Depends(get_db)):
    denied_response = require_admin_or_403(request, db, "/web/list-updates/ofac-consolidated", "Tentative d'accès refusée à la mise à jour OFAC Consolidated.")
    if denied_response:
        return denied_response

    try:
        return _queue_web_official_update(request, db, "OFAC_CONSOLIDATED")
    except Exception as e:
        return templates.TemplateResponse(request=request, name="list_updates.html", context={"request": request, "message": f"Erreur pendant la mise à jour OFAC Consolidated : {str(e)}", "success": False, "result": None})


@router.get("/scheduler-status")
def web_scheduler_status(
    request: Request,
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_permission(request, PERMISSION_LISTS_VIEW):
        log_access_denied(
            db=db,
            request=request,
            route="/web/scheduler-status",
            description="Tentative d'accès refusée à la page état scheduler."
        )
        return forbidden_page(request)

    scheduler_status = get_scheduler_status()
    list_freshness = get_list_freshness(db)

    latest_imports = db.query(ImportBatch).filter(
        ImportBatch.source_liste.in_([
            "OFAC_SDN",
            "OFAC_CONSOLIDATED",
            "FR_GEL",
            "UE",
            "ONU",
            "UKSL",
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
            "source": "UKSL",
            "format": "CSV",
            "frequence": "Mensuelle",
            "heure": "1er du mois 03:30 UTC",
            "mode": "Automatique + manuel"
        },
        {
            "source": "OFSI",
            "format": "Excel / CSV",
            "frequence": "-",
            "heure": "-",
            "mode": "Manuel uniquement"
        }
    ]

    return templates.TemplateResponse(
        request=request,
        name="scheduler_status.html",
        context={
            "request": request,
            "scheduler_status": scheduler_status,
            "list_freshness": list_freshness,
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

    if not require_permission(request, PERMISSION_LISTS_IMPORT):
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

    if not require_permission(request, PERMISSION_VIEW_AUDIT):
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

    if not require_permission(request, PERMISSION_MANAGE_MATCHING_SETTINGS):
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

    if not require_permission(request, PERMISSION_MANAGE_MATCHING_SETTINGS):
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
                "message": (
                    "Seuils invalides : l'ordre requis est "
                    "0 ≤ possible ≤ probable ≤ exacte ≤ 100. "
                    "Aucune modification n'a été enregistrée."
                ),
                "success": False,
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

    create_approval_request(
        db=db,
        operation_type=OP_MATCHING_SETTINGS,
        initiator=current_user,
        target_entity_type="MatchingSetting",
        target_entity_id=str(old_settings.id),
        old_values={
            "exact_threshold": old_settings.exact_threshold,
            "probable_threshold": old_settings.probable_threshold,
            "possible_threshold": old_settings.possible_threshold,
        },
        new_values={
            "exact_threshold": exact_threshold,
            "probable_threshold": probable_threshold,
            "possible_threshold": possible_threshold,
        },
        comment="Modification des seuils de matching.",
        ip_address=request.client.host if request.client else None,
    )

    settings = old_settings
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
            "message": "Demande de modification des seuils envoyée pour validation.",
            "success": True,
            "history_logs": history_logs
        }
    )

@router.get("/critical-alerts")
def web_critical_alerts(
    request: Request,
    niveau_alerte: str | None = Query(None),
    statut: str | None = Query(None),
    message: str | None = Query(None),
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_permission(request, PERMISSION_VIEW_CRITICAL_ALERTS):
        log_access_denied(
            db=db,
            request=request,
            route="/web/critical-alerts",
            description="Tentative d'accès refusée à la supervision des alertes critiques."
        )
        return forbidden_page(request)

    base_query = db.query(Alert).filter(
        Alert.niveau_alerte.in_(["ALERTE_EXACTE", "ALERTE_PROBABLE"]),
        Alert.statut.in_(["GENEREE", "EN_COURS", "ESCALADEE", "CONFIRMEE"])
    )

    current_niveau = None
    current_status = None

    if niveau_alerte:
        current_niveau = niveau_alerte.strip().upper()
        base_query = base_query.filter(Alert.niveau_alerte == current_niveau)

    if statut:
        current_status = statut.strip().upper()
        critical_alerts = base_query.filter(
            Alert.statut == current_status
        ).order_by(Alert.created_at.desc()).all()
        actionable_alerts = critical_alerts if current_status != "CONFIRMEE" else []
        confirmed_alerts = critical_alerts if current_status == "CONFIRMEE" else []
    else:
        actionable_alerts = base_query.filter(
            Alert.statut.in_(["GENEREE", "EN_COURS", "ESCALADEE"])
        ).order_by(Alert.created_at.desc()).all()
        confirmed_alerts = base_query.filter(
            Alert.statut == "CONFIRMEE"
        ).order_by(Alert.created_at.desc()).all()

    critical_alerts = actionable_alerts + confirmed_alerts

    total_critical = len(critical_alerts)
    actionable_total = len(actionable_alerts)
    confirmed_total = len(confirmed_alerts)

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
            "actionable_total": actionable_total,
            "confirmed_total": confirmed_total,
            "exact_count": exact_count,
            "probable_count": probable_count,
            "niveau_alerte": current_niveau,
            "statut": current_status,
            "message": message
        }
    )

@router.post("/matching-settings/reset")
def web_matching_settings_reset(
    request: Request,
    db: Session = Depends(get_db)
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)

    if not require_permission(request, PERMISSION_MANAGE_MATCHING_SETTINGS):
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

    create_approval_request(
        db=db,
        operation_type=OP_MATCHING_SETTINGS,
        initiator=current_user,
        target_entity_type="MatchingSetting",
        target_entity_id=str(old_settings.id),
        old_values={
            "exact_threshold": old_settings.exact_threshold,
            "probable_threshold": old_settings.probable_threshold,
            "possible_threshold": old_settings.possible_threshold,
        },
        new_values={"exact_threshold": 90.0, "probable_threshold": 75.0, "possible_threshold": 60.0},
        comment="Réinitialisation des seuils de matching.",
        ip_address=request.client.host if request.client else None,
    )

    write_audit_log(
        db=db,
        user_identifier=username,
        action="RESET_MATCHING_SETTINGS_REQUESTED",
        entity_type="MatchingSetting",
        entity_id=str(old_settings.id),
        description=(
            f"Réinitialisation des seuils de matching aux valeurs par défaut. "
            f"Anciennes valeurs : {old_values}. "
            f"Nouvelles valeurs : Exacte=90.0, Probable=75.0, Possible=60.0."
        ),
        ip_address=request.client.host if request.client else None
    )

    db.commit()

    return RedirectResponse(
        url=(
            "/web/matching-settings?message=Demande de réinitialisation envoyée "
            "pour validation&success=True"
        ),
        status_code=303
    )

@router.get("/approvals")
def web_approvals(request: Request, db: Session = Depends(get_db)):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_VIEW_APPROVALS):
        log_access_denied(db, request, "/web/approvals", "Tentative d'accès refusée aux validations.")
        return forbidden_page(request)
    approvals = db.query(ApprovalRequest).order_by(ApprovalRequest.created_at.desc()).limit(200).all()
    approval_counts = {
        "pending": sum(approval.status == PENDING for approval in approvals),
        "approved": sum(approval.status == "VALIDE" for approval in approvals),
        "rejected": sum(approval.status == "REJETE" for approval in approvals),
    }
    current_user = get_current_user(request)
    return templates.TemplateResponse(
        request=request,
        name="approvals.html",
        context={
            "request": request,
            "approvals": approvals,
            "approval_counts": approval_counts,
            "approval_target_labels": approval_target_labels(db, approvals),
            "approval_internal_entry_links": approval_internal_entry_links(db, approvals),
            "approval_alert_links": approval_alert_links(db, approvals),
            "approval_operation_labels": approval_operation_labels(approvals),
            "pending_status": PENDING,
            "can_validate": require_permission(request, PERMISSION_REVIEW_FOUR_EYES),
            "current_user_id": current_user.get("id"),
        },
    )


@router.post("/approvals/{approval_id}/review")
def web_review_approval(
    approval_id: UUID,
    request: Request,
    decision: str = Form(...),
    comment: str = Form(None),
    db: Session = Depends(get_db),
):
    if not require_login(request):
        return RedirectResponse(url="/web/login", status_code=303)
    if not require_permission(request, PERMISSION_REVIEW_FOUR_EYES):
        log_access_denied(db, request, f"/web/approvals/{approval_id}/review", "Tentative de validation non autorisée.")
        return forbidden_page(request)
    approval = (
        db.query(ApprovalRequest)
        .filter(ApprovalRequest.id == approval_id)
        .with_for_update()
        .first()
    )
    if not approval:
        raise HTTPException(status_code=404, detail="Demande introuvable.")
    if approval.operation_type == "INTERNAL_LIST_CHANGE" and not require_permission(request, PERMISSION_INTERNAL_LISTS_VALIDATE):
        log_access_denied(db, request, f"/web/approvals/{approval_id}/review", "Validation interne non autorisée.")
        return forbidden_page(request)
    try:
        if approval.operation_type == OP_LIST_VERSION_RESTORE and decision.upper() == "APPROVE":
            queue_restore_approval(
                db=db, approval=approval, reviewer=get_current_user(request), comment=comment,
                ip_address=request.client.host if request.client else None,
            )
            db.commit()
            enqueue_restore_approval(str(approval.id))
            return RedirectResponse(url="/web/approvals?message=Restauration programmée", status_code=303)
        review_approval_request(
            db=db,
            approval=approval,
            reviewer=get_current_user(request),
            approved=decision.upper() == "APPROVE",
            comment=comment,
            ip_address=request.client.host if request.client else None,
        )
        db.commit()
    except (PermissionError, ValueError) as exc:
        db.rollback()
        return RedirectResponse(url=f"/web/approvals?message={str(exc)}", status_code=303)
    return RedirectResponse(url="/web/approvals?message=Demande traitée", status_code=303)


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

    if not require_permission(request, PERMISSION_MANAGE_LISTS):
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
        return _queue_web_official_update(request, db, "FR_GEL")

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

    if not require_permission(request, PERMISSION_MANAGE_LISTS):
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
        return _queue_web_official_update(request, db, "UE")

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

    if not require_permission(request, PERMISSION_MANAGE_LISTS):
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
        return _queue_web_official_update(request, db, "ONU")

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

    if not require_permission(request, PERMISSION_MANAGE_TECHNICAL_CONFIGURATION):
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
            "API_DOCUMENTATION_ACCESS",
            "API_AUTH_FAILED"
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

    total_api_auth_failures = db.query(AuditLog).filter(
        AuditLog.action == "API_AUTH_FAILED"
    ).count()

    last_api_call = db.query(AuditLog).filter(
        AuditLog.action.in_([
            "API_MATCHING_CLIENT",
            "API_GET_ALERTS",
            "API_STATUS_CHECK",
            "API_DOCUMENTATION_ACCESS",
            "API_AUTH_FAILED"
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
            "total_api_auth_failures": total_api_auth_failures,
            "last_api_call": last_api_call,
        }
    )

