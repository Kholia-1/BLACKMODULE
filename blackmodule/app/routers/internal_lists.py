"""Protected API for ANIF, judicial, internal PPE and AFB-watch lists."""

from __future__ import annotations

import hashlib
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import or_
from sqlalchemy.orm import Session, selectinload

from app.config import INTERNAL_LIST_IMPORT_MAX_BYTES, SECRET_KEY
from app.database import get_db
from app.models import ImportBatch, SanctionEntry
from app.schemas import InternalListChangeRequest, InternalListEntryRequest, InternalListSubmitRequest
from app.services.audit_service import write_audit_log
from app.services.api_auth import require_permission
from app.services.authorization_service import (
    PERMISSION_INTERNAL_LISTS_CREATE, PERMISSION_INTERNAL_LISTS_EDIT,
    PERMISSION_INTERNAL_LISTS_SUBMIT, PERMISSION_INTERNAL_LISTS_VALIDATE,
    PERMISSION_INTERNAL_LISTS_VIEW, PERMISSION_INTERNAL_LISTS_SENSITIVE_VIEW,
    has_permission,
)
from app.services.internal_list_service import (
    DRAFT, INTERNAL_CATEGORIES, DuplicateInternalEntryError, create_internal_entry,
    parse_internal_import, preview_internal_import, request_entry_change, serialize_internal_entry,
    submit_internal_entry,
)

router = APIRouter(prefix="/api/internal-lists", tags=["Listes internes"])
_PREVIEW_TOKEN_MAX_AGE_SECONDS = 15 * 60
_preview_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="internal-list-import-preview")


def _preview_token(*, content: bytes, category: str, username: str | None) -> str:
    return _preview_serializer.dumps({
        "sha256": hashlib.sha256(content).hexdigest(),
        "category": category,
        "username": username,
    })


def _valid_preview_token(
    token: str | None, *, content: bytes, category: str, username: str | None,
) -> bool:
    if not token:
        return False
    try:
        payload = _preview_serializer.loads(token, max_age=_PREVIEW_TOKEN_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return False
    expected_hash = hashlib.sha256(content).hexdigest()
    return (
        payload.get("sha256") == expected_hash
        and payload.get("category") == category
        and payload.get("username") == username
    )


def _entry_or_404(db: Session, entry_id: UUID, *, with_history: bool = False) -> SanctionEntry:
    options = [selectinload(SanctionEntry.aliases)]
    if with_history:
        options.append(selectinload(SanctionEntry.internal_history))
    entry = db.query(SanctionEntry).options(*options).filter(
        SanctionEntry.id == entry_id, SanctionEntry.is_internal_list.is_(True)
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Fiche interne introuvable.")
    return entry


async def _read_import_upload(file: UploadFile) -> bytes:
    content = await file.read(INTERNAL_LIST_IMPORT_MAX_BYTES + 1)
    if len(content) > INTERNAL_LIST_IMPORT_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Fichier trop volumineux pour l'import des listes internes.",
        )
    return content


@router.get("/")
def list_internal_entries(
    category: str | None = Query(None), status: str | None = Query(None), q: str | None = Query(None),
    db: Session = Depends(get_db), user: dict = Depends(require_permission(PERMISSION_INTERNAL_LISTS_VIEW)),
):
    query = db.query(SanctionEntry).filter(SanctionEntry.is_internal_list.is_(True))
    if category:
        query = query.filter(SanctionEntry.source_liste == category.upper())
    if status:
        query = query.filter(SanctionEntry.internal_status == status.upper())
    can_view_sensitive = has_permission(user, PERMISSION_INTERNAL_LISTS_SENSITIVE_VIEW)
    if q:
        needle = f"%{q.strip()}%"
        searchable = [SanctionEntry.nom.ilike(needle), SanctionEntry.nom_complet.ilike(needle)]
        if can_view_sensitive:
            searchable.append(SanctionEntry.source_reference.ilike(needle))
        query = query.filter(or_(*searchable))
    entries = query.options(selectinload(SanctionEntry.aliases)).order_by(SanctionEntry.updated_at.desc()).all()
    return [serialize_internal_entry(entry, include_sensitive=can_view_sensitive) for entry in entries]


@router.get("/{entry_id}")
def get_internal_entry(
    entry_id: UUID, request: Request, db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_INTERNAL_LISTS_VIEW)),
):
    can_view_sensitive = has_permission(user, PERMISSION_INTERNAL_LISTS_SENSITIVE_VIEW)
    entry = _entry_or_404(db, entry_id, with_history=can_view_sensitive)
    write_audit_log(
        db, user.get("username"), "VIEW_INTERNAL_LIST_DETAIL", "InternalSanctionEntry", str(entry.id),
        f"Consultation fiche interne; rôle={user.get('role')}; catégorie={entry.source_liste}.",
        request.client.host if request.client else None,
    )
    db.commit()
    return serialize_internal_entry(entry, include_sensitive=can_view_sensitive)


@router.post("/", status_code=201)
def create_entry(
    payload: InternalListEntryRequest, db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_INTERNAL_LISTS_CREATE)),
):
    try:
        entry = create_internal_entry(db, category=payload.category, values=payload.values,
                                      aliases=payload.aliases, actor=user.get("username"))
        db.commit()
        return {"id": str(entry.id), "status": entry.internal_status}
    except DuplicateInternalEntryError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail={"message": str(exc), "duplicates": exc.duplicates})
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/{entry_id}/submit", status_code=202)
def submit_entry(
    entry_id: UUID, payload: InternalListSubmitRequest, db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_INTERNAL_LISTS_SUBMIT)),
):
    entry = _entry_or_404(db, entry_id)
    try:
        approval = submit_internal_entry(db, entry=entry, actor=user, comment=payload.comment, ip_address=None)
        db.commit()
        return {"approval_id": str(approval.id), "status": "EN_ATTENTE_VALIDATION"}
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/{entry_id}/changes", status_code=202)
def request_change(
    entry_id: UUID, payload: InternalListChangeRequest, db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_INTERNAL_LISTS_EDIT)),
):
    entry = _entry_or_404(db, entry_id)
    try:
        approval = request_entry_change(db, entry=entry, actor=user, action=payload.action.upper(),
                                        values=payload.values, aliases=payload.aliases,
                                        comment=payload.comment, ip_address=None)
        db.commit()
        return {"approval_id": str(approval.id) if approval else None,
                "status": "EN_ATTENTE_VALIDATION" if approval else DRAFT}
    except DuplicateInternalEntryError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail={"message": str(exc), "duplicates": exc.duplicates})
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/import/preview")
async def preview_import(
    category: str = Query(...), file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_INTERNAL_LISTS_CREATE)),
):
    if category.upper() not in INTERNAL_CATEGORIES:
        raise HTTPException(status_code=400, detail="Catégorie de liste interne invalide.")
    try:
        content = await _read_import_upload(file)
        accepted, rejected, duplicates = preview_internal_import(
            db, category=category.upper(), file_content=content, filename=file.filename or "",
        )
        accepted_rows = [
            {"row": row.get("__import_row__"), "name": row.get("nom_complet") or row.get("nom")}
            for row in accepted
        ]
        return {"accepted": len(accepted), "accepted_rows": accepted_rows,
                "rejected": rejected, "duplicates": duplicates,
                "requires_confirmation": True, "status_after_import": DRAFT,
                "preview_token": _preview_token(
                    content=content, category=category.upper(), username=user.get("username"),
                )}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/import/file-preview")
async def preview_import_file(
    file: UploadFile = File(...),
    user: dict = Depends(require_permission(PERMISSION_INTERNAL_LISTS_CREATE)),
):
    """Read up to ten CSV/XLSX rows without persisting or executing file content."""
    try:
        accepted, rejected = parse_internal_import(await _read_import_upload(file), file.filename or "")
        rows = [
            {"row": item.get("__import_row__"), "status": "Valide", "reason": "",
             "values": {key: value for key, value in item.items() if key != "__import_row__"}}
            for item in accepted
        ] + [
            {"row": item.get("row"), "status": "Rejetée", "reason": item.get("error", ""),
             "values": item.get("values", {})}
            for item in rejected
        ]
        rows.sort(key=lambda item: item["row"] or 0)
        columns = sorted({key for item in rows for key in item["values"]})
        return {"columns": columns, "rows": rows[:10], "truncated": len(rows) > 10}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/import", status_code=201)
async def import_internal_list(
    category: str = Query(...), confirmed: bool = Query(False),
    preview_token: str | None = Query(None), file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: dict = Depends(require_permission(PERMISSION_INTERNAL_LISTS_CREATE)),
):
    category = category.upper()
    if category not in INTERNAL_CATEGORIES:
        raise HTTPException(status_code=400, detail="Catégorie de liste interne invalide.")
    content = await _read_import_upload(file)
    try:
        accepted, rejected, duplicates = preview_internal_import(
            db, category=category, file_content=content, filename=file.filename or "",
        )
        if not confirmed or not _valid_preview_token(
            preview_token, content=content, category=category, username=user.get("username"),
        ):
            raise HTTPException(status_code=409, detail={
                "message": "Prévisualisation obligatoire ou expirée; prévisualisez de nouveau le fichier.",
                "accepted": len(accepted), "rejected": rejected, "duplicates": duplicates,
            })
        batch = ImportBatch(source_liste=category, filename=file.filename, file_type=(file.filename or "").rsplit(".", 1)[-1].upper(),
                            total_records=len(accepted) + len(rejected), inserted_records=0,
                            rejected_records=len(rejected), status="PENDING", imported_by=user.get("username"),
                            downloaded_at=datetime.utcnow(), file_size_bytes=len(content),
                            file_hash=hashlib.sha256(content).hexdigest())
        db.add(batch)
        for source_row in accepted:
            row = dict(source_row)
            aliases = str(row.pop("aliases", row.pop("alias", "")) or "").split("|")
            create_internal_entry(db, category=category, values=row, aliases=aliases, actor=user.get("username"))
            batch.inserted_records += 1
        batch.status = "SUCCESS"
        db.commit()
        return {"batch_id": str(batch.id), "inserted": batch.inserted_records,
                "rejected": rejected, "duplicates": duplicates,
                "status_after_import": DRAFT}
    except HTTPException:
        db.rollback()
        raise
    except DuplicateInternalEntryError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail={"message": str(exc), "duplicates": exc.duplicates})
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/import/template.csv")
def download_import_template(
    user: dict = Depends(require_permission(PERMISSION_INTERNAL_LISTS_CREATE)),
):
    content = (
        "nom,prenom,date_naissance,nationalite,pays,document_type,document_number,"
        "num_passeport,source_reference,risk_level,motif_sanction,alias,ppe_type,"
        "ppe_function,ppe_institution,ppe_country,ppe_function_start_date,"
        "ppe_function_end_date,ppe_status,ppe_relationship\n"
    )
    return Response(content=content, media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": 'attachment; filename="modele_listes_internes.csv"'
    })
