from typing import Callable

from fastapi import APIRouter, Depends, File, UploadFile, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ImportBatch
from app.schemas import ImportBatchResponse
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
    import_france_gel_xml,
    import_uksl_csv
)
from app.services.list_update_service import (
    auto_update_ofac_sdn,
    auto_update_ofac_consolidated,
    auto_update_france_gel,
    auto_update_eu_xml,
    auto_update_un_xml,
)


router = APIRouter(
    prefix="/api/imports",
    tags=["Imports"],
)


def _validate_extension(filename: str, allowed_extensions: list[str], message: str):
    if not filename:
        raise HTTPException(
            status_code=400,
            detail="Aucun fichier reçu.",
        )

    filename_lower = filename.lower()

    if not any(filename_lower.endswith(ext.lower()) for ext in allowed_extensions):
        raise HTTPException(
            status_code=400,
            detail=message,
        )


def _detect_file_type(filename: str, default_type: str) -> str:
    filename_lower = filename.lower()

    if filename_lower.endswith(".xlsx"):
        return "XLSX"

    if filename_lower.endswith(".xls"):
        return "XLS"

    return default_type


async def _execute_import(
    *,
    db: Session,
    file: UploadFile,
    imported_by: str,
    source_liste: str,
    file_type: str,
    importer: Callable,
    success_action: str,
    failed_action: str,
    success_description_label: str,
) -> ImportBatch:
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

        result = importer(
            db=db,
            file_content=file_content,
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
            action=success_action,
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=(
                f"{success_description_label} terminé. "
                f"Total : {import_batch.total_records}, "
                f"Insérés : {import_batch.inserted_records}, "
                f"Mis à jour : {import_batch.updated_records}, "
                f"Doublons : {import_batch.duplicate_records}, "
                f"Rejetés : {import_batch.rejected_records}."
            ),
            ip_address=None,
        )

        db.commit()
        db.refresh(import_batch)

        return import_batch

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
            action=failed_action,
            entity_type="ImportBatch",
            entity_id=str(failed_batch.id),
            description=f"Échec {success_description_label} : {str(e)[:500]}",
            ip_address=None,
        )

        db.commit()
        db.refresh(failed_batch)

        raise HTTPException(
            status_code=400,
            detail=str(e),
        )


@router.post("/afb-ppe-csv", response_model=ImportBatchResponse)
async def upload_afb_ppe_csv(
    file: UploadFile = File(...),
    imported_by: str = "SYSTEM",
    db: Session = Depends(get_db),
):
    _validate_extension(
        file.filename,
        [".csv"],
        "Format invalide. Veuillez importer un fichier CSV.",
    )

    return await _execute_import(
        db=db,
        file=file,
        imported_by=imported_by,
        source_liste="AFB_PPE",
        file_type="CSV",
        importer=import_afb_ppe_csv,
        success_action="IMPORT_AFB_PPE_CSV",
        failed_action="IMPORT_AFB_PPE_CSV_FAILED",
        success_description_label="Import CSV AFB_PPE",
    )


@router.post("/ofac-sdn-xml", response_model=ImportBatchResponse)
async def upload_ofac_sdn_xml(
    file: UploadFile = File(...),
    imported_by: str = "SYSTEM",
    db: Session = Depends(get_db),
):
    _validate_extension(
        file.filename,
        [".xml"],
        "Format invalide. Veuillez importer un fichier XML OFAC SDN.",
    )

    return await _execute_import(
        db=db,
        file=file,
        imported_by=imported_by,
        source_liste="OFAC_SDN",
        file_type="XML",
        importer=import_ofac_sdn_xml,
        success_action="IMPORT_OFAC_SDN_XML",
        failed_action="IMPORT_OFAC_SDN_XML_FAILED",
        success_description_label="Import XML OFAC_SDN",
    )


@router.post("/ofac-consolidated-xml", response_model=ImportBatchResponse)
async def upload_ofac_consolidated_xml(
    file: UploadFile = File(...),
    imported_by: str = "SYSTEM",
    db: Session = Depends(get_db),
):
    _validate_extension(
        file.filename,
        [".xml"],
        "Format invalide. Veuillez importer un fichier XML OFAC Consolidated.",
    )

    return await _execute_import(
        db=db,
        file=file,
        imported_by=imported_by,
        source_liste="OFAC_CONSOLIDATED",
        file_type="XML",
        importer=import_ofac_consolidated_xml,
        success_action="IMPORT_OFAC_CONSOLIDATED_XML",
        failed_action="IMPORT_OFAC_CONSOLIDATED_XML_FAILED",
        success_description_label="Import XML OFAC Consolidated",
    )


@router.post("/un-xml", response_model=ImportBatchResponse)
async def upload_un_xml(
    file: UploadFile = File(...),
    imported_by: str = "SYSTEM",
    db: Session = Depends(get_db),
):
    _validate_extension(
        file.filename,
        [".xml"],
        "Format invalide. Veuillez importer un fichier XML ONU.",
    )

    return await _execute_import(
        db=db,
        file=file,
        imported_by=imported_by,
        source_liste="ONU",
        file_type="XML",
        importer=import_un_xml,
        success_action="IMPORT_UN_XML",
        failed_action="IMPORT_UN_XML_FAILED",
        success_description_label="Import XML ONU",
    )


@router.post("/eu-csv", response_model=ImportBatchResponse)
async def upload_eu_csv(
    file: UploadFile = File(...),
    imported_by: str = "SYSTEM",
    db: Session = Depends(get_db),
):
    _validate_extension(
        file.filename,
        [".csv"],
        "Format invalide. Veuillez importer un fichier CSV Union Européenne.",
    )

    return await _execute_import(
        db=db,
        file=file,
        imported_by=imported_by,
        source_liste="UE",
        file_type="CSV",
        importer=import_eu_csv,
        success_action="IMPORT_EU_CSV",
        failed_action="IMPORT_EU_CSV_FAILED",
        success_description_label="Import CSV UE",
    )


@router.post("/ofsi-csv", response_model=ImportBatchResponse)
async def upload_ofsi_csv(
    file: UploadFile = File(...),
    imported_by: str = "SYSTEM",
    db: Session = Depends(get_db),
):
    _validate_extension(
        file.filename,
        [".csv"],
        "Format invalide. Veuillez importer un fichier CSV OFSI UK.",
    )

    return await _execute_import(
        db=db,
        file=file,
        imported_by=imported_by,
        source_liste="OFSI",
        file_type="CSV",
        importer=import_ofsi_csv,
        success_action="IMPORT_OFSI_CSV",
        failed_action="IMPORT_OFSI_CSV_FAILED",
        success_description_label="Import CSV OFSI",
    )


@router.post("/ofsi-excel", response_model=ImportBatchResponse)
async def upload_ofsi_excel(
    file: UploadFile = File(...),
    imported_by: str = "SYSTEM",
    db: Session = Depends(get_db),
):
    _validate_extension(
        file.filename,
        [".xls", ".xlsx"],
        "Format invalide. Veuillez importer un fichier Excel OFSI (.xls ou .xlsx).",
    )

    return await _execute_import(
        db=db,
        file=file,
        imported_by=imported_by,
        source_liste="OFSI",
        file_type=_detect_file_type(file.filename, "XLSX"),
        importer=import_ofsi_excel,
        success_action="IMPORT_OFSI_EXCEL",
        failed_action="IMPORT_OFSI_EXCEL_FAILED",
        success_description_label="Import Excel OFSI",
    )


@router.post("/france-gel-json", response_model=ImportBatchResponse)
async def upload_france_gel_json(
    file: UploadFile = File(...),
    imported_by: str = "SYSTEM",
    db: Session = Depends(get_db),
):
    _validate_extension(
        file.filename,
        [".json"],
        "Format invalide. Veuillez importer un fichier JSON France Gel des Avoirs.",
    )

    return await _execute_import(
        db=db,
        file=file,
        imported_by=imported_by,
        source_liste="FR_GEL",
        file_type="JSON",
        importer=import_france_gel_json,
        success_action="IMPORT_FRANCE_GEL_JSON",
        failed_action="IMPORT_FRANCE_GEL_JSON_FAILED",
        success_description_label="Import JSON France Gel des Avoirs",
    )


@router.post("/france-gel-xml", response_model=ImportBatchResponse)
async def upload_france_gel_xml(
    file: UploadFile = File(...),
    imported_by: str = "SYSTEM",
    db: Session = Depends(get_db),
):
    _validate_extension(
        file.filename,
        [".xml"],
        "Format invalide. Veuillez importer un fichier XML France Gel des Avoirs.",
    )

    return await _execute_import(
        db=db,
        file=file,
        imported_by=imported_by,
        source_liste="FR_GEL",
        file_type="XML",
        importer=import_france_gel_xml,
        success_action="IMPORT_FRANCE_GEL_XML",
        failed_action="IMPORT_FRANCE_GEL_XML_FAILED",
        success_description_label="Import XML France Gel des Avoirs",
    )


@router.post("/uksl-csv", response_model=ImportBatchResponse)
async def upload_uksl_csv(
    file: UploadFile = File(...),
    imported_by: str = "SYSTEM",
    db: Session = Depends(get_db)
):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Format invalide. Veuillez importer un fichier CSV UK Sanctions List."
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
            action="IMPORT_UKSL_CSV",
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=(
                f"Import CSV UKSL terminé. "
                f"Total : {import_batch.total_records}, "
                f"Insérés : {import_batch.inserted_records}, "
                f"Mis à jour : {import_batch.updated_records}, "
                f"Rejetés : {import_batch.rejected_records}."
            ),
            ip_address=None
        )

        db.commit()
        db.refresh(import_batch)

        return import_batch

    except Exception as e:
        import_batch.status = "FAILED"
        import_batch.error_message = str(e)

        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="IMPORT_UKSL_CSV_FAILED",
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=f"Échec import CSV UKSL : {str(e)}",
            ip_address=None
        )

        db.commit()
        db.refresh(import_batch)

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


@router.post("/auto-update/ofac-sdn", response_model=ImportBatchResponse)
def manual_auto_update_ofac_sdn(
    imported_by: str = "MANUAL_ADMIN",
    db: Session = Depends(get_db),
):
    try:
        return auto_update_ofac_sdn(
            db=db,
            imported_by=imported_by,
        )

    except Exception as e:
        print("ERREUR AUTO UPDATE OFAC SDN =", repr(e))

        raise HTTPException(
            status_code=400,
            detail=f"Erreur mise à jour automatique OFAC SDN : {repr(e)}",
        )


@router.post("/auto-update/ofac-consolidated", response_model=ImportBatchResponse)
def manual_auto_update_ofac_consolidated(
    imported_by: str = "MANUAL_ADMIN",
    db: Session = Depends(get_db),
):
    try:
        return auto_update_ofac_consolidated(
            db=db,
            imported_by=imported_by,
        )

    except Exception as e:
        print("ERREUR AUTO UPDATE OFAC CONSOLIDATED =", repr(e))

        raise HTTPException(
            status_code=400,
            detail=f"Erreur mise à jour automatique OFAC Consolidated : {repr(e)}",
        )

@router.post("/eu-xml", response_model=ImportBatchResponse)
async def upload_eu_xml(
    file: UploadFile = File(...),
    imported_by: str = "SYSTEM",
    db: Session = Depends(get_db)
):
    if not file.filename.lower().endswith(".xml"):
        raise HTTPException(
            status_code=400,
            detail="Format invalide. Veuillez importer un fichier XML Union Européenne."
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
            action="IMPORT_EU_XML",
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=(
                f"Import XML UE terminé. "
                f"Total : {import_batch.total_records}, "
                f"Insérés : {import_batch.inserted_records}, "
                f"Mis à jour : {import_batch.updated_records}, "
                f"Rejetés : {import_batch.rejected_records}."
            ),
            ip_address=None
        )

        db.commit()
        db.refresh(import_batch)

        return import_batch

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
            action="IMPORT_EU_XML_FAILED",
            entity_type="ImportBatch",
            entity_id=str(failed_batch.id),
            description=f"Échec import XML UE : {str(e)[:500]}",
            ip_address=None
        )

        db.commit()
        db.refresh(failed_batch)

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

@router.post("/auto-update/france-gel", response_model=ImportBatchResponse)
def manual_auto_update_france_gel(
    imported_by: str = "MANUAL_ADMIN",
    db: Session = Depends(get_db)
):
    try:
        return auto_update_france_gel(
            db=db,
            imported_by=imported_by
        )

    except Exception as e:
        print("ERREUR AUTO UPDATE FRANCE GEL =", repr(e))

        raise HTTPException(
            status_code=400,
            detail=f"Erreur mise à jour automatique France Gel : {repr(e)}"
        )


@router.post("/auto-update/eu", response_model=ImportBatchResponse)
def manual_auto_update_eu(
    imported_by: str = "MANUAL_ADMIN",
    db: Session = Depends(get_db)
):
    try:
        return auto_update_eu_xml(
            db=db,
            imported_by=imported_by
        )

    except Exception as e:
        print("ERREUR AUTO UPDATE UE =", repr(e))

        raise HTTPException(
            status_code=400,
            detail=f"Erreur mise à jour automatique UE : {repr(e)}"
        )


@router.post("/auto-update/un", response_model=ImportBatchResponse)
def manual_auto_update_un(
    imported_by: str = "MANUAL_ADMIN",
    db: Session = Depends(get_db)
):
    try:
        return auto_update_un_xml(
            db=db,
            imported_by=imported_by
        )

    except Exception as e:
        print("ERREUR AUTO UPDATE ONU =", repr(e))

        raise HTTPException(
            status_code=400,
            detail=f"Erreur mise à jour automatique ONU : {repr(e)}"

        )

@router.post("/auto-update/uksl")
def api_auto_update_uksl(
    imported_by: str = "MANUAL_ADMIN",
    db: Session = Depends(get_db)
):
    result = auto_update_uksl_csv(
        db=db,
        imported_by=imported_by
    )

    if not result.get("success"):
        raise HTTPException(
            status_code=400,
            detail=result.get("message")
        )

    return result