import hashlib
import requests

from sqlalchemy.orm import Session

from app.models import ImportBatch
from app.services.audit_service import write_audit_log
from app.services.import_service import (
    import_ofac_sdn_xml,
    import_ofac_consolidated_xml,
    import_france_gel_json,
    import_eu_xml,
    import_un_xml,
    import_ofsi_excel,
    import_uksl_csv,
)



OFAC_SDN_XML_URL = "https://www.treasury.gov/ofac/downloads/sdn.xml"
OFAC_CONSOLIDATED_XML_URL = "https://www.treasury.gov/ofac/downloads/sanctions/1.0/cons_advanced.xml"

def calculate_file_hash(file_content: bytes) -> str:
    return hashlib.sha256(file_content).hexdigest()


def download_file(url: str) -> bytes:
    headers = {
        "User-Agent": "BLACKMODULE/1.0"
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=90
    )

    if response.status_code == 404:
        raise ValueError(f"Fichier introuvable sur le site officiel : {url}")

    response.raise_for_status()

    if not response.content:
        raise ValueError("Le fichier téléchargé est vide.")

    if b"<" not in response.content[:100]:
        raise ValueError("Le fichier téléchargé ne semble pas être un fichier XML valide.")

    return response.content


def was_file_already_imported(
    db: Session,
    source_liste: str,
    file_hash: str
) -> ImportBatch | None:
    return db.query(ImportBatch).filter(
        ImportBatch.source_liste == source_liste,
        ImportBatch.status == "SUCCESS",
        ImportBatch.file_hash == file_hash,
        ImportBatch.total_records > 0
    ).first()



def compute_file_hash(file_content: bytes) -> str:
    return hashlib.sha256(file_content).hexdigest()


def get_last_success_batch(
    db: Session,
    source_liste: str
):
    return db.query(ImportBatch).filter(
        ImportBatch.source_liste == source_liste,
        ImportBatch.status == "SUCCESS"
    ).order_by(
        ImportBatch.imported_at.desc()
    ).first()


def auto_update_ofac_sdn(
    db: Session,
    imported_by: str = "DAILY_SCHEDULER"
) -> ImportBatch:
    file_content = download_file(OFAC_SDN_XML_URL)
    file_hash = calculate_file_hash(file_content)

    existing_import = was_file_already_imported(
        db=db,
        source_liste="OFAC_SDN",
        file_hash=file_hash
    )

    if existing_import:
        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="AUTO_UPDATE_OFAC_SDN_NO_CHANGE",
            entity_type="ImportBatch",
            entity_id=str(existing_import.id),
            description="Aucune mise à jour OFAC SDN : le fichier officiel est identique au dernier import.",
            ip_address=None
        )

        db.commit()
        return existing_import

    import_batch = ImportBatch(
        source_liste="OFAC_SDN",
        filename="sdn.xml",
        file_type="XML",
        status="PENDING",
        imported_by=imported_by,
        file_hash=file_hash
    )

    db.add(import_batch)
    db.flush()

    try:
        result = import_ofac_sdn_xml(
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
            action="AUTO_UPDATE_OFAC_SDN_XML",
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=(
                f"Mise à jour automatique OFAC SDN terminée. "
                f"Total : {import_batch.total_records}, "
                f"Insérés : {import_batch.inserted_records}, "
                f"Mis à jour : {import_batch.updated_records}, "
                f"Doublons : {import_batch.duplicate_records}, "
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
            action="AUTO_UPDATE_OFAC_SDN_XML_FAILED",
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=f"Échec mise à jour automatique OFAC SDN : {str(e)}",
            ip_address=None
        )

        db.commit()
        db.refresh(import_batch)
        raise


def auto_update_ofac_consolidated(
    db: Session,
    imported_by: str = "DAILY_SCHEDULER"
) -> ImportBatch:
    file_content = download_file(OFAC_CONSOLIDATED_XML_URL)
    file_hash = calculate_file_hash(file_content)

    existing_import = was_file_already_imported(
        db=db,
        source_liste="OFAC_CONSOLIDATED",
        file_hash=file_hash
    )

    if existing_import:
        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="AUTO_UPDATE_OFAC_CONSOLIDATED_NO_CHANGE",
            entity_type="ImportBatch",
            entity_id=str(existing_import.id),
            description="Aucune mise à jour OFAC Consolidated : le fichier officiel est identique au dernier import.",
            ip_address=None
        )

        db.commit()
        return existing_import

    import_batch = ImportBatch(
        source_liste="OFAC_CONSOLIDATED",
        filename="cons_advanced.xml",
        file_type="XML",
        status="PENDING",
        imported_by=imported_by,
        file_hash=file_hash
    )

    db.add(import_batch)
    db.flush()

    try:
        result = import_ofac_consolidated_xml(
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
            action="AUTO_UPDATE_OFAC_CONSOLIDATED_XML",
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=(
                f"Mise à jour automatique OFAC Consolidated terminée. "
                f"Total : {import_batch.total_records}, "
                f"Insérés : {import_batch.inserted_records}, "
                f"Mis à jour : {import_batch.updated_records}, "
                f"Doublons : {import_batch.duplicate_records}, "
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

            source_liste="OFAC_CONSOLIDATED",

            filename="cons_advanced.xml",

            file_type="XML",

            status="FAILED",

            imported_by=imported_by,

            file_hash=file_hash,

            error_message=str(e)[:1000]

        )

        db.add(failed_batch)

        db.flush()

        write_audit_log(

            db=db,

            user_identifier=imported_by,

            action="AUTO_UPDATE_OFAC_CONSOLIDATED_XML_FAILED",

            entity_type="ImportBatch",

            entity_id=str(failed_batch.id),

            description=f"Échec mise à jour automatique OFAC Consolidated : {str(e)[:500]}",

            ip_address=None

        )

        db.commit()

        db.refresh(failed_batch)

        raise


FR_GEL_JSON_URL = "https://gels-avoirs.dgtresor.gouv.fr/ApiPublic/api/v1/publication/derniere-publication-fichier-json"


def auto_update_france_gel(
    db: Session,
    imported_by: str = "DAILY_SCHEDULER"
):
    source_liste = "FR_GEL"
    filename = "france_gel.json"
    file_type = "JSON"

    try:
        response = requests.get(FR_GEL_JSON_URL, timeout=60)
        response.raise_for_status()

        file_content = response.content
        file_hash = compute_file_hash(file_content)

        last_batch = get_last_success_batch(db, source_liste)

        if (
                last_batch
                and getattr(last_batch, "file_hash", None) == file_hash
                and (last_batch.total_records or 0) > 0
        ):
            write_audit_log(
                db=db,
                user_identifier=imported_by,
                action="AUTO_UPDATE_FR_GEL_NO_CHANGE",
                entity_type="ImportBatch",
                entity_id=str(last_batch.id),
                description="Aucune modification détectée sur la liste France Gel.",
                ip_address=None
            )
            db.commit()
            return last_batch

        import_batch = ImportBatch(
            source_liste=source_liste,
            filename=filename,
            file_type=file_type,
            file_hash=file_hash,
            status="PENDING",
            imported_by=imported_by
        )

        db.add(import_batch)
        db.flush()

        result = import_france_gel_json(
            db=db,
            file_content=file_content
        )

        if result.get("total_records", 0) == 0:
            raise ValueError(
                "La liste France Gel a été téléchargée, mais aucune entrée n'a été lue. "
                "Le parser France Gel doit être vérifié."
            )

        import_batch.total_records = result["total_records"]
        import_batch.inserted_records = result["inserted_records"]
        import_batch.updated_records = result["updated_records"]
        import_batch.duplicate_records = result["duplicate_records"]
        import_batch.rejected_records = result["rejected_records"]
        import_batch.status = "SUCCESS"
        import_batch.error_message = None

        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="AUTO_UPDATE_FR_GEL",
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=(
                f"Mise à jour automatique France Gel terminée. "
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
            source_liste=source_liste,
            filename=filename,
            file_type=file_type,
            status="FAILED",
            imported_by=imported_by,
            error_message=str(e)[:1000]
        )

        db.add(failed_batch)
        db.flush()

        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="AUTO_UPDATE_FR_GEL_FAILED",
            entity_type="ImportBatch",
            entity_id=str(failed_batch.id),
            description=(
                "Échec mise à jour automatique France Gel. "
                "La source officielle est inaccessible depuis le réseau actuel. "
                "La dernière version valide reste exploitable et l'import manuel reste disponible."
            ),
            ip_address=None
        )

        db.commit()
        db.refresh(failed_batch)

        raise


EU_XML_URL = "https://webgate.ec.europa.eu/fsd/fsf/public/files/xmlFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw"


def auto_update_eu_xml(
    db: Session,
    imported_by: str = "WEEKLY_SCHEDULER"
):
    source_liste = "UE"
    filename = "eu_financial_sanctions.xml"
    file_type = "XML"

    try:
        response = requests.get(EU_XML_URL, timeout=90)
        response.raise_for_status()

        file_content = response.content
        file_hash = compute_file_hash(file_content)

        last_batch = get_last_success_batch(db, source_liste)

        if (
                last_batch
                and getattr(last_batch, "file_hash", None) == file_hash
                and (last_batch.total_records or 0) > 0
        ):
            write_audit_log(
                db=db,
                user_identifier=imported_by,
                action="AUTO_UPDATE_EU_NO_CHANGE",
                entity_type="ImportBatch",
                entity_id=str(last_batch.id),
                description="Aucune modification détectée sur la liste UE.",
                ip_address=None
            )
            db.commit()
            return last_batch

        import_batch = ImportBatch(
            source_liste=source_liste,
            filename=filename,
            file_type=file_type,
            file_hash=file_hash,
            status="PENDING",
            imported_by=imported_by
        )

        db.add(import_batch)
        db.flush()

        result = import_eu_xml(
            db=db,
            file_content=file_content
        )

        if result.get("total_records", 0) == 0:
            raise ValueError(
                "La liste UE a été téléchargée, mais aucune entrée n'a été lue. "
                "Le parser UE doit être vérifié."
            )

        import_batch.total_records = result["total_records"]
        import_batch.inserted_records = result["inserted_records"]
        import_batch.updated_records = result["updated_records"]
        import_batch.duplicate_records = result["duplicate_records"]
        import_batch.rejected_records = result["rejected_records"]
        import_batch.status = "SUCCESS"
        import_batch.error_message = None

        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="AUTO_UPDATE_EU",
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=(
                f"Mise à jour automatique UE terminée. "
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
            source_liste=source_liste,
            filename=filename,
            file_type=file_type,
            status="FAILED",
            imported_by=imported_by,
            error_message=str(e)[:1000]
        )

        db.add(failed_batch)
        db.flush()

        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="AUTO_UPDATE_EU_FAILED",
            entity_type="ImportBatch",
            entity_id=str(failed_batch.id),
            description=f"Échec mise à jour automatique UE : {str(e)[:500]}",
            ip_address=None
        )

        db.commit()
        db.refresh(failed_batch)

        raise

UN_XML_URL = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"


def auto_update_un_xml(
    db: Session,
    imported_by: str = "WEEKLY_SCHEDULER"
):
    source_liste = "ONU"
    filename = "un_consolidated.xml"
    file_type = "XML"

    try:
        response = requests.get(UN_XML_URL, timeout=90)
        response.raise_for_status()

        file_content = response.content
        file_hash = compute_file_hash(file_content)

        last_batch = get_last_success_batch(db, source_liste)

        if last_batch and getattr(last_batch, "file_hash", None) == file_hash:
            write_audit_log(
                db=db,
                user_identifier=imported_by,
                action="AUTO_UPDATE_UN_NO_CHANGE",
                entity_type="ImportBatch",
                entity_id=str(last_batch.id),
                description="Aucune modification détectée sur la liste ONU.",
                ip_address=None
            )
            db.commit()
            return last_batch

        import_batch = ImportBatch(
            source_liste=source_liste,
            filename=filename,
            file_type=file_type,
            file_hash=file_hash,
            status="PENDING",
            imported_by=imported_by
        )

        db.add(import_batch)
        db.flush()

        result = import_un_xml(
            db=db,
            file_content=file_content
        )

        import_batch.total_records = result["total_records"]
        import_batch.inserted_records = result["inserted_records"]
        import_batch.updated_records = result["updated_records"]
        import_batch.duplicate_records = result["duplicate_records"]
        import_batch.rejected_records = result["rejected_records"]
        import_batch.status = "SUCCESS"
        import_batch.error_message = None

        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="AUTO_UPDATE_UN",
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=(
                f"Mise à jour automatique ONU terminée. "
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
            source_liste=source_liste,
            filename=filename,
            file_type=file_type,
            status="FAILED",
            imported_by=imported_by,
            error_message=str(e)[:1000]
        )

        db.add(failed_batch)
        db.flush()

        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="AUTO_UPDATE_UN_FAILED",
            entity_type="ImportBatch",
            entity_id=str(failed_batch.id),
            description=f"Échec mise à jour automatique ONU : {str(e)[:500]}",
            ip_address=None
        )

        db.commit()
        db.refresh(failed_batch)

        raise

UKSL_CSV_URL = "https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.csv"


def auto_update_uksl_csv(db, imported_by: str = "SCHEDULER"):
    """
    Mise à jour automatique de la UK Sanctions List.
    Source normalisée en base : UKSL.
    """

    import_batch = ImportBatch(
        source_liste="UKSL",
        filename="UK-Sanctions-List.csv",
        file_type="CSV",
        status="PENDING",
        imported_by=imported_by,
    )

    db.add(import_batch)
    db.flush()

    try:
        response = requests.get(
            UKSL_CSV_URL,
            timeout=60,
            headers={
                "User-Agent": "BLACKMODULE-DEI/1.0"
            }
        )

        response.raise_for_status()

        file_content = response.content

        if not file_content:
            raise ValueError("Le fichier UKSL téléchargé est vide.")

        result = import_uksl_csv(
            db=db,
            file_content=file_content
        )

        if result.get("total_records", 0) == 0:
            raise ValueError(
                "Le fichier UKSL a été téléchargé, mais aucune ligne n'a été lue. "
                "Vérifiez le parser uksl_parser.py et les colonnes du fichier CSV officiel."
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
            action="AUTO_UPDATE_UKSL_CSV",
            entity_type="ImportBatch",
            entity_id=str(import_batch.id),
            description=(
                "Mise à jour automatique UK Sanctions List terminée. "
                f"Total : {import_batch.total_records}, "
                f"Insérés : {import_batch.inserted_records}, "
                f"Mis à jour : {import_batch.updated_records}, "
                f"Rejetés : {import_batch.rejected_records}."
            ),
            ip_address=None,
        )

        db.commit()
        db.refresh(import_batch)

        return {
            "success": True,
            "message": "Mise à jour UKSL effectuée avec succès.",
            "batch_id": import_batch.id,
            "source_liste": "UKSL",
            "total_records": import_batch.total_records,
            "inserted_records": import_batch.inserted_records,
            "updated_records": import_batch.updated_records,
            "rejected_records": import_batch.rejected_records,
        }


    except Exception as e:

        db.rollback()

        failed_batch = ImportBatch(

            source_liste="UKSL",

            filename="UK-Sanctions-List.csv",

            file_type="CSV",

            status="FAILED",

            imported_by=imported_by,

            error_message=str(e)[:1000],

        )

        db.add(failed_batch)

        db.flush()

        write_audit_log(

            db=db,

            user_identifier=imported_by,

            action="AUTO_UPDATE_UKSL_CSV_FAILED",

            entity_type="ImportBatch",

            entity_id=str(failed_batch.id),

            description=f"Échec mise à jour automatique UKSL : {str(e)[:500]}",

            ip_address=None,

        )

        db.commit()

        db.refresh(failed_batch)

        return {

            "success": False,

            "message": f"Erreur mise à jour UKSL : {str(e)}",

            "batch_id": failed_batch.id,

            "source_liste": "UKSL",

        }