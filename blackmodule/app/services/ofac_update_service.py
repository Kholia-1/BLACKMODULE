import hashlib
import requests
from sqlalchemy.orm import Session

from app.models import ImportBatch
from app.services.import_service import import_ofac_sdn_xml
from app.services.audit_service import write_audit_log


OFAC_SDN_XML_URL = "https://www.treasury.gov/ofac/downloads/sdn.xml"


def calculate_file_hash(file_content: bytes) -> str:
    return hashlib.sha256(file_content).hexdigest()


def download_ofac_sdn_xml() -> bytes:
    response = requests.get(
        OFAC_SDN_XML_URL,
        timeout=60
    )

    response.raise_for_status()

    if not response.content:
        raise ValueError("Le fichier OFAC SDN téléchargé est vide.")

    if b"<sdnList" not in response.content and b"sdnList" not in response.content:
        raise ValueError("Le fichier téléchargé ne semble pas être un XML OFAC SDN valide.")

    return response.content


def update_ofac_sdn_from_official_source(
    db: Session,
    imported_by: str = "SCHEDULER"
) -> ImportBatch:
    file_content = download_ofac_sdn_xml()
    file_hash = calculate_file_hash(file_content)

    existing_same_file = db.query(ImportBatch).filter(
        ImportBatch.source_liste == "OFAC_SDN",
        ImportBatch.status == "SUCCESS",
        ImportBatch.error_message == file_hash
    ).first()

    if existing_same_file:
        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="OFAC_SDN_NO_CHANGE",
            entity_type="ImportBatch",
            entity_id=str(existing_same_file.id),
            description="Aucune mise à jour OFAC SDN : le fichier officiel est identique au dernier import.",
            ip_address=None
        )

        db.commit()
        return existing_same_file

    import_batch = ImportBatch(
        source_liste="OFAC_SDN",
        filename="sdn.xml",
        file_type="XML",
        status="PENDING",
        imported_by=imported_by,
        error_message=file_hash
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
                f"Mise à jour automatique OFAC SDN depuis la source officielle. "
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
            description=f"Échec de la mise à jour automatique OFAC SDN : {str(e)}",
            ip_address=None
        )

        db.commit()
        db.refresh(import_batch)

        raise
