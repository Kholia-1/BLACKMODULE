"""Backward-compatible OFAC update entry point.

The canonical implementation lives in ``list_update_service`` so every OFAC
attempt receives the same provenance and freshness handling.
"""

from sqlalchemy.orm import Session

from app.models import ImportBatch
from app.services.list_update_service import (
    OFAC_SDN_XML_URL,
    auto_update_ofac_sdn,
    calculate_file_hash,
    download_file,
)


def download_ofac_sdn_xml() -> bytes:
    return download_file(OFAC_SDN_XML_URL)


def update_ofac_sdn_from_official_source(
    db: Session, imported_by: str = "SCHEDULER"
) -> ImportBatch:
    return auto_update_ofac_sdn(db=db, imported_by=imported_by)
