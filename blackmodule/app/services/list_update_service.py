"""Official sanctions-list downloads, import history, and freshness monitoring."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Callable

import requests
from sqlalchemy.orm import Session

from app.models import AuditLog, ImportBatch
from app.services.audit_service import write_audit_log
from app.services.import_service import (
    import_eu_xml,
    import_france_gel_json,
    import_ofac_consolidated_xml,
    import_ofac_sdn_xml,
    import_uksl_csv,
    import_un_xml,
)
from app.services.list_version_service import SourceOperationInProgress, SuspiciousListDropError, synchronize_source_version
from app.services.parsers.ofac_sdn_parser import parse_ofac_sdn_xml
from app.services.parsers.ofac_consolidated_parser import parse_ofac_consolidated_xml
from app.services.parsers.france_gel_parser import parse_france_gel_json
from app.services.parsers.eu_parser import parse_eu_xml
from app.services.parsers.un_parser import parse_un_xml
from app.services.parsers.uksl_parser import parse_uksl_csv


# The legacy www.treasury.gov download URLs now reject automated requests. OFAC
# publishes the same files through its Sanctions List Service (SLS).
OFAC_SDN_XML_URL = (
    "https://sanctionslistservice.ofac.treas.gov/"
    "api/PublicationPreview/exports/SDN.XML"
)
OFAC_CONSOLIDATED_XML_URL = (
    "https://sanctionslistservice.ofac.treas.gov/"
    "api/PublicationPreview/exports/CONS_ADVANCED.XML"
)
FR_GEL_JSON_URL = (
    "https://gels-avoirs.dgtresor.gouv.fr/ApiPublic/api/v1/"
    "publication/derniere-publication-fichier-json"
)
EU_XML_URL = (
    "https://webgate.ec.europa.eu/fsd/fsf/public/files/"
    "xmlFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw"
)
UN_XML_URL = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"
UKSL_CSV_URL = "https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.csv"


@dataclass(frozen=True)
class OfficialSource:
    source_liste: str
    filename: str
    file_type: str
    url: str
    importer: Callable
    timeout_seconds: int
    maximum_age_days: int
    parser: Callable | None = None


@dataclass(frozen=True)
class DownloadedFile:
    content: bytes
    downloaded_at: datetime
    published_at: datetime | None
    file_hash: str
    file_size_bytes: int


OFFICIAL_SOURCES = {
    "OFAC_SDN": OfficialSource(
        "OFAC_SDN", "sdn.xml", "XML", OFAC_SDN_XML_URL,
        import_ofac_sdn_xml, 90, 2, parse_ofac_sdn_xml,
    ),
    "OFAC_CONSOLIDATED": OfficialSource(
        "OFAC_CONSOLIDATED", "cons_advanced.xml", "XML",
        OFAC_CONSOLIDATED_XML_URL, import_ofac_consolidated_xml, 90, 2,
        parse_ofac_consolidated_xml,
    ),
    "FR_GEL": OfficialSource(
        "FR_GEL", "france_gel.json", "JSON", FR_GEL_JSON_URL,
        import_france_gel_json, 90, 2, parse_france_gel_json,
    ),
    "UE": OfficialSource(
        "UE", "eu_financial_sanctions.xml", "XML", EU_XML_URL,
        import_eu_xml, 180, 9, parse_eu_xml,
    ),
    "ONU": OfficialSource(
        "ONU", "un_consolidated.xml", "XML", UN_XML_URL,
        import_un_xml, 90, 9, parse_un_xml,
    ),
    "UKSL": OfficialSource(
        "UKSL", "UK-Sanctions-List.csv", "CSV", UKSL_CSV_URL,
        import_uksl_csv, 90, 35, parse_uksl_csv,
    ),
}

# OFSI is intentionally manual-only. It still participates in freshness
# monitoring so that an outdated manual upload is visible to the application.
FRESHNESS_RULES = {
    source.source_liste: source.maximum_age_days
    for source in OFFICIAL_SOURCES.values()
} | {"OFSI": 35}


def calculate_file_hash(file_content: bytes) -> str:
    return hashlib.sha256(file_content).hexdigest()


def compute_file_hash(file_content: bytes) -> str:
    """Backward-compatible alias used by existing callers and tests."""
    return calculate_file_hash(file_content)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _published_at_from_headers(headers) -> datetime | None:
    last_modified = headers.get("Last-Modified") if headers else None
    if not last_modified:
        return None
    try:
        return parsedate_to_datetime(last_modified).astimezone(timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def _validate_content(file_content: bytes, file_type: str) -> None:
    if not file_content:
        raise ValueError("Le fichier telecharge est vide.")

    normalized = file_content.lstrip()
    if file_type == "XML" and not normalized.startswith(b"<"):
        raise ValueError("Le fichier telecharge ne semble pas etre un XML valide.")
    if file_type == "JSON":
        try:
            json.loads(normalized.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Le fichier telecharge ne semble pas etre un JSON valide.") from exc


def download_official_file(source: OfficialSource) -> DownloadedFile:
    """Download and validate one official source without logging sensitive data."""
    response = requests.get(
        source.url,
        headers={
            "User-Agent": "BLACKMODULE/2.0 (+official-list-import)",
            "Accept": "application/xml, application/json, text/csv, */*",
        },
        timeout=source.timeout_seconds,
    )
    response.raise_for_status()
    content_length = response.headers.get("Content-Length")
    content_encoding = response.headers.get("Content-Encoding")
    if content_length and not content_encoding:
        try:
            if int(content_length) != len(response.content):
                raise ValueError(
                    f"Téléchargement incomplet: {len(response.content)} octets reçus sur {content_length} annoncés."
                )
        except ValueError as exc:
            if "Téléchargement incomplet" in str(exc):
                raise
    _validate_content(response.content, source.file_type)

    return DownloadedFile(
        content=response.content,
        downloaded_at=_utc_now(),
        published_at=_published_at_from_headers(response.headers),
        file_hash=calculate_file_hash(response.content),
        file_size_bytes=len(response.content),
    )


def download_file(url: str) -> bytes:
    """Compatibility helper for callers that previously downloaded OFAC XML."""
    source = OfficialSource("COMPAT", "download.xml", "XML", url, lambda **_: {}, 90, 1)
    return download_official_file(source).content


def get_last_success_batch(db: Session, source_liste: str) -> ImportBatch | None:
    return (
        db.query(ImportBatch)
        .filter(ImportBatch.source_liste == source_liste, ImportBatch.status == "SUCCESS")
        .order_by(ImportBatch.imported_at.desc())
        .first()
    )


def was_file_already_imported(
    db: Session, source_liste: str, file_hash: str
) -> ImportBatch | None:
    return (
        db.query(ImportBatch)
        .filter(
            ImportBatch.source_liste == source_liste,
            ImportBatch.status == "SUCCESS",
            ImportBatch.file_hash == file_hash,
        )
        .order_by(ImportBatch.imported_at.desc())
        .first()
    )


def _batch_for_download(
    source: OfficialSource,
    imported_by: str,
    downloaded: DownloadedFile | None = None,
    *,
    status: str = "PENDING",
    error_message: str | None = None,
) -> ImportBatch:
    return ImportBatch(
        source_liste=source.source_liste,
        filename=source.filename,
        file_type=source.file_type,
        status=status,
        imported_by=imported_by,
        source_url=source.url,
        downloaded_at=downloaded.downloaded_at if downloaded else _utc_now(),
        published_at=downloaded.published_at if downloaded else None,
        file_size_bytes=downloaded.file_size_bytes if downloaded else None,
        file_hash=downloaded.file_hash if downloaded else None,
        error_message=error_message,
    )


def queue_official_update(db: Session, source_key: str, imported_by: str) -> ImportBatch:
    """Persist a quick, traceable request before the scheduler does the work."""
    source = OFFICIAL_SOURCES[source_key]
    running = db.query(ImportBatch).filter(
        ImportBatch.source_liste == source.source_liste,
        ImportBatch.status == "EN_COURS",
    ).first()
    if running:
        raise SourceOperationInProgress(
            f"Une mise a jour {source.source_liste} est déjà en cours ({running.id})."
        )
    batch = _batch_for_download(source, imported_by, status="EN_COURS")
    db.add(batch)
    db.flush()
    _write_import_audit(
        db, batch, imported_by, f"AUTO_UPDATE_{source.source_liste}_QUEUED",
        f"Mise a jour officielle {source.source_liste} programmee.",
    )
    db.commit()
    db.refresh(batch)
    return batch


def interrupted_official_updates(db: Session) -> list[ImportBatch]:
    """Rows persisted before a process stop are safely re-scheduled on boot."""
    return db.query(ImportBatch).filter(
        ImportBatch.status == "EN_COURS",
        ImportBatch.source_liste.in_([source.source_liste for source in OFFICIAL_SOURCES.values()]),
    ).all()


def mark_interrupted_update_failed(
    db: Session, batch_id, source_key: str, imported_by: str, error: Exception,
) -> None:
    """Last-resort terminal state if the worker fails outside _auto_update."""
    batch = db.query(ImportBatch).filter(ImportBatch.id == batch_id).first()
    if not batch or batch.status != "EN_COURS":
        return
    batch.status = "FAILED"
    batch.error_message = str(error)[:1000]
    _write_import_audit(
        db, batch, imported_by, f"AUTO_UPDATE_{source_key}_FAILED",
        "Echec inattendu du traitement programme; reprise possible par une nouvelle demande.",
    )
    db.commit()


def _apply_import_result(import_batch: ImportBatch, result: dict) -> None:
    if result.get("total_records", 0) <= 0:
        raise ValueError(
            "Le fichier officiel a ete telecharge, mais aucune entree n'a ete lue. "
            "Le parser doit etre verifie avant une nouvelle tentative."
        )
    import_batch.total_records = result["total_records"]
    import_batch.inserted_records = result["inserted_records"]
    import_batch.updated_records = result["updated_records"]
    import_batch.duplicate_records = result["duplicate_records"]
    import_batch.rejected_records = result["rejected_records"]
    import_batch.status = "SUCCESS"
    import_batch.error_message = None


def _write_import_audit(
    db: Session, import_batch: ImportBatch, imported_by: str, action: str, description: str
) -> None:
    write_audit_log(
        db=db,
        user_identifier=imported_by,
        action=action,
        entity_type="ImportBatch",
        entity_id=str(import_batch.id),
        description=description,
        ip_address=None,
    )


def _record_failed_attempt(
    db: Session,
    source: OfficialSource,
    imported_by: str,
    error: Exception,
    downloaded: DownloadedFile | None,
    existing_batch_id=None,
) -> ImportBatch:
    review_required = isinstance(error, SuspiciousListDropError)
    failed_batch = db.query(ImportBatch).filter(ImportBatch.id == existing_batch_id).first() if existing_batch_id else None
    if not failed_batch:
        failed_batch = _batch_for_download(source, imported_by, downloaded)
        db.add(failed_batch)
    if downloaded:
        failed_batch.downloaded_at = downloaded.downloaded_at
        failed_batch.published_at = downloaded.published_at
        failed_batch.file_size_bytes = downloaded.file_size_bytes
        failed_batch.file_hash = downloaded.file_hash
    failed_batch.status = "A_VERIFIER" if review_required else "FAILED"
    failed_batch.error_message = str(error)[:1000]
    db.flush()
    _write_import_audit(
        db,
        failed_batch,
        imported_by,
        f"AUTO_UPDATE_{source.source_liste}_{'REVIEW_REQUIRED' if review_required else 'FAILED'}",
        f"Echec de mise a jour automatique {source.source_liste}: {str(error)[:500]}",
    )
    write_audit_log(
        db=db,
        user_identifier=imported_by,
        action="LIST_UPDATE_ALERT",
        entity_type="ListFreshness",
        entity_id=source.source_liste,
        description=(
            f"Alerte applicative: la mise a jour automatique {source.source_liste} "
            f"a {'été bloquée pour vérification' if review_required else 'échoué'}. {str(error)[:500]}"
        ),
        ip_address=None,
    )
    db.commit()
    db.refresh(failed_batch)
    return failed_batch


def _auto_update(db: Session, source: OfficialSource, imported_by: str, existing_batch_id=None) -> ImportBatch:
    downloaded: DownloadedFile | None = None
    try:
        downloaded = download_official_file(source)
        previous_batch = was_file_already_imported(
            db, source.source_liste, downloaded.file_hash
        )

        if previous_batch:
            # A successful check with identical data remains an explicit attempt:
            # it drives both last_attempt and last_success freshness indicators.
            import_batch = db.query(ImportBatch).filter(ImportBatch.id == existing_batch_id).first() if existing_batch_id else None
            if not import_batch:
                import_batch = _batch_for_download(source, imported_by, downloaded, status="SUCCESS")
                db.add(import_batch)
            import_batch.downloaded_at = downloaded.downloaded_at
            import_batch.published_at = downloaded.published_at
            import_batch.file_size_bytes = downloaded.file_size_bytes
            import_batch.file_hash = downloaded.file_hash
            import_batch.status = "SUCCESS"
            import_batch.total_records = previous_batch.total_records
            db.flush()
            _write_import_audit(
                db,
                import_batch,
                imported_by,
                f"AUTO_UPDATE_{source.source_liste}_NO_CHANGE",
                f"Aucune modification detectee sur la liste officielle {source.source_liste}.",
            )
            db.commit()
            db.refresh(import_batch)
            return import_batch

        import_batch = db.query(ImportBatch).filter(ImportBatch.id == existing_batch_id).first() if existing_batch_id else None
        if not import_batch:
            import_batch = _batch_for_download(source, imported_by, downloaded)
            db.add(import_batch)
        else:
            import_batch.downloaded_at = downloaded.downloaded_at
            import_batch.published_at = downloaded.published_at
            import_batch.file_size_bytes = downloaded.file_size_bytes
            import_batch.file_hash = downloaded.file_hash
        db.flush()
        if source.parser:
            # The reconciliation owns delist/reactivate decisions.  It is
            # deliberately source-scoped and uses official IDs when present;
            # no fuzzy matching is ever used for a regulatory list update.
            _, result = synchronize_source_version(
                db,
                source_liste=source.source_liste,
                import_batch=import_batch,
                source_url=source.url,
                downloaded_at=downloaded.downloaded_at,
                published_at=downloaded.published_at,
                file_hash=downloaded.file_hash,
                archive_content=downloaded.content,
                entries=source.parser(downloaded.content),
                imported_by=imported_by,
            )
        else:
            result = source.importer(db=db, file_content=downloaded.content)
        _apply_import_result(import_batch, result)
        _write_import_audit(
            db,
            import_batch,
            imported_by,
            f"AUTO_UPDATE_{source.source_liste}",
            (
                f"Mise a jour automatique {source.source_liste} terminee. "
                f"Total: {import_batch.total_records}, inseres: {import_batch.inserted_records}, "
                f"mis a jour: {import_batch.updated_records}, rejetes: {import_batch.rejected_records}."
            ),
        )
        db.commit()
        db.refresh(import_batch)
        return import_batch
    except Exception as error:
        db.rollback()
        _record_failed_attempt(db, source, imported_by, error, downloaded, existing_batch_id)
        raise


def auto_update_ofac_sdn(db: Session, imported_by: str = "DAILY_SCHEDULER", existing_batch_id=None) -> ImportBatch:
    return _auto_update(db, OFFICIAL_SOURCES["OFAC_SDN"], imported_by, existing_batch_id)


def auto_update_ofac_consolidated(
    db: Session, imported_by: str = "DAILY_SCHEDULER", existing_batch_id=None
) -> ImportBatch:
    return _auto_update(db, OFFICIAL_SOURCES["OFAC_CONSOLIDATED"], imported_by, existing_batch_id)


def auto_update_france_gel(db: Session, imported_by: str = "DAILY_SCHEDULER", existing_batch_id=None) -> ImportBatch:
    return _auto_update(db, OFFICIAL_SOURCES["FR_GEL"], imported_by, existing_batch_id)


def auto_update_eu_xml(db: Session, imported_by: str = "WEEKLY_SCHEDULER", existing_batch_id=None) -> ImportBatch:
    return _auto_update(db, OFFICIAL_SOURCES["UE"], imported_by, existing_batch_id)


def auto_update_un_xml(db: Session, imported_by: str = "WEEKLY_SCHEDULER", existing_batch_id=None) -> ImportBatch:
    return _auto_update(db, OFFICIAL_SOURCES["ONU"], imported_by, existing_batch_id)


def auto_update_uksl_csv(db: Session, imported_by: str = "SCHEDULER", existing_batch_id=None) -> ImportBatch:
    return _auto_update(db, OFFICIAL_SOURCES["UKSL"], imported_by, existing_batch_id)


def get_list_freshness(db: Session, now: datetime | None = None) -> list[dict]:
    """Return the persisted freshness state for every monitored official list."""
    current_time = now or _utc_now()
    freshness = []
    for source_liste, maximum_age_days in FRESHNESS_RULES.items():
        last_attempt = (
            db.query(ImportBatch)
            .filter(ImportBatch.source_liste == source_liste)
            .order_by(ImportBatch.imported_at.desc())
            .first()
        )
        last_success = get_last_success_batch(db, source_liste)
        last_success_at = last_success.imported_at if last_success else None
        age_days = None
        if last_success_at:
            age_days = max(0, (current_time - last_success_at).total_seconds() / 86400)

        if last_attempt and last_attempt.status in {"FAILED", "A_VERIFIER"}:
            status = "ECHEC"
        elif not last_success_at or age_days is None or age_days > maximum_age_days:
            status = "EN_RETARD"
        else:
            status = "FRAICHE"

        freshness.append({
            "source": source_liste,
            "status": status,
            "maximum_age_days": maximum_age_days,
            "last_success": last_success_at,
            "last_attempt": last_attempt.imported_at if last_attempt else None,
            "last_attempt_status": last_attempt.status if last_attempt else None,
            "age_days": age_days,
        })
    return freshness


def emit_list_freshness_alerts(db: Session, imported_by: str = "LIST_MONITOR") -> list[dict]:
    """Emit one audit-visible application alert per stale period, not every day."""
    alerts = []
    for item in get_list_freshness(db):
        if item["status"] != "EN_RETARD":
            continue

        last_alert = (
            db.query(AuditLog)
            .filter(
                AuditLog.action == "LIST_UPDATE_ALERT",
                AuditLog.entity_type == "ListFreshness",
                AuditLog.entity_id == item["source"],
            )
            .order_by(AuditLog.created_at.desc())
            .first()
        )
        if last_alert and (
            item["last_success"] is None or last_alert.created_at >= item["last_success"]
        ):
            continue

        write_audit_log(
            db=db,
            user_identifier=imported_by,
            action="LIST_UPDATE_ALERT",
            entity_type="ListFreshness",
            entity_id=item["source"],
            description=(
                f"Alerte applicative: la liste {item['source']} est EN_RETARD "
                f"(seuil {item['maximum_age_days']} jours)."
            ),
            ip_address=None,
        )
        alerts.append(item)
    if alerts:
        db.commit()
    return alerts
