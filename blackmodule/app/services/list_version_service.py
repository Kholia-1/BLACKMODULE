"""Safe, source-scoped versioning and four-eyes restoration of official lists."""

from __future__ import annotations

import gzip
import json
import uuid
from datetime import date, datetime
from typing import Iterable

from sqlalchemy import text
from sqlalchemy.orm import Session, load_only, selectinload

from app.config import LIST_MAX_ENTRY_DROP_PERCENT
from app.models import (
    ImportBatch,
    ListVersion,
    ListVersionActivation,
    ListVersionEntry,
    SanctionAlias,
    SanctionEntry,
)
from app.services.audit_service import write_audit_log
from app.services.parsers.eu_parser import parse_eu_xml
from app.services.parsers.france_gel_parser import parse_france_gel_json
from app.services.parsers.ofac_consolidated_parser import parse_ofac_consolidated_xml
from app.services.parsers.ofac_sdn_parser import parse_ofac_sdn_xml
from app.services.parsers.uksl_parser import parse_uksl_csv
from app.services.parsers.un_parser import parse_un_xml


ACTIVE = "ACTIVE"
ARCHIVED = "ARCHIVED"
ENTRY_ACTIVE = "ACTIF"
LEGACY_ENTRY_ACTIVE = "ACTIVE"
DELISTED = "RADIEE"

CHANGE_ADDED = "AJOUT"
CHANGE_MODIFIED = "MODIFICATION"
CHANGE_DELISTED = "RADIATION"
CHANGE_REACTIVATED = "REACTIVATION"
CHANGE_UNCHANGED = "INCHANGE"

ACTIVATION_IMPORT = "IMPORT"
ACTIVATION_RESTORE = "RESTAURATION"


def _entry_is_active(entry: SanctionEntry) -> bool:
    return entry.statut in {ENTRY_ACTIVE, LEGACY_ENTRY_ACTIVE}


class SuspiciousListDropError(ValueError):
    """Raised before mutation when a parsed list shrinks beyond the safety threshold."""


class SourceOperationInProgress(ValueError):
    """Raised when another transaction already updates/restores the same source."""


class NonRestorableVersionError(ValueError):
    """Raised when a version has no usable source archive."""


class ObsoleteRestoreRequest(ValueError):
    """Raised when the current version changed after the restore request was created."""


ARCHIVE_PARSERS = {
    "OFAC_SDN": parse_ofac_sdn_xml,
    "OFAC_CONSOLIDATED": parse_ofac_consolidated_xml,
    "FR_GEL": parse_france_gel_json,
    "UE": parse_eu_xml,
    "ONU": parse_un_xml,
    "UKSL": parse_uksl_csv,
}


def _official_entry_options():
    """Avoid loading LOT 2C-only columns in 50k official-list operations."""
    return (
        load_only(
            SanctionEntry.id, SanctionEntry.source_liste, SanctionEntry.source_record_id,
            SanctionEntry.type_entite, SanctionEntry.nom, SanctionEntry.prenom,
            SanctionEntry.nom_complet, SanctionEntry.date_naissance,
            SanctionEntry.lieu_naissance, SanctionEntry.nationalite, SanctionEntry.pays,
            SanctionEntry.num_passeport, SanctionEntry.autres_documents,
            SanctionEntry.motif_sanction, SanctionEntry.date_inscription,
            SanctionEntry.date_suppression, SanctionEntry.statut,
            SanctionEntry.hash_signature, SanctionEntry.delisted_at,
            SanctionEntry.delisted_by_version_id,
        ),
        selectinload(SanctionEntry.aliases),
    )


def _json_value(value):
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return value


def _stable_source_id(item: dict) -> str | None:
    """Return an exact source-scoped ID; names and fuzzy matching are forbidden."""
    for key in ("source_record_id", "reference_externe", "uid", "record_id", "id"):
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()[:255]
    value = item.get("hash_signature")
    has_secondary_identifier = any(
        item.get(key)
        for key in ("date_naissance", "num_passeport")
    )
    if value and has_secondary_identifier:
        return f"HASH:{str(value).strip()}"[:255]
    return None


def _entry_snapshot(entry: SanctionEntry) -> dict:
    return {
        "source_liste": entry.source_liste,
        "source_record_id": entry.source_record_id or entry.hash_signature,
        "type_entite": entry.type_entite,
        "nom": entry.nom,
        "prenom": entry.prenom,
        "nom_complet": entry.nom_complet,
        "date_naissance": _json_value(entry.date_naissance),
        "lieu_naissance": entry.lieu_naissance,
        "nationalite": entry.nationalite,
        "pays": entry.pays,
        "num_passeport": entry.num_passeport,
        "autres_documents": entry.autres_documents,
        "motif_sanction": entry.motif_sanction,
        "date_inscription": _json_value(entry.date_inscription),
        "date_suppression": _json_value(entry.date_suppression),
        "statut": entry.statut,
        "hash_signature": entry.hash_signature,
        "aliases": sorted(alias.alias for alias in entry.aliases),
    }


def _item_snapshot(item: dict, source_liste: str, source_record_id: str) -> dict:
    aliases = sorted({str(alias).strip() for alias in item.get("aliases", []) if str(alias).strip()})
    return {
        "source_liste": source_liste,
        "source_record_id": source_record_id,
        "type_entite": item.get("type_entite") or "PERSONNE_PHYSIQUE",
        "nom": item.get("nom") or "",
        "prenom": item.get("prenom"),
        "nom_complet": item.get("nom_complet"),
        "date_naissance": _json_value(item.get("date_naissance")),
        "lieu_naissance": item.get("lieu_naissance"),
        "nationalite": item.get("nationalite"),
        "pays": item.get("pays"),
        "num_passeport": item.get("num_passeport"),
        "autres_documents": item.get("autres_documents"),
        "motif_sanction": item.get("motif_sanction"),
        "date_inscription": _json_value(item.get("date_inscription")),
        "date_suppression": _json_value(item.get("date_suppression")),
        "statut": ENTRY_ACTIVE,
        "hash_signature": item.get("hash_signature"),
        "aliases": aliases,
    }


def _scalar_snapshot(snapshot: dict) -> dict:
    return {key: value for key, value in snapshot.items() if key not in {"statut", "aliases"}}


def _snapshot_differs(current: dict, target: dict) -> bool:
    if _scalar_snapshot(current) != _scalar_snapshot(target):
        return True
    return not set(target.get("aliases", [])).issubset(set(current.get("aliases", [])))


def _apply_item(entry: SanctionEntry, snapshot: dict) -> bool:
    for field in (
        "type_entite", "nom", "prenom", "nom_complet", "date_naissance", "lieu_naissance",
        "nationalite", "pays", "num_passeport", "autres_documents", "motif_sanction",
        "date_inscription", "date_suppression", "hash_signature",
    ):
        value = snapshot[field]
        if field in {"date_naissance", "date_inscription", "date_suppression"} and isinstance(value, str):
            value = date.fromisoformat(value) if value else None
        setattr(entry, field, value)
    entry.source_record_id = snapshot["source_record_id"]
    entry.statut = ENTRY_ACTIVE
    entry.delisted_at = None
    entry.delisted_by_version_id = None

    existing_aliases = {alias.alias for alias in entry.aliases}
    aliases_added = False
    for alias in snapshot["aliases"]:
        if alias not in existing_aliases:
            entry.aliases.append(SanctionAlias(alias=alias))
            existing_aliases.add(alias)
            aliases_added = True
    return aliases_added


def _new_entry(snapshot: dict) -> SanctionEntry:
    entry = SanctionEntry(id=uuid.uuid4(), source_liste=snapshot["source_liste"], **{
        field: snapshot[field]
        for field in (
            "source_record_id", "type_entite", "nom", "prenom", "nom_complet", "date_naissance",
            "lieu_naissance", "nationalite", "pays", "num_passeport", "autres_documents",
            "motif_sanction", "date_inscription", "date_suppression", "hash_signature",
        )
    })
    _apply_item(entry, snapshot)
    return entry


def _acquire_source_lock(db: Session, source_liste: str) -> None:
    """Acquire a PostgreSQL transaction lock scoped to one list source."""
    if db.get_bind().dialect.name != "postgresql":
        return
    locked = db.execute(
        text("SELECT pg_try_advisory_xact_lock(hashtext(:source_liste))"),
        {"source_liste": source_liste},
    ).scalar()
    if not locked:
        raise SourceOperationInProgress(
            f"Une mise à jour ou restauration de {source_liste} est déjà en cours."
        )


def _archive_for_storage(raw_content: bytes) -> bytes:
    return gzip.compress(raw_content, compresslevel=6, mtime=0)


def _raw_archive(version: ListVersion) -> bytes:
    if not version.archive_content:
        raise NonRestorableVersionError("Version non restaurable : archive source absente.")
    if version.archive_compression == "gzip":
        try:
            return gzip.decompress(version.archive_content)
        except (OSError, EOFError) as exc:
            raise NonRestorableVersionError("Version non restaurable : archive gzip invalide.") from exc
    return bytes(version.archive_content)


def is_version_restorable(version: ListVersion) -> bool:
    return bool(version.archive_content) and version.source_liste in ARCHIVE_PARSERS


def _snapshots_from_archive(version: ListVersion) -> dict[str, dict]:
    if not is_version_restorable(version):
        raise NonRestorableVersionError("Version non restaurable : archive ou parseur indisponible.")
    parsed = ARCHIVE_PARSERS[version.source_liste](_raw_archive(version))
    snapshots = {}
    for item in parsed:
        source_record_id = _stable_source_id(item)
        if not source_record_id or not (item.get("nom") or item.get("nom_complet")):
            continue
        if source_record_id in snapshots:
            raise NonRestorableVersionError("Archive ambiguë : identifiant source dupliqué.")
        snapshots[source_record_id] = _item_snapshot(item, version.source_liste, source_record_id)
    if not snapshots:
        raise NonRestorableVersionError("Version non restaurable : archive sans entrée exploitable.")
    return snapshots


def _validated_items(entries: Iterable[dict], source_liste: str) -> tuple[list[tuple[str, dict]], int, int]:
    parsed = list(entries)
    valid = []
    seen = set()
    rejected = 0
    for item in parsed:
        source_record_id = _stable_source_id(item)
        if not source_record_id or not (item.get("nom") or item.get("nom_complet")):
            rejected += 1
            continue
        if source_record_id in seen:
            raise ValueError(f"Identifiant source dupliqué dans {source_liste}: {source_record_id}")
        seen.add(source_record_id)
        valid.append((source_record_id, item))
    if not valid:
        raise SuspiciousListDropError(f"Mise à jour {source_liste} bloquée : aucune entrée exploitable.")
    return valid, len(parsed), rejected


def synchronize_source_version(
    db: Session,
    *,
    source_liste: str,
    import_batch: ImportBatch,
    source_url: str | None,
    downloaded_at: datetime | None,
    published_at: datetime | None,
    file_hash: str,
    archive_content: bytes,
    entries: Iterable[dict],
    imported_by: str,
) -> tuple[ListVersion, dict]:
    """Validate then reconcile one source atomically; caller owns commit/rollback."""
    _acquire_source_lock(db, source_liste)
    existing_version = db.query(ListVersion).filter(
        ListVersion.source_liste == source_liste,
        ListVersion.file_hash == file_hash,
    ).first()
    if existing_version:
        return existing_version, {
            "total_records": existing_version.total_entries,
            "inserted_records": 0, "updated_records": 0,
            "duplicate_records": existing_version.active_entries,
            "rejected_records": 0, "delisted_records": 0, "reactivated_records": 0,
        }

    valid_items, parsed_count, rejected = _validated_items(entries, source_liste)
    current_entries = db.query(SanctionEntry).options(
        *_official_entry_options()
    ).filter(SanctionEntry.source_liste == source_liste).all()
    previous_active_count = sum(_entry_is_active(entry) for entry in current_entries)
    accepted_count = len(valid_items)
    minimum_allowed = previous_active_count * (1 - LIST_MAX_ENTRY_DROP_PERCENT / 100)
    if previous_active_count and accepted_count < minimum_allowed:
        drop_percent = 100 * (previous_active_count - accepted_count) / previous_active_count
        raise SuspiciousListDropError(
            f"Mise à jour {source_liste} A_VERIFIER : baisse de {drop_percent:.1f}% "
            f"({previous_active_count} vers {accepted_count}), seuil {LIST_MAX_ENTRY_DROP_PERCENT:.1f}%."
        )

    # The reference is the activated version, not the most recently created
    # snapshot.  A restored version can therefore legitimately predate other
    # archived snapshots.
    previous_version = get_active_version(db, source_liste, lock=True)
    version = ListVersion(
        source_liste=source_liste,
        technical_version=file_hash[:16],
        import_batch_id=import_batch.id,
        source_url=source_url,
        downloaded_at=downloaded_at,
        published_at=published_at,
        file_hash=file_hash,
        archive_content=_archive_for_storage(archive_content),
        archive_compression="gzip",
        status=ACTIVE,
    )
    db.add(version)
    db.flush()

    by_source_id = {entry.source_record_id: entry for entry in current_entries if entry.source_record_id}
    by_hash = {entry.hash_signature: entry for entry in current_entries if entry.hash_signature}
    changes: dict[object, str] = {}
    seen_ids: set[object] = set()
    inserted = updated = reactivated = 0

    for source_record_id, item in valid_items:
        snapshot = _item_snapshot(item, source_liste, source_record_id)
        entry = by_source_id.get(source_record_id) or by_hash.get(snapshot["hash_signature"])
        if entry is None:
            entry = _new_entry(snapshot)
            db.add(entry)
            current_entries.append(entry)
            by_source_id[source_record_id] = entry
            if entry.hash_signature:
                by_hash[entry.hash_signature] = entry
            inserted += 1
            changes[entry.id] = CHANGE_ADDED
        else:
            before = _entry_snapshot(entry)
            was_delisted = entry.statut == DELISTED
            aliases_added = _apply_item(entry, snapshot)
            if was_delisted:
                reactivated += 1
                changes[entry.id] = CHANGE_REACTIVATED
            elif _scalar_snapshot(before) != _scalar_snapshot(snapshot) or aliases_added:
                updated += 1
                changes[entry.id] = CHANGE_MODIFIED
        seen_ids.add(entry.id)

    delisted = 0
    history_pending = 0
    for entry in current_entries:
        if entry.id not in seen_ids and entry.statut != DELISTED:
            entry.statut = DELISTED
            entry.delisted_at = datetime.utcnow()
            entry.delisted_by_version_id = version.id
            changes[entry.id] = CHANGE_DELISTED
            delisted += 1

    if previous_version and previous_version.id != version.id:
        previous_version.status = ARCHIVED
    db.flush()

    for entry in current_entries:
        change_type = changes.get(entry.id)
        if not change_type:
            continue
        snapshot = {"source_record_id": entry.source_record_id} if change_type == CHANGE_ADDED else _entry_snapshot(entry)
        db.add(ListVersionEntry(
            list_version_id=version.id,
            sanction_entry_id=entry.id,
            source_record_id=entry.source_record_id or entry.hash_signature or str(entry.id),
            change_type=change_type,
            entry_snapshot=json.dumps(snapshot, ensure_ascii=False, sort_keys=True),
        ))
        history_pending += 1
        if history_pending >= 1000:
            db.flush()
            history_pending = 0
    if history_pending:
        db.flush()
    db.add(ListVersionActivation(
        source_liste=source_liste,
        version_id=version.id,
        previous_version_id=previous_version.id if previous_version else None,
        activation_type=ACTIVATION_IMPORT,
        reason="Mise à jour officielle",
        activated_by=imported_by,
    ))

    version.total_entries = accepted_count
    version.active_entries = accepted_count
    version.added_entries = inserted
    version.modified_entries = updated
    version.delisted_entries = delisted
    version.reactivated_entries = reactivated
    import_batch.delisted_records = delisted
    import_batch.reactivated_records = reactivated
    write_audit_log(
        db, imported_by, "LIST_VERSION_CREATED", "ListVersion", str(version.id),
        f"Version {source_liste} créée: ajout={inserted}, modif={updated}, radiation={delisted}, réactivation={reactivated}.",
        None,
    )
    return version, {
        "total_records": parsed_count,
        "inserted_records": inserted,
        "updated_records": updated,
        "duplicate_records": max(0, accepted_count - inserted - updated - reactivated),
        "rejected_records": rejected,
        "delisted_records": delisted,
        "reactivated_records": reactivated,
    }


def get_active_version(
    db: Session, source_liste: str, *, lock: bool = False
) -> ListVersion | None:
    """Return the sole active version for a source (never the newest row)."""
    query = db.query(ListVersion).filter(
        ListVersion.source_liste == source_liste,
        ListVersion.status == ACTIVE,
    )
    if lock:
        query = query.with_for_update()
    return query.first()


def get_version_preview(db: Session, target_version: ListVersion) -> dict:
    """Compute source-scoped impact from the archived source without writing."""
    target = _snapshots_from_archive(target_version)
    current_entries = db.query(SanctionEntry).options(
        *_official_entry_options()
    ).filter(SanctionEntry.source_liste == target_version.source_liste).all()
    current = {entry.source_record_id or entry.hash_signature: entry for entry in current_entries}
    reactivated = sum(key not in current or not _entry_is_active(current[key]) for key in target)
    delisted = sum(key not in target and _entry_is_active(entry) for key, entry in current.items())
    modified = sum(
        key in current and _snapshot_differs(_entry_snapshot(current[key]), snapshot)
        for key, snapshot in target.items()
    )
    return {
        "source_liste": target_version.source_liste,
        "version_id": str(target_version.id),
        "reactivated": reactivated,
        "delisted": delisted,
        "modified": modified,
        "total_target_entries": len(target),
    }


def apply_version_restore(
    db: Session,
    *,
    target_version_id: str,
    expected_current_version_id: str,
    reviewer_username: str,
    reason: str | None = None,
) -> None:
    """Apply an approved restore only if its expected source state is still current."""
    try:
        target_id = uuid.UUID(str(target_version_id))
        expected_id = uuid.UUID(str(expected_current_version_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("Identifiant de version invalide.") from exc
    target_version = db.query(ListVersion).filter(ListVersion.id == target_id).first()
    if not target_version:
        raise ValueError("Version cible introuvable.")
    if not is_version_restorable(target_version):
        raise NonRestorableVersionError("Cette version est non restaurable : archive source absente.")

    _acquire_source_lock(db, target_version.source_liste)
    current_version = get_active_version(db, target_version.source_liste, lock=True)
    if not current_version or current_version.id != expected_id:
        raise ObsoleteRestoreRequest(
            "Demande OBSOLETE : la version courante a changé. Une nouvelle prévisualisation est requise."
        )

    target = _snapshots_from_archive(target_version)
    source_entries = db.query(SanctionEntry).options(
        *_official_entry_options()
    ).filter(SanctionEntry.source_liste == target_version.source_liste).all()
    current = {entry.source_record_id or entry.hash_signature: entry for entry in source_entries}
    for source_record_id, snapshot in target.items():
        entry = current.get(source_record_id)
        if entry:
            _apply_item(entry, snapshot)
        else:
            entry = _new_entry(snapshot)
            db.add(entry)
            current[source_record_id] = entry
    for source_record_id, entry in current.items():
        if source_record_id not in target and _entry_is_active(entry):
            entry.statut = DELISTED
            entry.delisted_at = datetime.utcnow()
            entry.delisted_by_version_id = target_version.id

    if current_version.id != target_version.id:
        current_version.status = ARCHIVED
    target_version.status = ACTIVE
    db.add(ListVersionActivation(
        source_liste=target_version.source_liste,
        version_id=target_version.id,
        previous_version_id=current_version.id,
        activation_type=ACTIVATION_RESTORE,
        reason=reason,
        activated_by=reviewer_username,
    ))
    write_audit_log(
        db, reviewer_username, "LIST_VERSION_RESTORED", "ListVersion", str(target_version.id),
        f"Version active restaurée à partir de {target_version.technical_version} ({target_version.source_liste}).",
        None,
    )
