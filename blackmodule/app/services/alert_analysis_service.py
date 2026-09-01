import hashlib

from sqlalchemy.orm import Session, selectinload

from app.models import Alert, SanctionEntry
from app.services.matching_service import _document_identifiers, normalize_identifier, normalize_name


def _entry_names(entry: SanctionEntry) -> set[str]:
    names = {normalize_name(entry.nom_complet), normalize_name(f"{entry.prenom or ''} {entry.nom or ''}")}
    names.update(normalize_name(alias.alias) for alias in entry.aliases if alias.alias)
    names.discard("")
    return names


def _same_probable_person(first: SanctionEntry, second: SanctionEntry) -> tuple[bool, list[str]]:
    signals: list[str] = []
    first_passport = normalize_identifier(first.num_passeport)
    second_passport = normalize_identifier(second.num_passeport)
    first_document = normalize_identifier(first.document_number)
    second_document = normalize_identifier(second.document_number)
    shared_published_documents = _document_identifiers(first).intersection(
        _document_identifiers(second)
    )
    if first_passport and first_passport == second_passport:
        shared_published_documents.discard(first_passport)

    if first_passport and first_passport == second_passport:
        signals.append("Passeport commun")
    if (first_document and first_document == second_document) or shared_published_documents:
        signals.append("Document commun")

    shared_names = _entry_names(first).intersection(_entry_names(second))
    same_birthdate = bool(
        first.date_naissance and second.date_naissance
        and first.date_naissance == second.date_naissance
    )
    if shared_names:
        signals.append("Nom ou alias commun")
    if same_birthdate:
        signals.append("Date de naissance commune")

    strong_identifier = "Passeport commun" in signals or "Document commun" in signals
    return strong_identifier or bool(shared_names and same_birthdate), signals


def build_alert_analysis(db: Session, alert: Alert) -> dict:
    """Create a read-only grouping; alerts and sanctions remain independent."""
    candidate_query = db.query(Alert)
    if alert.client_reference:
        candidate_query = candidate_query.filter(Alert.client_reference == alert.client_reference)
    else:
        candidate_query = candidate_query.filter(Alert.id == alert.id)
    candidates = candidate_query.order_by(Alert.created_at.asc()).all()
    if all(candidate.id != alert.id for candidate in candidates):
        candidates.append(alert)

    entry_ids = {candidate.sanction_entry_id for candidate in candidates if candidate.sanction_entry_id}
    entries = db.query(SanctionEntry).options(selectinload(SanctionEntry.aliases)).filter(
        SanctionEntry.id.in_(entry_ids)
    ).all() if entry_ids else []
    by_id = {entry.id: entry for entry in entries}
    anchor = by_id.get(alert.sanction_entry_id)

    grouped: list[Alert] = [alert]
    rationale: set[str] = set()
    if anchor:
        for candidate in candidates:
            if candidate.id == alert.id or candidate.source_liste == alert.source_liste:
                continue
            entry = by_id.get(candidate.sanction_entry_id)
            if not entry:
                continue
            same_person, signals = _same_probable_person(anchor, entry)
            if same_person:
                grouped.append(candidate)
                rationale.update(signals)

    grouped = sorted({item.id: item for item in grouped}.values(), key=lambda item: str(item.id))
    group_key = "|".join(str(item.id) for item in grouped)
    sources = []
    for item in grouped:
        entry = by_id.get(item.sanction_entry_id)
        sources.append({
            "alert_id": str(item.id),
            "sanction_entry_id": str(item.sanction_entry_id) if item.sanction_entry_id else None,
            "source": item.source_liste,
            "score": float(item.matching_score) if item.matching_score is not None else None,
            "matching_type": item.matching_type,
            "niveau_alerte": item.niveau_alerte,
            "statut": item.statut,
            "sanction_name": entry.nom_complet if entry else None,
        })

    is_multi_source = len({item["source"] for item in sources if item["source"]}) > 1
    return {
        "analysis_id": hashlib.sha256(group_key.encode("utf-8")).hexdigest()[:16],
        "classification": "MULTI_SOURCE_PROBABLE" if is_multi_source else "INDIVIDUAL",
        "rationale": sorted(rationale) if is_multi_source else [],
        "sources": sources,
    }
