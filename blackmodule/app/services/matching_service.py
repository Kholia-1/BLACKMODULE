import re
import unicodedata
from dataclasses import dataclass
from datetime import date
from rapidfuzz import fuzz, process
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session, load_only, selectinload

from app.models import SanctionAlias, SanctionEntry
from app.services.performance import log_slow_operation, performance_timer


MAX_FUZZY_CANDIDATES = 1_000
ACTIVE_SANCTION_STATUSES = ("ACTIF", "ACTIVE")
NORMALIZED_NOISE_SCORE = 95.0
EXACT_MATCH_TYPES = frozenset({
    "EXACT_NAME",
    "EXACT_ALIAS",
    "EXACT_PASSPORT",
    "EXACT_DOCUMENT",
})


@dataclass(frozen=True)
class MatchEvaluation:
    """Stable, explainable result of evaluating one selected candidate."""

    score: float
    matching_type: str
    explanation: tuple[str, ...]
    name_score: float


def normalize_text(value: str | None) -> str:
    """
    Normalise une chaîne avant comparaison :
    - transforme en majuscules
    - enlève les accents
    - enlève les espaces multiples
    - nettoie les tirets et apostrophes
    """
    if not value:
        return ""

    value = value.upper().strip()

    value = unicodedata.normalize("NFD", value)
    value = "".join(
        char for char in value
        if unicodedata.category(char) != "Mn"
    )

    value = value.replace("-", " ")
    value = value.replace("'", " ")
    value = " ".join(value.split())

    return value


def normalize_name(value: str | None) -> str:
    """Build the tolerant name used only for candidate retrieval and scoring."""
    cleaned_tokens = []
    for token in normalize_text(value).split():
        if token.isdigit():
            continue
        # Screening forms sometimes receive counters or punctuation appended
        # to the final alphabetic token (for example AWAN123 or AWAN###).
        token = re.sub(r"(?<=[A-Z])[^A-Z]+$", "", token)
        if token:
            cleaned_tokens.append(token)
    return " ".join(cleaned_tokens)


def normalize_identifier(value: str | None) -> str:
    """Normalize an identifier without logging or exposing its value."""
    return "".join(char for char in normalize_text(value) if char.isalnum())


def build_full_name(prenom: str | None, nom: str | None) -> str:
    parts = [prenom, nom]
    return normalize_text(" ".join([p for p in parts if p]))


def calculate_name_score(client_name: str, listed_name: str) -> float:
    """
    Calcule le score fuzzy entre le nom du client et le nom blacklisté.
    token_sort_ratio gère mieux les inversions : JOHN DOE / DOE JOHN.
    """
    strict_client_name = normalize_text(client_name)
    strict_listed_name = normalize_text(listed_name)
    client_name = normalize_name(client_name)
    listed_name = normalize_name(listed_name)

    if not client_name or not listed_name:
        return 0.0

    if client_name == listed_name:
        score = 100.0
    else:
        abbreviation_score = _abbreviation_score(client_name, listed_name)
        score = max(float(fuzz.token_sort_ratio(client_name, listed_name)), abbreviation_score)

    if strict_client_name != client_name or strict_listed_name != listed_name:
        score = min(score, NORMALIZED_NOISE_SCORE)
    return score


def _abbreviation_score(client_name: str, listed_name: str) -> float:
    """Recognize safe initials while requiring at least one full shared token."""
    client_tokens = client_name.split()
    listed_tokens = listed_name.split()
    if len(client_tokens) != len(listed_tokens) or len(client_tokens) < 2:
        return 0.0

    remaining = list(listed_tokens)
    has_initial = False
    has_full_token = False
    for token in client_tokens:
        match_index = next((i for i, other in enumerate(remaining) if token == other), None)
        if match_index is not None:
            has_full_token = has_full_token or len(token) >= 2
            remaining.pop(match_index)
            continue
        match_index = next(
            (i for i, other in enumerate(remaining)
             if (len(token) == 1 and other.startswith(token))
             or (len(other) == 1 and token.startswith(other))),
            None,
        )
        if match_index is None:
            return 0.0
        has_initial = True
        remaining.pop(match_index)

    return 85.0 if has_initial and has_full_token else 0.0


def calculate_name_scores_batch(client_name: str, listed_names: list[str]) -> list[float]:
    """
    Calcule le score fuzzy d'un client contre une liste de noms blacklistés
    en une seule passe vectorisée (rapidfuzz.process.cdist), au lieu d'un
    appel Python par entrée. Résultats strictement identiques à des appels
    répétés de calculate_name_score, mais nettement plus rapide sur de
    grandes listes de sanctions.
    """
    strict_client_name = normalize_text(client_name)
    client_name = normalize_name(client_name)

    if not client_name or not listed_names:
        return [0.0] * len(listed_names)

    strict_listed = [normalize_text(name) for name in listed_names]
    normalized_listed = [normalize_name(name) for name in listed_names]

    scores = process.cdist(
        [client_name],
        normalized_listed,
        scorer=fuzz.token_sort_ratio
    )[0]

    results = []
    for score, listed, strict_name in zip(scores, normalized_listed, strict_listed):
        if not listed:
            results.append(0.0)
            continue
        value = max(float(score), _abbreviation_score(client_name, listed))
        if strict_client_name != client_name or strict_name != listed:
            value = min(value, NORMALIZED_NOISE_SCORE)
        results.append(value)
    return results


def _name_tokens(normalized_name: str) -> list[str]:
    """Keep useful tokens only; one-character tokens are too broad in SQL."""
    return list(dict.fromkeys(
        token for token in normalized_name.split()
        if len(token) >= 2 and not token.isdigit()
    ))


def _document_identifiers(entry: SanctionEntry) -> set[str]:
    """Return every published identifier accepted by a generic document field.

    A passport remains stored and matched as a passport when the caller uses
    ``passport_number``.  The generic ``document_number`` field is broader by
    design, however, and must also be able to find a source-published passport
    without reclassifying other identifiers as passports.
    """
    identifiers = {
        normalize_identifier(getattr(entry, "document_number", None)),
        normalize_identifier(getattr(entry, "num_passeport", None)),
    }
    raw_documents = getattr(entry, "autres_documents", None) or ""
    parts = re.split(r"[;,|\n\r]+|\s+/\s+(?=[^:/]{1,80}:)", raw_documents)
    document_label_markers = (
        "DOCUMENT", "IDENTIFIER", "IDENTIFICATION", "PASSPORT", "PASSEPORT",
        "LICENSE", "LICENCE", "CEDULA", "REGISTRATION", "REGISTRE",
        "PERMIT", "PERMIS", "CARTE", "TAX", "VAT", "FISCAL",
    )
    document_label_tokens = {
        "ID", "NO", "NUMBER", "NUMERO", "NUM", "CNI", "DNI", "NIN",
        "SSN", "TIN", "IMO", "MMSI",
    }
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            label, value = part.split(":", 1)
            normalized_label = normalize_text(label)
            label_tokens = set(normalized_label.split())
            if not (
                any(marker in normalized_label for marker in document_label_markers)
                or label_tokens.intersection(document_label_tokens)
            ):
                continue
        else:
            value = part
            # Unlabelled legacy values are accepted only when they look like
            # identifiers, never for plain metadata such as MALE/FEMALE.
            if not any(char.isdigit() for char in value):
                continue
        identifiers.add(normalize_identifier(value))
    identifiers.discard("")
    return identifiers


def _same_nationality(client_value: str, listed_value: str) -> bool:
    client = normalize_text(client_value)
    listed = normalize_text(listed_value)
    if client == listed:
        return True
    listed_values = {
        normalize_text(value) for value in re.split(r"[;,|/]", listed_value) if value.strip()
    }
    return client in listed_values


def evaluate_candidate(
    entry: SanctionEntry,
    client_name: str,
    listed_name: str,
    name_score: float,
    *,
    date_naissance: date | None = None,
    nationalite: str | None = None,
    passport_number: str | None = None,
    document_number: str | None = None,
) -> MatchEvaluation:
    """Combine name and secondary evidence with deterministic conflict rules."""
    explanations: list[str] = []
    strict_client_name = normalize_text(client_name)
    normalized_client_name = normalize_name(client_name)
    strict_primary_names = {
        normalize_text(entry.nom_complet),
        normalize_text(build_full_name(entry.prenom, entry.nom)),
    }
    strict_primary_names.discard("")
    primary_names = {
        normalize_name(entry.nom_complet),
        normalize_name(build_full_name(entry.prenom, entry.nom)),
    }
    primary_names.discard("")
    strict_alias_names = {normalize_text(alias.alias) for alias in entry.aliases if alias.alias}
    alias_names = {normalize_name(alias.alias) for alias in entry.aliases if alias.alias}

    if strict_client_name in strict_primary_names:
        matching_type = "EXACT_NAME"
        explanations.append("Nom exact")
    elif strict_client_name in strict_alias_names:
        matching_type = "EXACT_ALIAS"
        explanations.append("Alias exact")
    elif normalized_client_name in primary_names or normalized_client_name in alias_names:
        matching_type = "NORMALIZED_NAME"
        explanations.append(
            "Caractères parasites ignorés pour comparer le nom ; correspondance non exacte"
        )
    elif _abbreviation_score(normalized_client_name, normalize_name(listed_name)):
        matching_type = "NAME_ABBREVIATION"
        explanations.append("Abréviation de nom cohérente")
    else:
        matching_type = "FUZZY_NAME"
        explanations.append(f"Similarité du nom : {name_score:.2f}/100")

    score = float(name_score)
    client_passport = normalize_identifier(passport_number)
    listed_passport = normalize_identifier(entry.num_passeport)
    client_document = normalize_identifier(document_number)
    listed_documents = _document_identifiers(entry)
    exact_passport = bool(client_passport and listed_passport and client_passport == listed_passport)
    exact_document = bool(client_document and client_document in listed_documents)

    if exact_passport:
        score = 100.0
        matching_type = "EXACT_PASSPORT"
        explanations.append("Passeport exact")
    elif exact_document:
        score = 100.0
        matching_type = "EXACT_DOCUMENT"
        explanations.append("Document exact")
    else:
        if client_passport and listed_passport and client_passport != listed_passport:
            score = min(score - 50.0, 40.0)
            explanations.append("Passeports contradictoires")
        if client_document and listed_documents and client_document not in listed_documents:
            score = min(score - 50.0, 40.0)
            explanations.append("Documents contradictoires")

    if date_naissance and entry.date_naissance:
        if date_naissance == entry.date_naissance:
            explanations.append("Date de naissance concordante")
            if not (exact_passport or exact_document) and name_score >= 60.0:
                score = max(score, 95.0)
                matching_type = "NAME_AND_BIRTHDATE"
        else:
            explanations.append("Dates de naissance contradictoires")
            if not (exact_passport or exact_document):
                score = min(score - 40.0, 40.0)

    if nationalite and entry.nationalite:
        if _same_nationality(nationalite, entry.nationalite):
            explanations.append("Nationalité concordante")
            if not (exact_passport or exact_document) and name_score >= 60.0:
                score = min(100.0, score + 5.0)
        else:
            explanations.append("Nationalités différentes")
            if not (exact_passport or exact_document):
                score -= 15.0

    return MatchEvaluation(
        score=round(max(0.0, min(100.0, score)), 2),
        matching_type=matching_type,
        explanation=tuple(explanations),
        name_score=round(float(name_score), 2),
    )


def _query_candidates(query):
    return query.options(
        load_only(
            SanctionEntry.id,
            SanctionEntry.source_liste,
            SanctionEntry.type_entite,
            SanctionEntry.nom,
            SanctionEntry.prenom,
            SanctionEntry.nom_complet,
            SanctionEntry.date_naissance,
            SanctionEntry.nationalite,
            SanctionEntry.pays,
            SanctionEntry.num_passeport,
            SanctionEntry.autres_documents,
            SanctionEntry.document_number,
            SanctionEntry.motif_sanction,
            SanctionEntry.created_at,
        ),
        selectinload(SanctionEntry.aliases).load_only(SanctionAlias.alias),
    ).all()


def select_matching_candidates(
    db: Session,
    client_name: str,
    passport_number: str | None = None,
    document_number: str | None = None,
) -> list[tuple[SanctionEntry, str, float]]:
    """Return a bounded fuzzy candidate set plus every SQL-identifiable exact hit.

    Exact passport and exact normalized (case/space/punctuation) names are queried
    independently and are never affected by the fuzzy candidate limit. Aliases are
    eager-loaded in batches, so matching does not cause an N+1 query pattern.
    """
    started_at = performance_timer()
    normalized_client_name = normalize_name(client_name)
    normalized_passport = normalize_identifier(passport_number)
    normalized_document = normalize_identifier(document_number)
    # LOT 2B historically wrote ACTIVE while parsers and internal lists use
    # ACTIF. Both values represent an active sanction; new writes use ACTIF.
    active = SanctionEntry.statut.in_(ACTIVE_SANCTION_STATUSES)
    by_id: dict[object, SanctionEntry] = {}

    if normalized_passport:
        sql_normalized_passport = func.regexp_replace(
            func.upper(SanctionEntry.num_passeport), r"[^A-Z0-9]", "", "g"
        )
        passport_matches = _query_candidates(
            db.query(SanctionEntry).filter(
                active,
                sql_normalized_passport == normalized_passport,
            )
        )
        by_id.update({entry.id: entry for entry in passport_matches})

    if normalized_document:
        sql_normalized_document = func.regexp_replace(
            func.upper(SanctionEntry.document_number), r"[^A-Z0-9]", "", "g"
        )
        sql_normalized_passport = func.regexp_replace(
            func.upper(SanctionEntry.num_passeport), r"[^A-Z0-9]", "", "g"
        )
        sql_normalized_other_documents = func.regexp_replace(
            func.upper(SanctionEntry.autres_documents), r"[^A-Z0-9]", "", "g"
        )
        document_matches = _query_candidates(
            db.query(SanctionEntry).filter(
                active,
                or_(
                    sql_normalized_document == normalized_document,
                    sql_normalized_passport == normalized_document,
                    sql_normalized_other_documents.contains(normalized_document),
                ),
            )
        )
        by_id.update({entry.id: entry for entry in document_matches})

    # This SQL normalization mirrors the whitespace/punctuation part of
    # normalize_text, including accents through PostgreSQL's unaccent extension.
    sql_normalized_name = func.regexp_replace(
        func.replace(
            func.replace(func.unaccent(func.upper(SanctionEntry.nom_complet)), "-", " "),
            "'",
            " ",
        ),
        r"\s+",
        " ",
        "g",
    )
    sql_normalized_alias = func.regexp_replace(
        func.replace(
            func.replace(func.unaccent(func.upper(SanctionAlias.alias)), "-", " "),
            "'",
            " ",
        ),
        r"\s+",
        " ",
        "g",
    )
    if normalized_client_name:
        exact_name_matches = _query_candidates(
            db.query(SanctionEntry).filter(
                active,
                or_(
                    sql_normalized_name == normalized_client_name,
                    SanctionEntry.aliases.any(sql_normalized_alias == normalized_client_name),
                ),
            )
        )
        by_id.update({entry.id: entry for entry in exact_name_matches})

    tokens = _name_tokens(normalized_client_name)
    if tokens:
        token_filters = []
        for token in tokens:
            pattern = f"%{token}%"
            token_filters.append(
                or_(
                    SanctionEntry.nom.ilike(pattern),
                    SanctionEntry.prenom.ilike(pattern),
                    SanctionEntry.nom_complet.ilike(pattern),
                    SanctionEntry.aliases.any(SanctionAlias.alias.ilike(pattern)),
                )
            )

        fuzzy_query = db.query(SanctionEntry).filter(active, and_(*token_filters))
        for entry in _query_candidates(
            fuzzy_query.order_by(SanctionEntry.created_at.desc()).limit(MAX_FUZZY_CANDIDATES)
        ):
            by_id.setdefault(entry.id, entry)

    candidates: list[tuple[SanctionEntry, str, float]] = []
    for entry in by_id.values():
        candidate_names = [
            name for name in [entry.nom_complet, build_full_name(entry.prenom, entry.nom)] if name
        ]
        candidate_names.extend(alias.alias for alias in entry.aliases if alias.alias)
        if not candidate_names:
            continue

        strict_client_name = normalize_text(client_name)
        strict_names = [normalize_text(name) for name in candidate_names]
        if strict_client_name in strict_names:
            best_index = strict_names.index(strict_client_name)
            score = 100.0
        else:
            scores = calculate_name_scores_batch(client_name, candidate_names)
            best_index = max(range(len(scores)), key=lambda index: scores[index])
            score = float(scores[best_index])
        candidates.append((entry, candidate_names[best_index], score))

    log_slow_operation(
        "matching_candidate_selection",
        started_at,
        candidate_count=len(candidates),
    )
    return candidates

def classify_alert(
    score: float,
    exact_threshold: float = 90.0,
    probable_threshold: float = 75.0,
    possible_threshold: float = 60.0,
    matching_type: str | None = None,
):
    """Classify a score while reserving exact alerts for exact evidence.

    The numeric thresholds remain configurable and unchanged.  When the
    caller provides a matching type, a high fuzzy/normalized score is kept at
    the probable level rather than being presented as an exact match.
    """
    if score >= exact_threshold and (
        matching_type is None or matching_type in EXACT_MATCH_TYPES
    ):
        return "ALERTE_EXACTE", "BLOQUER_OPERATION"

    if score >= probable_threshold or (
        score >= exact_threshold and matching_type not in EXACT_MATCH_TYPES
    ):
        return "ALERTE_PROBABLE", "REVUE_CONFORMITE"

    if score >= possible_threshold:
        return "ALERTE_POSSIBLE", "SURVEILLANCE_RENFORCEE"

    return "AUCUNE_ALERTE", "OPERATION_AUTORISEE"
