import unicodedata
from rapidfuzz import fuzz, process
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session, load_only, selectinload

from app.models import SanctionAlias, SanctionEntry
from app.services.performance import log_slow_operation, performance_timer


MAX_FUZZY_CANDIDATES = 1_000


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


def build_full_name(prenom: str | None, nom: str | None) -> str:
    parts = [prenom, nom]
    return normalize_text(" ".join([p for p in parts if p]))


def calculate_name_score(client_name: str, listed_name: str) -> float:
    """
    Calcule le score fuzzy entre le nom du client et le nom blacklisté.
    token_sort_ratio gère mieux les inversions : JOHN DOE / DOE JOHN.
    """
    client_name = normalize_text(client_name)
    listed_name = normalize_text(listed_name)

    if not client_name or not listed_name:
        return 0.0

    return float(fuzz.token_sort_ratio(client_name, listed_name))


def calculate_name_scores_batch(client_name: str, listed_names: list[str]) -> list[float]:
    """
    Calcule le score fuzzy d'un client contre une liste de noms blacklistés
    en une seule passe vectorisée (rapidfuzz.process.cdist), au lieu d'un
    appel Python par entrée. Résultats strictement identiques à des appels
    répétés de calculate_name_score, mais nettement plus rapide sur de
    grandes listes de sanctions.
    """
    client_name = normalize_text(client_name)

    if not client_name or not listed_names:
        return [0.0] * len(listed_names)

    normalized_listed = [normalize_text(name) for name in listed_names]

    scores = process.cdist(
        [client_name],
        normalized_listed,
        scorer=fuzz.token_sort_ratio
    )[0]

    return [
        float(score) if listed else 0.0
        for score, listed in zip(scores, normalized_listed)
    ]


def _name_tokens(normalized_name: str) -> list[str]:
    """Keep useful tokens only; one-character tokens are too broad in SQL."""
    return list(dict.fromkeys(token for token in normalized_name.split() if len(token) >= 2))


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
            SanctionEntry.motif_sanction,
            SanctionEntry.created_at,
        ),
        selectinload(SanctionEntry.aliases).load_only(SanctionAlias.alias),
    ).all()


def select_matching_candidates(
    db: Session,
    client_name: str,
    passport_number: str | None = None,
) -> list[tuple[SanctionEntry, str, float]]:
    """Return a bounded fuzzy candidate set plus every SQL-identifiable exact hit.

    Exact passport and exact normalized (case/space/punctuation) names are queried
    independently and are never affected by the fuzzy candidate limit. Aliases are
    eager-loaded in batches, so matching does not cause an N+1 query pattern.
    """
    started_at = performance_timer()
    normalized_client_name = normalize_text(client_name)
    normalized_passport = (passport_number or "").strip().upper()
    active = SanctionEntry.statut == "ACTIF"
    by_id: dict[object, SanctionEntry] = {}

    if normalized_passport:
        passport_matches = _query_candidates(
            db.query(SanctionEntry).filter(
                active,
                func.upper(SanctionEntry.num_passeport) == normalized_passport,
            )
        )
        by_id.update({entry.id: entry for entry in passport_matches})

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

        normalized_names = [normalize_text(name) for name in candidate_names]
        if normalized_client_name in normalized_names:
            best_index = normalized_names.index(normalized_client_name)
            score = 100.0
        else:
            scores = process.cdist(
                [normalized_client_name], normalized_names, scorer=fuzz.token_sort_ratio
            )[0]
            best_index = max(range(len(scores)), key=lambda index: scores[index])
            score = float(scores[best_index])
        candidates.append((entry, candidate_names[best_index], score))

    log_slow_operation(
        "matching_candidate_selection",
        started_at,
        candidate_count=len(candidates),
    )
    return candidates

"""
    Classification selon les seuils BLACKMODULE :
    >= 95 : alerte exacte
    80-94 : alerte probable
    60-79 : alerte possible
    < 60 : aucune alerte
"""

def classify_alert(
    score: float,
    exact_threshold: float = 90.0,
    probable_threshold: float = 75.0,
    possible_threshold: float = 60.0
):
    if score >= exact_threshold:
        return "ALERTE_EXACTE", "BLOQUER_OPERATION"

    if score >= probable_threshold:
        return "ALERTE_PROBABLE", "REVUE_CONFORMITE"

    if score >= possible_threshold:
        return "ALERTE_POSSIBLE", "SURVEILLANCE_RENFORCEE"

    return "AUCUNE_ALERTE", "OPERATION_AUTORISEE"
