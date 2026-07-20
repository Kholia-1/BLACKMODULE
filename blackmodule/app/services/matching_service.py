import unicodedata
from rapidfuzz import fuzz, process


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
