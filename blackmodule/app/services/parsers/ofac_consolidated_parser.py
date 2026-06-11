import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, date


def clean_text(value) -> str | None:
    if value is None:
        return None

    value = str(value).strip()

    if not value or value.lower() in ["nan", "none", "null"]:
        return None

    return value


def parse_date(value) -> date | None:
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    formats = [
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%d-%m-%Y",
        "%d %b %Y",
        "%d %B %Y",
        "%Y"
    ]

    for fmt in formats:
        try:
            parsed = datetime.strptime(value, fmt).date()

            if fmt == "%Y":
                return date(parsed.year, 1, 1)

            return parsed

        except ValueError:
            continue

    return None


def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def tag_equals(element, name: str) -> bool:
    return local_name(element.tag).lower() == name.lower()


def tag_contains(element, text: str) -> bool:
    return text.lower() in local_name(element.tag).lower()


def unique_values(values: list[str]) -> list[str]:
    result = []
    seen = set()

    for value in values:
        value = clean_text(value)

        if not value:
            continue

        key = value.upper()

        if key not in seen:
            seen.add(key)
            result.append(value)

    return result


def get_texts_by_tag_exact(element, tag_names: list[str]) -> list[str]:
    tag_names_lower = [x.lower() for x in tag_names]
    values = []

    for child in element.iter():
        if local_name(child.tag).lower() in tag_names_lower and child.text:
            value = clean_text(child.text)
            if value:
                values.append(value)

    return unique_values(values)


def get_texts_by_tag_contains(element, keywords: list[str]) -> list[str]:
    values = []

    for child in element.iter():
        child_tag = local_name(child.tag).lower()

        for keyword in keywords:
            if keyword.lower() in child_tag and child.text:
                value = clean_text(child.text)

                if value:
                    values.append(value)

    return unique_values(values)


def generate_hash_signature(
    source_liste: str,
    nom: str | None,
    prenom: str | None,
    date_naissance: date | None,
    num_passeport: str | None
) -> str:
    raw_value = f"{source_liste}|{nom}|{prenom}|{date_naissance}|{num_passeport}"
    return hashlib.sha256(raw_value.upper().encode("utf-8")).hexdigest()


def find_distinct_parties(root):
    """
    Dans le format Advanced XML OFAC, les personnes/entités sont généralement
    dans des blocs DistinctParty.
    """
    parties = []

    for element in root.iter():
        name = local_name(element.tag).lower()

        if name == "distinctparty":
            parties.append(element)

    return parties


def extract_names_from_party(party) -> tuple[str | None, list[str]]:
    """
    Extrait les noms à partir du modèle Advanced XML.

    Les noms peuvent être découpés dans des balises comme :
    NamePartValue, NamePart, DocumentedName, Alias, etc.
    """

    # Cas le plus fréquent dans Advanced XML : valeurs de parties de noms
    name_parts = get_texts_by_tag_contains(
        party,
        [
            "namepartvalue",
            "namepart"
        ]
    )

    # Nettoyer les valeurs trop techniques
    cleaned_parts = []

    for value in name_parts:
        v = clean_text(value)

        if not v:
            continue

        # éviter certains codes techniques
        if len(v) <= 1:
            continue

        if v.upper() in ["TRUE", "FALSE", "PRIMARY", "WEAK", "STRONG"]:
            continue

        cleaned_parts.append(v)

    cleaned_parts = unique_values(cleaned_parts)

    if cleaned_parts:
        # Pour le MVP, on construit un nom complet à partir des premières parties
        primary_name = " ".join(cleaned_parts[:4])
        aliases = []

        if len(cleaned_parts) > 4:
            aliases = cleaned_parts[4:]

        return primary_name, aliases

    # Fallback : autres balises possibles
    fallback_names = get_texts_by_tag_exact(
        party,
        [
            "FormattedFullName",
            "FullName",
            "Name",
            "AliasName",
            "EntityName"
        ]
    )

    if fallback_names:
        primary_name = fallback_names[0]
        aliases = fallback_names[1:]
        return primary_name, aliases

    return None, []


def extract_type_entite(party) -> str:
    texts = get_texts_by_tag_exact(
        party,
        [
            "ProfileType",
            "PartyType",
            "EntityType",
            "Type"
        ]
    )

    joined = " ".join(texts).lower()

    if "individual" in joined or "person" in joined:
        return "PERSONNE_PHYSIQUE"

    if "entity" in joined or "organization" in joined or "vessel" in joined:
        return "PERSONNE_MORALE"

    # Fallback : s'il y a une date de naissance, on suppose personne physique
    dob_values = get_texts_by_tag_contains(
        party,
        [
            "birth",
            "dob"
        ]
    )

    if dob_values:
        return "PERSONNE_PHYSIQUE"

    return "PERSONNE_MORALE"


def extract_date_naissance(party):
    values = get_texts_by_tag_contains(
        party,
        [
            "birthdate",
            "dateofbirth",
            "dob"
        ]
    )

    for value in values:
        parsed = parse_date(value)

        if parsed:
            return parsed

    return None


def extract_passport_or_document(party):
    values = get_texts_by_tag_contains(
        party,
        [
            "passport",
            "idnumber",
            "documentnumber",
            "registrationnumber"
        ]
    )

    if values:
        return values[0]

    return None


def extract_country(party):
    values = get_texts_by_tag_exact(
        party,
        [
            "Country",
            "Nationality",
            "Citizenship",
            "CountryDescription"
        ]
    )

    if values:
        return values[0]

    return None


def extract_programs(party):
    values = get_texts_by_tag_contains(
        party,
        [
            "program",
            "list",
            "sanctionstype"
        ]
    )

    cleaned = []

    for value in values:
        v = clean_text(value)

        if not v:
            continue

        if v.upper() in ["TRUE", "FALSE"]:
            continue

        cleaned.append(v)

    cleaned = unique_values(cleaned)

    if cleaned:
        return ", ".join(cleaned[:5])

    return "OFAC CONSOLIDATED"


def parse_ofac_consolidated_xml(file_content: bytes) -> list[dict]:
    root = ET.fromstring(file_content)

    parties = find_distinct_parties(root)

    normalized_entries = []

    for party in parties:
        nom_complet, aliases = extract_names_from_party(party)

        if not nom_complet:
            continue

        type_entite = extract_type_entite(party)
        date_naissance = extract_date_naissance(party)
        num_passeport = extract_passport_or_document(party)
        country = extract_country(party)
        motif_sanction = extract_programs(party)

        # Pour le MVP, nom = nom_complet pour le format Advanced XML
        nom = nom_complet
        prenom = None

        # Si c'est une personne physique et qu'il y a plusieurs mots,
        # on sépare simplement premier mot = prénom, reste = nom.
        if type_entite == "PERSONNE_PHYSIQUE":
            parts = nom_complet.split()

            if len(parts) >= 2:
                prenom = parts[0]
                nom = " ".join(parts[1:])

        hash_signature = generate_hash_signature(
            source_liste="OFAC_CONSOLIDATED",
            nom=nom,
            prenom=prenom,
            date_naissance=date_naissance,
            num_passeport=num_passeport
        )

        normalized_entries.append({
            "source_liste": "OFAC_CONSOLIDATED",
            "type_entite": type_entite,
            "nom": nom.upper() if nom else None,
            "prenom": prenom.upper() if prenom else None,
            "nom_complet": nom_complet.upper(),
            "date_naissance": date_naissance,
            "nationalite": country.upper() if country else None,
            "pays": country.upper() if country else None,
            "num_passeport": num_passeport.upper() if num_passeport else None,
            "motif_sanction": motif_sanction,
            "date_inscription": date.today(),
            "date_suppression": None,
            "statut": "ACTIF",
            "hash_signature": hash_signature,
            "aliases": [alias.upper() for alias in aliases if alias]
        })

    return normalized_entries