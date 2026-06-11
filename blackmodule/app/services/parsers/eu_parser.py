import csv
import hashlib
from datetime import datetime, date
from io import StringIO


def clean_text(value: str | None) -> str | None:
    if value is None:
        return None

    value = value.strip()

    if not value:
        return None

    return value


def parse_date(value: str | None) -> date | None:
    if not value:
        return None

    value = value.strip()

    formats = [
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%d-%m-%Y",
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


def generate_hash_signature(
    source_liste: str,
    nom: str | None,
    prenom: str | None,
    date_naissance: date | None,
    num_passeport: str | None
) -> str:
    raw_value = f"{source_liste}|{nom}|{prenom}|{date_naissance}|{num_passeport}"
    return hashlib.sha256(raw_value.upper().encode("utf-8")).hexdigest()


def parse_eu_csv(file_content: bytes) -> list[dict]:
    """
    Parse un fichier CSV Union Européenne simplifié.

    Colonnes attendues pour le prototype :
    nom,prenom,nom_complet,type_entite,date_naissance,nationalite,pays,num_passeport,motif_sanction,date_inscription,statut,alias
    """

    decoded_content = file_content.decode("utf-8-sig")
    csv_file = StringIO(decoded_content)

    reader = csv.DictReader(csv_file)

    if not reader.fieldnames:
        raise ValueError("Le fichier CSV UE est vide ou invalide.")

    required_columns = [
        "nom",
        "prenom",
        "nom_complet",
        "type_entite",
        "date_naissance",
        "nationalite",
        "pays",
        "num_passeport",
        "motif_sanction",
        "date_inscription",
        "statut",
        "alias"
    ]

    missing_columns = [
        col for col in required_columns
        if col not in reader.fieldnames
    ]

    if missing_columns:
        raise ValueError(
            f"Colonnes manquantes dans le CSV UE : {', '.join(missing_columns)}"
        )

    normalized_entries = []

    for row in reader:
        nom = clean_text(row.get("nom"))
        prenom = clean_text(row.get("prenom"))
        nom_complet = clean_text(row.get("nom_complet"))

        type_entite = clean_text(row.get("type_entite")) or "PERSONNE_PHYSIQUE"

        date_naissance = parse_date(row.get("date_naissance"))
        nationalite = clean_text(row.get("nationalite"))
        pays = clean_text(row.get("pays"))
        num_passeport = clean_text(row.get("num_passeport"))
        motif_sanction = clean_text(row.get("motif_sanction")) or "UNION EUROPEENNE SANCTIONS"
        date_inscription = parse_date(row.get("date_inscription")) or date.today()
        statut = clean_text(row.get("statut")) or "ACTIF"

        alias_raw = clean_text(row.get("alias"))
        aliases = []

        if alias_raw:
            aliases = [
                alias.strip().upper()
                for alias in alias_raw.split(";")
                if alias.strip()
            ]

        if not nom_complet:
            parts = [prenom, nom]
            nom_complet = " ".join([p for p in parts if p])

        if not nom and nom_complet:
            nom = nom_complet

        if not nom:
            continue

        hash_signature = generate_hash_signature(
            source_liste="UE",
            nom=nom,
            prenom=prenom,
            date_naissance=date_naissance,
            num_passeport=num_passeport
        )

        normalized_entries.append({
            "source_liste": "UE",
            "type_entite": type_entite.upper(),
            "nom": nom.upper() if nom else None,
            "prenom": prenom.upper() if prenom else None,
            "nom_complet": nom_complet.upper() if nom_complet else nom.upper(),
            "date_naissance": date_naissance,
            "nationalite": nationalite.upper() if nationalite else None,
            "pays": pays.upper() if pays else None,
            "num_passeport": num_passeport.upper() if num_passeport else None,
            "motif_sanction": motif_sanction,
            "date_inscription": date_inscription,
            "date_suppression": None,
            "statut": statut.upper(),
            "hash_signature": hash_signature,
            "aliases": aliases
        })

    return normalized_entries

import xml.etree.ElementTree as ET


def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def get_texts_by_names(element, names: list[str]) -> list[str]:
    values = []
    names_lower = [name.lower() for name in names]

    for child in element.iter():
        if local_name(child.tag).lower() in names_lower and child.text:
            value = clean_text(child.text)
            if value:
                values.append(value)

    unique_values = []
    seen = set()

    for value in values:
        key = value.upper()
        if key not in seen:
            seen.add(key)
            unique_values.append(value)

    return unique_values


def get_first_text(element, names: list[str]) -> str | None:
    values = get_texts_by_names(element, names)
    return values[0] if values else None


def find_eu_records(root):
    possible_names = [
        "sanctionEntity",
        "entity",
        "subject",
        "person",
        "individual",
        "organisation",
        "organization"
    ]

    records = []

    for element in root.iter():
        tag = local_name(element.tag).lower()
        if tag in [name.lower() for name in possible_names]:
            records.append(element)

    return records


def parse_eu_xml(file_content: bytes) -> list[dict]:
    root = ET.fromstring(file_content)

    records = find_eu_records(root)
    normalized_entries = []

    for record in records:
        whole_names = get_texts_by_names(
            record,
            [
                "wholeName",
                "nameAlias",
                "alias",
                "name",
                "fullName",
                "designation"
            ]
        )

        first_name = get_first_text(
            record,
            [
                "firstName",
                "givenName",
                "forename"
            ]
        )

        last_name = get_first_text(
            record,
            [
                "lastName",
                "surname",
                "familyName"
            ]
        )

        if first_name and last_name:
            nom_complet = f"{first_name} {last_name}"
            nom = last_name
            prenom = first_name
        elif whole_names:
            nom_complet = whole_names[0]
            nom = whole_names[0]
            prenom = None
        else:
            continue

        aliases = []

        if len(whole_names) > 1:
            aliases = whole_names[1:]

        type_raw = get_first_text(
            record,
            [
                "subjectType",
                "entityType",
                "classificationCode",
                "type"
            ]
        )

        if type_raw and any(word in type_raw.lower() for word in ["person", "individual", "physique"]):
            type_entite = "PERSONNE_PHYSIQUE"
        elif first_name or last_name:
            type_entite = "PERSONNE_PHYSIQUE"
        else:
            type_entite = "PERSONNE_MORALE"

        date_naissance = parse_date(
            get_first_text(
                record,
                [
                    "birthdate",
                    "dateOfBirth",
                    "birthDate",
                    "dob"
                ]
            )
        )

        nationalite = get_first_text(
            record,
            [
                "citizenship",
                "nationality",
                "nationalite"
            ]
        )

        pays = get_first_text(
            record,
            [
                "country",
                "countryDescription",
                "addressCountry"
            ]
        )

        num_passeport = get_first_text(
            record,
            [
                "passportNumber",
                "number",
                "documentNumber",
                "identificationNumber"
            ]
        )

        motif_sanction = (
            get_first_text(
                record,
                [
                    "regulationSummary",
                    "programme",
                    "program",
                    "remark",
                    "reason",
                    "legalBasis"
                ]
            )
            or "UNION EUROPEENNE"
        )

        date_inscription = (
            parse_date(
                get_first_text(
                    record,
                    [
                        "publicationDate",
                        "entryIntoForceDate",
                        "listedOn",
                        "dateInscription"
                    ]
                )
            )
            or date.today()
        )

        hash_signature = generate_hash_signature(
            source_liste="UE",
            nom=nom,
            prenom=prenom,
            date_naissance=date_naissance,
            num_passeport=num_passeport
        )

        normalized_entries.append({
            "source_liste": "UE",
            "type_entite": type_entite,
            "nom": nom.upper() if nom else None,
            "prenom": prenom.upper() if prenom else None,
            "nom_complet": nom_complet.upper(),
            "date_naissance": date_naissance,
            "nationalite": nationalite.upper() if nationalite else None,
            "pays": pays.upper() if pays else None,
            "num_passeport": num_passeport.upper() if num_passeport else None,
            "motif_sanction": motif_sanction,
            "date_inscription": date_inscription,
            "date_suppression": None,
            "statut": "ACTIF",
            "hash_signature": hash_signature,
            "aliases": [alias.upper() for alias in aliases if alias]
        })

    return normalized_entries