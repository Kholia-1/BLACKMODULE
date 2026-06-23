import csv
import hashlib
from datetime import datetime, date
from io import StringIO


def clean_value(value):
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    if value.lower() in ["nan", "none", "null", "n/a", "na"]:
        return None

    return value


def normalize_key(key):
    if key is None:
        return ""

    return str(key).replace("\ufeff", "").strip()


def normalize_row(row: dict) -> dict:
    return {
        normalize_key(key): clean_value(value)
        for key, value in row.items()
    }


def get_value(row: dict, possible_keys: list[str]):
    for key in possible_keys:
        value = row.get(key)

        if value:
            return value

    return None


def parse_date_value(value):
    value = clean_value(value)

    if not value:
        return None

    formats = [
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%d-%m-%Y",
        "%Y/%m/%d",
        "%d %B %Y",
        "%B %d, %Y",
        "%Y",
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


def build_full_name(row: dict):
    name_parts = []

    for key in [
        "Name 1",
        "Name 2",
        "Name 3",
        "Name 4",
        "Name 5",
        "Name 6",
    ]:
        value = clean_value(row.get(key))

        if value:
            name_parts.append(value)

    if name_parts:
        return " ".join(name_parts).strip().upper()

    fallback_name = get_value(
        row,
        [
            "Name",
            "Full Name",
            "Full name",
            "Individual, Entity, Ship",
            "Title",
        ]
    )

    if fallback_name:
        return fallback_name.strip().upper()

    return None


def build_reference(row: dict):
    return get_value(
        row,
        [
            "Unique ID",
            "UK Sanctions List Ref",
            "UK Sanctions List Reference",
            "OFSI Group ID",
            "Group ID",
            "UN Reference Number",
        ]
    )


def normalize_entity_type(value):
    value = clean_value(value)

    if not value:
        return "PERSONNE_PHYSIQUE"

    value_upper = value.upper()

    if "ENTITY" in value_upper:
        return "PERSONNE_MORALE"

    if "ORGANISATION" in value_upper:
        return "PERSONNE_MORALE"

    if "ORGANIZATION" in value_upper:
        return "PERSONNE_MORALE"

    if "SHIP" in value_upper:
        return "NAVIRE"

    if "VESSEL" in value_upper:
        return "NAVIRE"

    if "INDIVIDUAL" in value_upper:
        return "PERSONNE_PHYSIQUE"

    if "PERSON" in value_upper:
        return "PERSONNE_PHYSIQUE"

    return value_upper[:50]


def build_motif(row: dict):
    parts = []

    for key in [
        "Regime Name",
        "Sanctions Imposed",
        "Other Information",
        "UK Statement of Reasons",
    ]:
        value = clean_value(row.get(key))

        if value:
            parts.append(f"{key}: {value}")

    motif = " | ".join(parts)

    if len(motif) > 500:
        motif = motif[:500]

    return motif or None


def build_passport(row: dict):
    values = []

    for key in [
        "Passport Number",
        "Passport Details",
        "National Identifier Number",
        "National Identifier Details",
    ]:
        value = clean_value(row.get(key))

        if value:
            values.append(value)

    if not values:
        return None

    result = " / ".join(values)

    if len(result) > 100:
        result = result[:100]

    return result


def generate_hash_signature(
    source_liste,
    nom_complet,
    date_naissance,
    reference_externe
):
    raw = f"{source_liste}|{nom_complet}|{date_naissance}|{reference_externe}"
    return hashlib.sha256(raw.upper().encode("utf-8")).hexdigest()


def decode_csv(file_content: bytes) -> str:
    try:
        return file_content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return file_content.decode("latin-1")


def parse_uksl_csv(file_content: bytes):
    decoded_content = decode_csv(file_content)

    if not decoded_content.strip():
        return []

    lines = decoded_content.splitlines(keepends=True)

    header_index = None

    for index, line in enumerate(lines):
        clean_line = line.replace("\ufeff", "").strip()

        if (
            "Unique ID" in clean_line
            and "OFSI Group ID" in clean_line
            and ("Name 1" in clean_line or "Name 6" in clean_line)
        ):
            header_index = index
            break

    if header_index is None:
        raise ValueError(
            "En-tête CSV UKSL introuvable. "
            "Colonnes attendues : Unique ID, OFSI Group ID, Name 1."
        )

    csv_content = "".join(lines[header_index:])
    sample = csv_content[:4096]

    try:
        dialect = csv.Sniffer().sniff(sample)
    except Exception:
        dialect = csv.excel

    csv_file = StringIO(csv_content)
    reader = csv.DictReader(csv_file, dialect=dialect)

    if not reader.fieldnames:
        return []

    reader.fieldnames = [
        normalize_key(key)
        for key in reader.fieldnames
    ]

    entries = []

    for raw_row in reader:
        row = normalize_row(raw_row)

        nom_complet = build_full_name(row)

        if not nom_complet:
            continue

        reference_externe = build_reference(row)

        group_type = get_value(
            row,
            [
                "Group Type",
                "Entity Type",
                "Type",
                "Designation Type",
                "Name type",
            ]
        )

        type_entite = normalize_entity_type(group_type)

        name_parts = []

        for key in [
            "Name 1",
            "Name 2",
            "Name 3",
            "Name 4",
            "Name 5",
            "Name 6",
        ]:
            value = clean_value(row.get(key))

            if value:
                name_parts.append(value.strip().upper())

        if len(name_parts) >= 2:
            prenom = " ".join(name_parts[:-1])
            nom = name_parts[-1]
        else:
            prenom = None
            nom = nom_complet

        date_naissance = parse_date_value(
            get_value(
                row,
                [
                    "Date of Birth",
                    "DOB",
                    "Birth Date",
                    "Date Birth",
                ]
            )
        )

        date_inscription = parse_date_value(
            get_value(
                row,
                [
                    "Date Designated",
                    "Date Listed",
                    "Date of Designation",
                ]
            )
        )

        nationalite = get_value(
            row,
            [
                "Nationality",
                "Nationality Country",
                "Country of Nationality",
            ]
        )

        pays = get_value(
            row,
            [
                "Address Country",
                "Country",
                "Country of Residence",
            ]
        )

        num_passeport = build_passport(row)
        motif_sanction = build_motif(row)

        statut = get_value(
            row,
            [
                "Status",
                "Current Status",
            ]
        ) or "ACTIF"

        item = {
            "source_liste": "UKSL",
            "reference_externe": reference_externe,
            "type_entite": type_entite,
            "nom": nom[:150] if nom else None,
            "prenom": prenom[:150] if prenom else None,
            "nom_complet": nom_complet[:255] if nom_complet else None,
            "date_naissance": date_naissance,
            "nationalite": nationalite[:100].upper() if nationalite else None,
            "pays": pays[:100].upper() if pays else None,
            "num_passeport": num_passeport,
            "motif_sanction": motif_sanction,
            "date_inscription": date_inscription,
            "date_suppression": None,
            "statut": statut.upper()[:30] if statut else "ACTIF",
            "aliases": [],
            "hash_signature": generate_hash_signature(
                "UKSL",
                nom_complet,
                date_naissance,
                reference_externe,
            ),
        }

        entries.append(item)

    return entries