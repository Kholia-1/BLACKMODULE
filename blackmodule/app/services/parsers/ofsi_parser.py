import csv
import hashlib
from datetime import datetime, date
from io import StringIO
from io import BytesIO
import pandas as pd


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

    if hasattr(value, "date"):
        try:
            return value.date()
        except Exception:
            pass

    value = str(value).strip()

    if not value or value.lower() in ["nan", "none", "null"]:
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


def generate_hash_signature(
    source_liste: str,
    nom: str | None,
    prenom: str | None,
    date_naissance: date | None,
    num_passeport: str | None
) -> str:
    raw_value = f"{source_liste}|{nom}|{prenom}|{date_naissance}|{num_passeport}"
    return hashlib.sha256(raw_value.upper().encode("utf-8")).hexdigest()


def parse_ofsi_csv(file_content: bytes) -> list[dict]:
    """
    Parse un fichier CSV OFSI UK simplifié.

    Colonnes attendues pour le prototype :
    nom_complet,type_entite,date_naissance,nationalite,pays,num_passeport,adresse,motif_sanction,date_inscription,statut,alias
    """

    decoded_content = file_content.decode("utf-8-sig")
    csv_file = StringIO(decoded_content)

    reader = csv.DictReader(csv_file)

    if not reader.fieldnames:
        raise ValueError("Le fichier CSV OFSI est vide ou invalide.")

    required_columns = [
        "nom_complet",
        "type_entite",
        "date_naissance",
        "nationalite",
        "pays",
        "num_passeport",
        "adresse",
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
            f"Colonnes manquantes dans le CSV OFSI : {', '.join(missing_columns)}"
        )

    normalized_entries = []

    for row in reader:
        nom_complet = clean_text(row.get("nom_complet"))
        type_entite = clean_text(row.get("type_entite")) or "PERSONNE_PHYSIQUE"

        date_naissance = parse_date(row.get("date_naissance"))
        nationalite = clean_text(row.get("nationalite"))
        pays = clean_text(row.get("pays"))
        num_passeport = clean_text(row.get("num_passeport"))
        adresse = clean_text(row.get("adresse"))

        motif_sanction = clean_text(row.get("motif_sanction")) or "OFSI UK SANCTIONS"
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
            continue

        name_parts = nom_complet.split()

        if len(name_parts) >= 2 and type_entite.upper() == "PERSONNE_PHYSIQUE":
            prenom = name_parts[0]
            nom = " ".join(name_parts[1:])
        else:
            prenom = None
            nom = nom_complet

        if adresse:
            motif_sanction = f"{motif_sanction} | Adresse : {adresse}"

        hash_signature = generate_hash_signature(
            source_liste="OFSI",
            nom=nom,
            prenom=prenom,
            date_naissance=date_naissance,
            num_passeport=num_passeport
        )

        normalized_entries.append({
            "source_liste": "OFSI",
            "type_entite": type_entite.upper(),
            "nom": nom.upper() if nom else nom_complet.upper(),
            "prenom": prenom.upper() if prenom else None,
            "nom_complet": nom_complet.upper(),
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

def parse_ofsi_excel(file_content: bytes) -> list[dict]:
    """
    Parse un fichier Excel OFSI UK simplifié.

    Colonnes attendues :
    nom_complet,type_entite,date_naissance,nationalite,pays,num_passeport,adresse,motif_sanction,date_inscription,statut,alias
    """

    excel_file = BytesIO(file_content)

    try:
        df = pd.read_excel(excel_file)
    except Exception as e:
        raise ValueError(f"Impossible de lire le fichier Excel OFSI : {str(e)}")

    required_columns = [
        "nom_complet",
        "type_entite",
        "date_naissance",
        "nationalite",
        "pays",
        "num_passeport",
        "adresse",
        "motif_sanction",
        "date_inscription",
        "statut",
        "alias"
    ]

    missing_columns = [
        col for col in required_columns
        if col not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Colonnes manquantes dans le fichier Excel OFSI : {', '.join(missing_columns)}"
        )

    normalized_entries = []

    for _, row in df.iterrows():
        nom_complet = clean_text(row.get("nom_complet"))
        type_entite = clean_text(row.get("type_entite")) or "PERSONNE_PHYSIQUE"

        date_naissance = parse_date(row.get("date_naissance"))
        nationalite = clean_text(row.get("nationalite"))
        pays = clean_text(row.get("pays"))
        num_passeport = clean_text(row.get("num_passeport"))
        adresse = clean_text(row.get("adresse"))

        motif_sanction = clean_text(row.get("motif_sanction")) or "OFSI UK SANCTIONS"
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
            continue

        name_parts = nom_complet.split()

        if len(name_parts) >= 2 and type_entite.upper() == "PERSONNE_PHYSIQUE":
            prenom = name_parts[0]
            nom = " ".join(name_parts[1:])
        else:
            prenom = None
            nom = nom_complet

        if adresse:
            motif_sanction = f"{motif_sanction} | Adresse : {adresse}"

        hash_signature = generate_hash_signature(
            source_liste="OFSI",
            nom=nom,
            prenom=prenom,
            date_naissance=date_naissance,
            num_passeport=num_passeport
        )

        normalized_entries.append({
            "source_liste": "OFSI",
            "type_entite": type_entite.upper(),
            "nom": nom.upper() if nom else nom_complet.upper(),
            "prenom": prenom.upper() if prenom else None,
            "nom_complet": nom_complet.upper(),
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



