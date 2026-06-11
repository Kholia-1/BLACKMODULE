import json
import hashlib
from datetime import datetime, date
import xml.etree.ElementTree as ET

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

    if not value or value.lower() in ["nan", "none", "null"]:
        return None

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


def parse_france_gel_json(file_content: bytes) -> list[dict]:
    """
    Parse un fichier JSON France Gel des Avoirs.

    Format accepté :
    [
      {
        "nom": "DURAND",
        "prenom": "PIERRE",
        "nom_complet": "PIERRE DURAND",
        "type_entite": "PERSONNE_PHYSIQUE",
        "date_naissance": "1972-09-01",
        "nationalite": "FRANCAISE",
        "pays": "FRANCE",
        "num_passeport": "FRP123456",
        "decision": "Décision de gel des avoirs",
        "date_inscription": "2025-03-01",
        "date_suppression": null,
        "statut": "ACTIF",
        "alias": ["P DURAND", "PIERRE D."]
      }
    ]
    """

    decoded_content = file_content.decode("utf-8-sig")
    data = json.loads(decoded_content)

    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        if "data" in data and isinstance(data["data"], list):
            records = data["data"]
        elif "items" in data and isinstance(data["items"], list):
            records = data["items"]
        elif "results" in data and isinstance(data["results"], list):
            records = data["results"]
        else:
            raise ValueError("Structure JSON France Gel non reconnue.")
    else:
        raise ValueError("Le JSON France Gel doit être une liste ou contenir une liste.")

    normalized_entries = []

    for row in records:
        nom = clean_text(row.get("nom"))
        prenom = clean_text(row.get("prenom"))
        nom_complet = clean_text(row.get("nom_complet"))

        type_entite = clean_text(row.get("type_entite")) or "PERSONNE_PHYSIQUE"

        date_naissance = parse_date(row.get("date_naissance"))
        nationalite = clean_text(row.get("nationalite"))
        pays = clean_text(row.get("pays"))
        num_passeport = clean_text(row.get("num_passeport"))

        decision = clean_text(row.get("decision")) or clean_text(row.get("motif_sanction"))
        motif_sanction = decision or "FRANCE GEL DES AVOIRS"

        date_inscription = parse_date(row.get("date_inscription")) or date.today()
        date_suppression = parse_date(row.get("date_suppression"))
        statut = clean_text(row.get("statut")) or "ACTIF"

        alias_raw = row.get("alias")
        aliases = []

        if isinstance(alias_raw, list):
            aliases = [
                clean_text(alias).upper()
                for alias in alias_raw
                if clean_text(alias)
            ]

        elif isinstance(alias_raw, str):
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
            source_liste="FR_GEL",
            nom=nom,
            prenom=prenom,
            date_naissance=date_naissance,
            num_passeport=num_passeport
        )

        normalized_entries.append({
            "source_liste": "FR_GEL",
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
            "date_suppression": date_suppression,
            "statut": statut.upper(),
            "hash_signature": hash_signature,
            "aliases": aliases
        })

    return normalized_entries

def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def get_child_text(element, possible_names: list[str]) -> str | None:
    for child in element.iter():
        if local_name(child.tag).lower() in [name.lower() for name in possible_names]:
            if child.text:
                return clean_text(child.text)
    return None


def get_all_child_texts(element, possible_names: list[str]) -> list[str]:
    values = []

    for child in element.iter():
        if local_name(child.tag).lower() in [name.lower() for name in possible_names]:
            if child.text:
                value = clean_text(child.text)
                if value:
                    values.append(value)

    unique = []
    for value in values:
        if value.upper() not in [v.upper() for v in unique]:
            unique.append(value)

    return unique


def find_france_gel_records(root):
    """
    Recherche souple des blocs contenant les personnes ou entités.
    Le XML officiel peut varier selon la structure utilisée.
    """
    possible_record_names = [
        "personne",
        "person",
        "individu",
        "individual",
        "entite",
        "entity",
        "registre",
        "record",
        "publication"
    ]

    records = []

    for element in root.iter():
        tag = local_name(element.tag).lower()

        if tag in possible_record_names:
            records.append(element)

    return records


def parse_france_gel_xml(file_content: bytes) -> list[dict]:
    """
    Parse un fichier XML France Gel des Avoirs.

    Le parseur est volontairement souple pour accepter plusieurs variantes :
    - nom / prenom / nom_complet
    - alias
    - date_naissance
    - nationalite / pays
    - passeport / document
    - decision / motif / fondement
    """

    root = ET.fromstring(file_content)
    records = find_france_gel_records(root)

    normalized_entries = []

    for record in records:
        nom = get_child_text(record, ["nom", "lastName", "name"])
        prenom = get_child_text(record, ["prenom", "firstName", "givenName"])
        nom_complet = get_child_text(record, ["nomComplet", "fullName", "nameComplete", "denomination"])

        if not nom_complet:
            parts = [prenom, nom]
            nom_complet = " ".join([p for p in parts if p])

        if not nom and nom_complet:
            nom = nom_complet

        if not nom:
            continue

        type_raw = get_child_text(record, ["type", "typeEntite", "nature"])
        type_entite = "PERSONNE_PHYSIQUE"

        if type_raw and any(word in type_raw.lower() for word in ["morale", "entity", "organisation", "organization", "societe", "société"]):
            type_entite = "PERSONNE_MORALE"

        date_naissance = parse_date(
            get_child_text(record, ["dateNaissance", "date_naissance", "birthDate", "dateOfBirth"])
        )

        nationalite = get_child_text(record, ["nationalite", "nationality"])
        pays = get_child_text(record, ["pays", "country"])
        num_passeport = get_child_text(record, ["numPasseport", "passeport", "passport", "documentNumber", "numeroDocument"])

        decision = (
            get_child_text(record, ["decision", "motif", "motifSanction", "fondement", "reference"])
            or "FRANCE GEL DES AVOIRS"
        )

        date_inscription = parse_date(
            get_child_text(record, ["dateInscription", "datePublication", "publicationDate", "listedOn"])
        ) or date.today()

        date_suppression = parse_date(
            get_child_text(record, ["dateSuppression", "dateRadiation", "removedDate"])
        )

        statut = get_child_text(record, ["statut", "status"]) or "ACTIF"

        aliases = get_all_child_texts(record, ["alias", "aliasName", "autreNom", "nomAlias"])

        hash_signature = generate_hash_signature(
            source_liste="FR_GEL",
            nom=nom,
            prenom=prenom,
            date_naissance=date_naissance,
            num_passeport=num_passeport
        )

        normalized_entries.append({
            "source_liste": "FR_GEL",
            "type_entite": type_entite,
            "nom": nom.upper() if nom else None,
            "prenom": prenom.upper() if prenom else None,
            "nom_complet": nom_complet.upper() if nom_complet else nom.upper(),
            "date_naissance": date_naissance,
            "nationalite": nationalite.upper() if nationalite else None,
            "pays": pays.upper() if pays else None,
            "num_passeport": num_passeport.upper() if num_passeport else None,
            "motif_sanction": decision,
            "date_inscription": date_inscription,
            "date_suppression": date_suppression,
            "statut": statut.upper(),
            "hash_signature": hash_signature,
            "aliases": [alias.upper() for alias in aliases if alias]
        })

    return normalized_entries

def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def get_child_text(element, possible_names: list[str]) -> str | None:
    for child in element.iter():
        if local_name(child.tag).lower() in [name.lower() for name in possible_names]:
            if child.text:
                return clean_text(child.text)
    return None


def get_all_child_texts(element, possible_names: list[str]) -> list[str]:
    values = []

    for child in element.iter():
        if local_name(child.tag).lower() in [name.lower() for name in possible_names]:
            if child.text:
                value = clean_text(child.text)
                if value:
                    values.append(value)

    unique = []
    for value in values:
        if value.upper() not in [v.upper() for v in unique]:
            unique.append(value)

    return unique


def find_france_gel_records(root):
    """
    Recherche souple des blocs contenant les personnes ou entités.
    Le XML officiel peut varier selon la structure utilisée.
    """
    possible_record_names = [
        "personne",
        "person",
        "individu",
        "individual",
        "entite",
        "entity",
        "registre",
        "record",
        "publication"
    ]

    records = []

    for element in root.iter():
        tag = local_name(element.tag).lower()

        if tag in possible_record_names:
            records.append(element)

    return records


def parse_france_gel_xml(file_content: bytes) -> list[dict]:
    """
    Parse un fichier XML France Gel des Avoirs.

    Le parseur est volontairement souple pour accepter plusieurs variantes :
    - nom / prenom / nom_complet
    - alias
    - date_naissance
    - nationalite / pays
    - passeport / document
    - decision / motif / fondement
    """

    root = ET.fromstring(file_content)
    records = find_france_gel_records(root)

    normalized_entries = []

    for record in records:
        nom = get_child_text(record, ["nom", "lastName", "name"])
        prenom = get_child_text(record, ["prenom", "firstName", "givenName"])
        nom_complet = get_child_text(record, ["nomComplet", "fullName", "nameComplete", "denomination"])

        if not nom_complet:
            parts = [prenom, nom]
            nom_complet = " ".join([p for p in parts if p])

        if not nom and nom_complet:
            nom = nom_complet

        if not nom:
            continue

        type_raw = get_child_text(record, ["type", "typeEntite", "nature"])
        type_entite = "PERSONNE_PHYSIQUE"

        if type_raw and any(word in type_raw.lower() for word in ["morale", "entity", "organisation", "organization", "societe", "société"]):
            type_entite = "PERSONNE_MORALE"

        date_naissance = parse_date(
            get_child_text(record, ["dateNaissance", "date_naissance", "birthDate", "dateOfBirth"])
        )

        nationalite = get_child_text(record, ["nationalite", "nationality"])
        pays = get_child_text(record, ["pays", "country"])
        num_passeport = get_child_text(record, ["numPasseport", "passeport", "passport", "documentNumber", "numeroDocument"])

        decision = (
            get_child_text(record, ["decision", "motif", "motifSanction", "fondement", "reference"])
            or "FRANCE GEL DES AVOIRS"
        )

        date_inscription = parse_date(
            get_child_text(record, ["dateInscription", "datePublication", "publicationDate", "listedOn"])
        ) or date.today()

        date_suppression = parse_date(
            get_child_text(record, ["dateSuppression", "dateRadiation", "removedDate"])
        )

        statut = get_child_text(record, ["statut", "status"]) or "ACTIF"

        aliases = get_all_child_texts(record, ["alias", "aliasName", "autreNom", "nomAlias"])

        hash_signature = generate_hash_signature(
            source_liste="FR_GEL",
            nom=nom,
            prenom=prenom,
            date_naissance=date_naissance,
            num_passeport=num_passeport
        )

        normalized_entries.append({
            "source_liste": "FR_GEL",
            "type_entite": type_entite,
            "nom": nom.upper() if nom else None,
            "prenom": prenom.upper() if prenom else None,
            "nom_complet": nom_complet.upper() if nom_complet else nom.upper(),
            "date_naissance": date_naissance,
            "nationalite": nationalite.upper() if nationalite else None,
            "pays": pays.upper() if pays else None,
            "num_passeport": num_passeport.upper() if num_passeport else None,
            "motif_sanction": decision,
            "date_inscription": date_inscription,
            "date_suppression": date_suppression,
            "statut": statut.upper(),
            "hash_signature": hash_signature,
            "aliases": [alias.upper() for alias in aliases if alias]
        })

    return normalized_entries