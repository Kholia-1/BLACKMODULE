import json
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, date


def clean_text(value):
    if value is None:
        return None
    value = str(value).strip()
    if not value or value.lower() in ["nan", "none", "null", "n/a", "na"]:
        return None
    return value


def parse_date(value):
    value = clean_text(value)
    if not value:
        return None
    formats = ["%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d", "%Y"]
    for fmt in formats:
        try:
            parsed = datetime.strptime(value[:10], fmt).date()
            if fmt == "%Y":
                return date(parsed.year, 1, 1)
            return parsed
        except ValueError:
            continue
    return None


def generate_hash_signature(source_liste, nom, prenom, date_naissance, num_passeport):
    raw_value = f"{source_liste}|{nom}|{prenom}|{date_naissance}|{num_passeport}"
    return hashlib.sha256(raw_value.upper().encode("utf-8")).hexdigest()


def local_name(tag):
    return tag.split("}", 1)[1] if "}" in tag else tag


def get_child_text(element, possible_names):
    names = [name.lower() for name in possible_names]
    for child in element.iter():
        if local_name(child.tag).lower() in names and child.text:
            value = clean_text(child.text)
            if value:
                return value
    return None


def get_all_child_texts(element, possible_names):
    names = [name.lower() for name in possible_names]
    values = []
    for child in element.iter():
        if local_name(child.tag).lower() in names and child.text:
            value = clean_text(child.text)
            if value:
                values.append(value)
    unique, seen = [], set()
    for value in values:
        key = value.upper()
        if key not in seen:
            seen.add(key)
            unique.append(value)
    return unique


def value_from_dict(data, possible_keys):
    if not isinstance(data, dict):
        return None
    lower_map = {str(k).lower(): k for k in data.keys()}
    for key in possible_keys:
        real_key = lower_map.get(key.lower())
        if real_key is not None:
            return data.get(real_key)
    return None


def first_clean_value(data, possible_keys):
    value = value_from_dict(data, possible_keys)
    if isinstance(value, dict):
        for nested_key in ["valeur", "value", "libelle", "label", "texte", "text", "nom", "name"]:
            cleaned = first_clean_value(value, [nested_key])
            if cleaned:
                return cleaned
    if isinstance(value, list):
        for item in value:
            cleaned = clean_text(item)
            if cleaned:
                return cleaned
            if isinstance(item, dict):
                cleaned = first_clean_value(item, ["valeur", "value", "libelle", "label", "texte", "text", "nom", "name"])
                if cleaned:
                    return cleaned
    return clean_text(value)


def collect_text_values(value):
    results = []
    if value is None:
        return results
    if isinstance(value, str):
        cleaned = clean_text(value)
        if cleaned:
            results.append(cleaned)
    elif isinstance(value, dict):
        for nested_value in value.values():
            results.extend(collect_text_values(nested_value))
    elif isinstance(value, list):
        for item in value:
            results.extend(collect_text_values(item))
    else:
        cleaned = clean_text(value)
        if cleaned:
            results.append(cleaned)
    return results


def extract_records_from_json(data):
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []

    records = []
    direct_keys = [
        "data", "items", "results", "resultats", "publications", "publication",
        "registre", "mesures", "gels", "personnes", "personnesPhysiques",
        "personnesMorales", "entites", "individus", "registres",
    ]

    for key in direct_keys:
        value = value_from_dict(data, [key])
        if isinstance(value, list):
            records.extend([item for item in value if isinstance(item, dict)])
        elif isinstance(value, dict):
            records.extend(extract_records_from_json(value))

    identity_keys = [
        "nom", "prenom", "nomComplet", "nom_complet", "denomination",
        "raisonSociale", "name", "fullName", "alias", "identite",
    ]

    if any(value_from_dict(data, [key]) is not None for key in identity_keys):
        records.append(data)

    for value in data.values():
        if isinstance(value, (dict, list)):
            records.extend(extract_records_from_json(value))

    unique, seen = [], set()
    for record in records:
        marker = id(record)
        if marker not in seen:
            seen.add(marker)
            unique.append(record)
    return unique


def detect_type_entite(row):
    type_raw = first_clean_value(row, ["type_entite", "typeEntite", "type", "nature", "categorie", "category"])
    text = (type_raw or "").lower()
    if any(word in text for word in ["morale", "entite", "entity", "organisation", "organization", "societe", "société"]):
        return "PERSONNE_MORALE"
    if any(word in text for word in ["navire", "ship", "vessel"]):
        return "NAVIRE"
    denomination = first_clean_value(row, ["denomination", "raisonSociale", "socialReason", "companyName"])
    return "PERSONNE_MORALE" if denomination else "PERSONNE_PHYSIQUE"


def parse_json_record(row):
    nom = first_clean_value(row, ["nom", "lastName", "name", "patronyme"])
    prenom = first_clean_value(row, ["prenom", "firstName", "givenName"])
    denomination = first_clean_value(row, ["denomination", "raisonSociale", "companyName", "nomSociete"])
    nom_complet = first_clean_value(row, ["nom_complet", "nomComplet", "fullName", "nameComplete", "identite"])

    if not nom_complet:
        nom_complet = denomination or " ".join([p for p in [prenom, nom] if p])
    if not nom and nom_complet:
        nom = denomination or nom_complet
    if not nom:
        return None

    type_entite = detect_type_entite(row)
    date_naissance = parse_date(first_clean_value(row, ["date_naissance", "dateNaissance", "birthDate", "dateOfBirth"]))
    nationalite = first_clean_value(row, ["nationalite", "nationality", "paysNationalite"])
    pays = first_clean_value(row, ["pays", "country", "paysResidence", "adressePays"])
    num_passeport = first_clean_value(row, ["num_passeport", "numPasseport", "passeport", "passport", "documentNumber", "numeroDocument", "identifiant"])
    motif_sanction = first_clean_value(row, ["decision", "motif_sanction", "motifSanction", "motif", "fondement", "reference", "programme"]) or "FRANCE GEL DES AVOIRS"
    date_inscription = parse_date(first_clean_value(row, ["date_inscription", "dateInscription", "datePublication", "publicationDate", "listedOn"])) or date.today()
    date_suppression = parse_date(first_clean_value(row, ["date_suppression", "dateSuppression", "dateRadiation", "removedDate"]))
    statut = first_clean_value(row, ["statut", "status", "etat"]) or "ACTIF"

    alias_values = []
    for key in ["alias", "aliases", "aliasName", "autreNom", "autresNoms"]:
        alias_values.extend(collect_text_values(value_from_dict(row, [key])))

    aliases, seen_alias = [], set()
    for alias in alias_values:
        alias = alias.upper()
        if alias != nom_complet.upper() and alias not in seen_alias:
            seen_alias.add(alias)
            aliases.append(alias)

    hash_signature = generate_hash_signature("FR_GEL", nom, prenom, date_naissance, num_passeport)
    return {
        "source_liste": "FR_GEL",
        "type_entite": type_entite,
        "nom": nom.upper()[:150] if nom else None,
        "prenom": prenom.upper()[:150] if prenom else None,
        "nom_complet": nom_complet.upper()[:255] if nom_complet else nom.upper()[:255],
        "date_naissance": date_naissance,
        "nationalite": nationalite.upper()[:100] if nationalite else None,
        "pays": pays.upper()[:100] if pays else None,
        "num_passeport": num_passeport.upper()[:100] if num_passeport else None,
        "motif_sanction": motif_sanction[:500] if motif_sanction else "FRANCE GEL DES AVOIRS",
        "date_inscription": date_inscription,
        "date_suppression": date_suppression,
        "statut": statut.upper()[:30],
        "hash_signature": hash_signature,
        "aliases": aliases,
    }


def parse_france_gel_json(file_content: bytes) -> list[dict]:
    data = json.loads(file_content.decode("utf-8-sig"))
    records = extract_records_from_json(data)
    if not records:
        raise ValueError("Structure JSON France Gel non reconnue : aucune fiche exploitable trouvée.")

    entries, seen = [], set()
    for row in records:
        item = parse_json_record(row)
        if not item:
            continue
        hash_signature = item.get("hash_signature")
        if hash_signature in seen:
            continue
        seen.add(hash_signature)
        entries.append(item)
    return entries


def find_france_gel_records(root):
    possible_record_names = ["personne", "person", "individu", "individual", "entite", "entity", "registre", "record", "publication", "mesure", "gel"]
    records = []
    for element in root.iter():
        if local_name(element.tag).lower() in possible_record_names:
            records.append(element)
    return records


def parse_france_gel_xml(file_content: bytes) -> list[dict]:
    root = ET.fromstring(file_content)
    records = find_france_gel_records(root)
    entries, seen = [], set()

    for record in records:
        nom = get_child_text(record, ["nom", "lastName", "name"])
        prenom = get_child_text(record, ["prenom", "firstName", "givenName"])
        nom_complet = get_child_text(record, ["nomComplet", "nom_complet", "fullName", "nameComplete", "denomination"])
        if not nom_complet:
            nom_complet = " ".join([p for p in [prenom, nom] if p])
        if not nom and nom_complet:
            nom = nom_complet
        if not nom:
            continue

        type_raw = get_child_text(record, ["type", "typeEntite", "nature"])
        type_text = (type_raw or "").lower()
        type_entite = "PERSONNE_PHYSIQUE"
        if any(word in type_text for word in ["morale", "entity", "organisation", "organization", "societe", "société"]):
            type_entite = "PERSONNE_MORALE"
        if any(word in type_text for word in ["navire", "ship", "vessel"]):
            type_entite = "NAVIRE"

        date_naissance = parse_date(get_child_text(record, ["dateNaissance", "date_naissance", "birthDate", "dateOfBirth"]))
        nationalite = get_child_text(record, ["nationalite", "nationality"])
        pays = get_child_text(record, ["pays", "country"])
        num_passeport = get_child_text(record, ["numPasseport", "passeport", "passport", "documentNumber", "numeroDocument"])
        motif_sanction = get_child_text(record, ["decision", "motif", "motifSanction", "fondement", "reference"]) or "FRANCE GEL DES AVOIRS"
        date_inscription = parse_date(get_child_text(record, ["dateInscription", "datePublication", "publicationDate", "listedOn"])) or date.today()
        date_suppression = parse_date(get_child_text(record, ["dateSuppression", "dateRadiation", "removedDate"]))
        statut = get_child_text(record, ["statut", "status"]) or "ACTIF"
        aliases = get_all_child_texts(record, ["alias", "aliasName", "autreNom", "nomAlias"])
        hash_signature = generate_hash_signature("FR_GEL", nom, prenom, date_naissance, num_passeport)
        if hash_signature in seen:
            continue
        seen.add(hash_signature)
        entries.append({
            "source_liste": "FR_GEL",
            "type_entite": type_entite,
            "nom": nom.upper()[:150] if nom else None,
            "prenom": prenom.upper()[:150] if prenom else None,
            "nom_complet": nom_complet.upper()[:255] if nom_complet else nom.upper()[:255],
            "date_naissance": date_naissance,
            "nationalite": nationalite.upper()[:100] if nationalite else None,
            "pays": pays.upper()[:100] if pays else None,
            "num_passeport": num_passeport.upper()[:100] if num_passeport else None,
            "motif_sanction": motif_sanction[:500] if motif_sanction else "FRANCE GEL DES AVOIRS",
            "date_inscription": date_inscription,
            "date_suppression": date_suppression,
            "statut": statut.upper()[:30] if statut else "ACTIF",
            "hash_signature": hash_signature,
            "aliases": [alias.upper() for alias in aliases if alias],
        })
    return entries
