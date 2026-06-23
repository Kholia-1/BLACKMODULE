import csv
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, date
from io import StringIO


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


def attr(element, names):
    names = [n.lower() for n in names]
    for k, v in element.attrib.items():
        if local_name(k).lower() in names:
            return clean_text(v)
    return None


def first_child_attr(element, child_names, attr_names):
    child_names = [n.lower() for n in child_names]
    for child in element.iter():
        if local_name(child.tag).lower() in child_names:
            value = attr(child, attr_names)
            if value:
                return value
    return None


def all_child_attrs(element, child_names, attr_names):
    child_names = [n.lower() for n in child_names]
    values = []
    for child in element.iter():
        if local_name(child.tag).lower() in child_names:
            for attr_name in attr_names:
                value = attr(child, [attr_name])
                if value:
                    values.append(value)
    unique, seen = [], set()
    for value in values:
        key = value.upper()
        if key not in seen:
            seen.add(key)
            unique.append(value)
    return unique


def texts(element, names):
    names = [n.lower() for n in names]
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


def first_text(element, names):
    vals = texts(element, names)
    return vals[0] if vals else None


def parse_eu_csv(file_content: bytes) -> list[dict]:
    decoded_content = file_content.decode("utf-8-sig")
    reader = csv.DictReader(StringIO(decoded_content))
    if not reader.fieldnames:
        raise ValueError("Le fichier CSV UE est vide ou invalide.")

    entries = []
    for row in reader:
        nom = clean_text(row.get("nom"))
        prenom = clean_text(row.get("prenom"))
        nom_complet = clean_text(row.get("nom_complet")) or " ".join([p for p in [prenom, nom] if p])
        if not nom and nom_complet:
            nom = nom_complet
        if not nom:
            continue
        date_naissance = parse_date(row.get("date_naissance"))
        num_passeport = clean_text(row.get("num_passeport"))
        hash_signature = generate_hash_signature("UE", nom, prenom, date_naissance, num_passeport)
        entries.append({
            "source_liste": "UE",
            "type_entite": (clean_text(row.get("type_entite")) or "PERSONNE_PHYSIQUE").upper(),
            "nom": nom.upper(),
            "prenom": prenom.upper() if prenom else None,
            "nom_complet": nom_complet.upper() if nom_complet else nom.upper(),
            "date_naissance": date_naissance,
            "nationalite": clean_text(row.get("nationalite")).upper() if clean_text(row.get("nationalite")) else None,
            "pays": clean_text(row.get("pays")).upper() if clean_text(row.get("pays")) else None,
            "num_passeport": num_passeport.upper() if num_passeport else None,
            "motif_sanction": clean_text(row.get("motif_sanction")) or "UNION EUROPEENNE SANCTIONS",
            "date_inscription": parse_date(row.get("date_inscription")) or date.today(),
            "date_suppression": None,
            "statut": (clean_text(row.get("statut")) or "ACTIF").upper(),
            "hash_signature": hash_signature,
            "aliases": []
        })
    return entries


def find_eu_records(root):
    records = []
    for element in root.iter():
        tag = local_name(element.tag).lower()
        if tag in ["sanctionentity", "sanctionedentity", "entity", "subject"]:
            has_name_alias = any(local_name(child.tag).lower() == "namealias" for child in element.iter())
            if has_name_alias or tag == "sanctionentity":
                records.append(element)
    return records


def parse_eu_xml(file_content: bytes) -> list[dict]:
    root = ET.fromstring(file_content)
    records = find_eu_records(root)
    entries = []
    seen = set()

    for record in records:
        name_values = all_child_attrs(record, ["nameAlias", "alias", "name"], ["wholeName", "name", "alias", "lastName", "firstName", "middleName"])
        name_values += [v for v in texts(record, ["wholeName", "nameAlias", "alias", "name", "fullName"]) if v not in name_values]

        first_name = first_child_attr(record, ["nameAlias"], ["firstName", "givenName", "forename"]) or first_text(record, ["firstName", "givenName", "forename"])
        middle_name = first_child_attr(record, ["nameAlias"], ["middleName"])
        last_name = first_child_attr(record, ["nameAlias"], ["lastName", "surname", "familyName"]) or first_text(record, ["lastName", "surname", "familyName"])
        whole_name = first_child_attr(record, ["nameAlias"], ["wholeName"]) or (name_values[0] if name_values else None)

        if first_name and last_name:
            prenom = " ".join([p for p in [first_name, middle_name] if p])
            nom = last_name
            nom_complet = whole_name or f"{prenom} {nom}"
        elif whole_name:
            prenom = None
            nom = whole_name
            nom_complet = whole_name
        else:
            continue

        aliases = [v.upper() for v in name_values if v and v.upper() != nom_complet.upper()]
        subject_type = attr(record, ["subjectType", "subjectTypeClassificationCode"]) or first_child_attr(record, ["subjectType"], ["code", "classificationCode", "description"])
        subject_type_upper = subject_type.upper() if subject_type else ""
        type_entite = "PERSONNE_PHYSIQUE" if subject_type_upper in ["P", "PERSON"] or first_name or last_name else "PERSONNE_MORALE"

        birth_year = first_child_attr(record, ["birthdate"], ["year"])
        birth_month = first_child_attr(record, ["birthdate"], ["monthOfYear", "month"])
        birth_day = first_child_attr(record, ["birthdate"], ["dayOfMonth", "day"])
        date_naissance = None
        if birth_year:
            try:
                date_naissance = date(int(birth_year), int(birth_month) if birth_month else 1, int(birth_day) if birth_day else 1)
            except Exception:
                date_naissance = parse_date(birth_year)
        if not date_naissance:
            date_naissance = parse_date(first_text(record, ["birthdate", "dateOfBirth", "birthDate", "dob"]))

        nationalite = first_child_attr(record, ["citizenship"], ["countryDescription", "countryIso2Code", "country"]) or first_text(record, ["citizenship", "nationality"])
        pays = first_child_attr(record, ["address"], ["countryDescription", "countryIso2Code", "country"]) or first_text(record, ["country", "countryDescription", "addressCountry"])
        num_passeport = first_child_attr(record, ["identification", "document", "passport"], ["number", "passportNumber", "documentNumber", "identificationNumber"])
        motif_sanction = first_child_attr(record, ["regulation", "regulationSummary"], ["programme", "numberTitle", "publicationUrl"]) or first_text(record, ["regulationSummary", "programme", "program", "remark", "reason", "legalBasis"]) or "UNION EUROPEENNE"
        designation_date = attr(record, ["designationDate", "listedOn", "publicationDate"]) or first_child_attr(record, ["regulation"], ["entryIntoForceDate", "publicationDate"])
        date_inscription = parse_date(designation_date) or date.today()

        hash_signature = generate_hash_signature("UE", nom, prenom, date_naissance, num_passeport)
        if hash_signature in seen:
            continue
        seen.add(hash_signature)

        entries.append({
            "source_liste": "UE",
            "type_entite": type_entite,
            "nom": nom.upper()[:150] if nom else None,
            "prenom": prenom.upper()[:150] if prenom else None,
            "nom_complet": nom_complet.upper()[:255],
            "date_naissance": date_naissance,
            "nationalite": nationalite.upper()[:100] if nationalite else None,
            "pays": pays.upper()[:100] if pays else None,
            "num_passeport": num_passeport.upper()[:100] if num_passeport else None,
            "motif_sanction": motif_sanction[:500] if motif_sanction else "UNION EUROPEENNE",
            "date_inscription": date_inscription,
            "date_suppression": None,
            "statut": "ACTIF",
            "hash_signature": hash_signature,
            "aliases": aliases,
        })

    return entries
