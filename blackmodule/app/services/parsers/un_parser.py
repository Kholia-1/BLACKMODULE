import hashlib
import defusedxml.ElementTree as ET
from datetime import datetime, date


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


def get_text_from_child(element, child_name: str) -> str | None:
    child = element.find(child_name)

    if child is not None and child.text:
        return clean_text(child.text)

    return None


def parse_un_xml(file_content: bytes) -> list[dict]:
    """
    Parse une liste ONU XML simplifiée et retourne des entrées normalisées BLACKMODULE.

    Le parseur supporte une structure de type :
    <CONSOLIDATED_LIST>
        <INDIVIDUALS>
            <INDIVIDUAL>
                <FIRST_NAME>...</FIRST_NAME>
                <SECOND_NAME>...</SECOND_NAME>
                <THIRD_NAME>...</THIRD_NAME>
                <FOURTH_NAME>...</FOURTH_NAME>
                <NATIONALITY>...</NATIONALITY>
                <INDIVIDUAL_DATE_OF_BIRTH>...</INDIVIDUAL_DATE_OF_BIRTH>
                <INDIVIDUAL_ALIAS>...</INDIVIDUAL_ALIAS>
                <INDIVIDUAL_DOCUMENT>...</INDIVIDUAL_DOCUMENT>
            </INDIVIDUAL>
        </INDIVIDUALS>
        <ENTITIES>
            <ENTITY>...</ENTITY>
        </ENTITIES>
    </CONSOLIDATED_LIST>
    """

    root = ET.fromstring(file_content)

    normalized_entries = []

    # ============================
    # PERSONNES PHYSIQUES ONU
    # ============================

    individuals = root.findall(".//INDIVIDUAL")

    for individual in individuals:
        source_record_id = (
            get_text_from_child(individual, "DATAID")
            or get_text_from_child(individual, "REFERENCE_NUMBER")
        )
        first_name = get_text_from_child(individual, "FIRST_NAME")
        second_name = get_text_from_child(individual, "SECOND_NAME")
        third_name = get_text_from_child(individual, "THIRD_NAME")
        fourth_name = get_text_from_child(individual, "FOURTH_NAME")

        name_parts = [
            first_name,
            second_name,
            third_name,
            fourth_name
        ]

        full_name = " ".join([p for p in name_parts if p])

        prenom = first_name
        nom_parts = [second_name, third_name, fourth_name]
        nom = " ".join([p for p in nom_parts if p])

        if not nom:
            nom = full_name

        # Nationalité(s) : plusieurs valeurs sont parfois listées
        nationalites_list = []

        for nationality_value_node in individual.findall(".//NATIONALITY/VALUE"):
            if nationality_value_node.text:
                value = clean_text(nationality_value_node.text)
                if value and value not in nationalites_list:
                    nationalites_list.append(value)

        nationalite = "; ".join(nationalites_list) if nationalites_list else None

        # Pays de résidence : distinct de la nationalité, tiré de l'adresse si présente
        pays_residence = None
        address_country_node = individual.find(".//INDIVIDUAL_ADDRESS/COUNTRY")

        if address_country_node is not None and address_country_node.text:
            pays_residence = clean_text(address_country_node.text)

        # Date de naissance (certaines fiches ONU ne donnent que l'année)
        date_naissance = None
        dob_node = individual.find(".//INDIVIDUAL_DATE_OF_BIRTH/DATE")

        if dob_node is not None and dob_node.text:
            date_naissance = parse_date(dob_node.text)

        if not date_naissance:
            year_node = individual.find(".//INDIVIDUAL_DATE_OF_BIRTH/YEAR")

            if year_node is not None and year_node.text:
                date_naissance = parse_date(year_node.text)

        # Lieu de naissance (ville / état / pays selon ce qui est renseigné)
        lieu_naissance_parts = []

        for place_node in individual.findall(".//INDIVIDUAL_PLACE_OF_BIRTH"):
            for field_name in ["CITY", "STATE_PROVINCE", "COUNTRY"]:
                value = get_text_from_child(place_node, field_name)

                if value and value not in lieu_naissance_parts:
                    lieu_naissance_parts.append(value)

        lieu_naissance = ", ".join(lieu_naissance_parts) if lieu_naissance_parts else None

        # Passeport et autres pièces d'identité : on ne retient comme "passeport"
        # que les documents explicitement de ce type, sinon une carte nationale
        # d'identité se retrouverait étiquetée passeport.
        num_passeport = None
        autres_documents_list = []

        for document_node in individual.findall(".//INDIVIDUAL_DOCUMENT"):
            doc_type = get_text_from_child(document_node, "TYPE_OF_DOCUMENT")
            doc_number = get_text_from_child(document_node, "NUMBER")

            if not doc_number:
                continue

            if doc_type and any(
                keyword in doc_type.lower()
                for keyword in ["passport", "passeport", "pasaporte"]
            ):
                if not num_passeport:
                    num_passeport = doc_number
            else:
                autres_documents_list.append(f"{doc_type or 'DOCUMENT'} : {doc_number}")

        autres_documents = "; ".join(autres_documents_list) if autres_documents_list else None

        # Alias
        aliases = []

        alias_nodes = individual.findall(".//INDIVIDUAL_ALIAS")

        for alias_node in alias_nodes:
            alias_name = get_text_from_child(alias_node, "ALIAS_NAME")

            if alias_name:
                aliases.append(alias_name.upper())

        # Motif / programme ONU
        listed_on = get_text_from_child(individual, "LISTED_ON")
        comments = get_text_from_child(individual, "COMMENTS1")

        motif_sanction = "ONU SANCTIONS"

        if comments:
            motif_sanction = comments

        date_inscription = parse_date(listed_on)

        hash_signature = generate_hash_signature(
            source_liste="ONU",
            nom=nom,
            prenom=prenom,
            date_naissance=date_naissance,
            num_passeport=num_passeport
        )

        normalized_entries.append({
            "source_liste": "ONU",
            "source_record_id": source_record_id,
            "type_entite": "PERSONNE_PHYSIQUE",
            "nom": nom.upper() if nom else full_name.upper(),
            "prenom": prenom.upper() if prenom else None,
            "nom_complet": full_name.upper(),
            "date_naissance": date_naissance,
            "lieu_naissance": lieu_naissance.upper() if lieu_naissance else None,
            "nationalite": nationalite.upper() if nationalite else None,
            "pays": pays_residence.upper() if pays_residence else (nationalite.upper() if nationalite else None),
            "num_passeport": num_passeport.upper() if num_passeport else None,
            "autres_documents": autres_documents.upper() if autres_documents else None,
            "motif_sanction": motif_sanction,
            "date_inscription": date_inscription or date.today(),
            "date_suppression": None,
            "statut": "ACTIF",
            "hash_signature": hash_signature,
            "aliases": aliases
        })

    # ============================
    # PERSONNES MORALES / ENTITÉS ONU
    # ============================

    entities = root.findall(".//ENTITY")

    for entity in entities:
        source_record_id = (
            get_text_from_child(entity, "DATAID")
            or get_text_from_child(entity, "REFERENCE_NUMBER")
        )
        first_name = get_text_from_child(entity, "FIRST_NAME")

        if not first_name:
            continue

        nom_complet = first_name

        aliases = []

        alias_nodes = entity.findall(".//ENTITY_ALIAS")

        for alias_node in alias_nodes:
            alias_name = get_text_from_child(alias_node, "ALIAS_NAME")

            if alias_name:
                aliases.append(alias_name.upper())

        listed_on = get_text_from_child(entity, "LISTED_ON")
        comments = get_text_from_child(entity, "COMMENTS1")

        motif_sanction = comments if comments else "ONU SANCTIONS ENTITY"

        date_inscription = parse_date(listed_on)

        hash_signature = generate_hash_signature(
            source_liste="ONU",
            nom=nom_complet,
            prenom=None,
            date_naissance=None,
            num_passeport=None
        )

        normalized_entries.append({
            "source_liste": "ONU",
            "source_record_id": source_record_id,
            "type_entite": "PERSONNE_MORALE",
            "nom": nom_complet.upper(),
            "prenom": None,
            "nom_complet": nom_complet.upper(),
            "date_naissance": None,
            "nationalite": None,
            "pays": None,
            "num_passeport": None,
            "motif_sanction": motif_sanction,
            "date_inscription": date_inscription or date.today(),
            "date_suppression": None,
            "statut": "ACTIF",
            "hash_signature": hash_signature,
            "aliases": aliases
        })

    return normalized_entries
