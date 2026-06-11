import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, date


def parse_date(value: str | None) -> date | None:
    """
    Convertit une date OFAC en date Python.
    OFAC peut parfois fournir des dates partielles ou textuelles.
    Pour le prototype, on accepte surtout YYYY-MM-DD.
    """
    if not value:
        return None

    value = value.strip()

    if not value:
        return None

    formats = [
        "%Y-%m-%d",
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


def clean_text(value: str | None) -> str | None:
    if value is None:
        return None

    value = value.strip()

    if not value:
        return None

    return value


def generate_hash_signature(
    source_liste: str,
    nom: str | None,
    prenom: str | None,
    date_naissance: date | None,
    num_passeport: str | None
) -> str:
    raw_value = f"{source_liste}|{nom}|{prenom}|{date_naissance}|{num_passeport}"
    return hashlib.sha256(raw_value.upper().encode("utf-8")).hexdigest()


def get_namespace(root):
    """
    Détecte automatiquement le namespace XML si le fichier OFAC en contient un.
    """
    if root.tag.startswith("{"):
        return root.tag.split("}")[0].strip("{")

    return ""


def find_text(element, path: str, namespace: str = "") -> str | None:
    """
    Recherche un texte dans le XML avec ou sans namespace.
    """
    if namespace:
        found = element.find(path, {"ns": namespace})
    else:
        found = element.find(path)

    if found is not None and found.text:
        return clean_text(found.text)

    return None


def find_all(element, path: str, namespace: str = ""):
    if namespace:
        return element.findall(path, {"ns": namespace})

    return element.findall(path)


def parse_ofac_sdn_xml(file_content: bytes) -> list[dict]:
    """
    Parse un fichier OFAC SDN XML et retourne une liste normalisée.

    Chaque entrée retournée respecte notre format BLACKMODULE :
    {
        "source_liste": "OFAC_SDN",
        "type_entite": "...",
        "nom": "...",
        "prenom": "...",
        "nom_complet": "...",
        "date_naissance": ...,
        "nationalite": "...",
        "pays": "...",
        "num_passeport": "...",
        "motif_sanction": "...",
        "statut": "ACTIF",
        "hash_signature": "...",
        "aliases": [...]
    }
    """

    root = ET.fromstring(file_content)
    namespace = get_namespace(root)

    if namespace:
        sdn_entries = root.findall(".//ns:sdnEntry", {"ns": namespace})
    else:
        sdn_entries = root.findall(".//sdnEntry")

    normalized_entries = []

    for entry in sdn_entries:
        uid = find_text(entry, "ns:uid" if namespace else "uid", namespace)
        first_name = find_text(entry, "ns:firstName" if namespace else "firstName", namespace)
        last_name = find_text(entry, "ns:lastName" if namespace else "lastName", namespace)
        sdn_type = find_text(entry, "ns:sdnType" if namespace else "sdnType", namespace)
        program_list = []

        # Programmes de sanctions OFAC
        program_nodes = find_all(
            entry,
            ".//ns:program" if namespace else ".//program",
            namespace
        )

        for program in program_nodes:
            if program.text:
                program_list.append(program.text.strip())

        motif_sanction = ", ".join(program_list) if program_list else "OFAC SDN"

        # Type entité
        if sdn_type and sdn_type.upper() == "INDIVIDUAL":
            type_entite = "PERSONNE_PHYSIQUE"
        else:
            type_entite = "PERSONNE_MORALE"

        nom = clean_text(last_name)
        prenom = clean_text(first_name)

        if prenom and nom:
            nom_complet = f"{prenom} {nom}"
        elif nom:
            nom_complet = nom
        elif prenom:
            nom_complet = prenom
        else:
            nom_complet = f"OFAC_UID_{uid}" if uid else "OFAC_UNKNOWN"

        # Alias OFAC
        aliases = []
        aka_nodes = find_all(
            entry,
            ".//ns:aka" if namespace else ".//aka",
            namespace
        )

        for aka in aka_nodes:
            aka_first = find_text(aka, "ns:firstName" if namespace else "firstName", namespace)
            aka_last = find_text(aka, "ns:lastName" if namespace else "lastName", namespace)

            if aka_first and aka_last:
                aliases.append(f"{aka_first} {aka_last}")
            elif aka_last:
                aliases.append(aka_last)
            elif aka_first:
                aliases.append(aka_first)

        # Nationalité
        nationalite = None
        nationality_nodes = find_all(
            entry,
            ".//ns:nationality" if namespace else ".//nationality",
            namespace
        )

        if nationality_nodes:
            nationalite = find_text(
                nationality_nodes[0],
                "ns:country" if namespace else "country",
                namespace
            )

        # Date de naissance
        date_naissance = None
        dob_nodes = find_all(
            entry,
            ".//ns:dateOfBirthItem" if namespace else ".//dateOfBirthItem",
            namespace
        )

        if dob_nodes:
            dob_value = find_text(
                dob_nodes[0],
                "ns:dateOfBirth" if namespace else "dateOfBirth",
                namespace
            )
            date_naissance = parse_date(dob_value)

        # Passeport
        num_passeport = None
        id_nodes = find_all(
            entry,
            ".//ns:id" if namespace else ".//id",
            namespace
        )

        for id_node in id_nodes:
            id_type = find_text(id_node, "ns:idType" if namespace else "idType", namespace)
            id_number = find_text(id_node, "ns:idNumber" if namespace else "idNumber", namespace)

            if id_type and "passport" in id_type.lower() and id_number:
                num_passeport = id_number
                break

        hash_signature = generate_hash_signature(
            source_liste="OFAC_SDN",
            nom=nom,
            prenom=prenom,
            date_naissance=date_naissance,
            num_passeport=num_passeport
        )

        normalized_entries.append({
            "source_liste": "OFAC_SDN",
            "type_entite": type_entite,
            "nom": nom.upper() if nom else nom_complet.upper(),
            "prenom": prenom.upper() if prenom else None,
            "nom_complet": nom_complet.upper(),
            "date_naissance": date_naissance,
            "nationalite": nationalite.upper() if nationalite else None,
            "pays": nationalite.upper() if nationalite else None,
            "num_passeport": num_passeport.upper() if num_passeport else None,
            "motif_sanction": motif_sanction,
            "date_inscription": None,
            "date_suppression": date.today(),
            "statut": "ACTIF",
            "hash_signature": hash_signature,
            "aliases": aliases
        })

    return normalized_entries