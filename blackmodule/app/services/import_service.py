import csv
import hashlib
from datetime import datetime, date
from io import StringIO

from sqlalchemy.orm import Session

from app.models import SanctionEntry,SanctionAlias
from app.services.parsers.ofac_sdn_parser import parse_ofac_sdn_xml
from app.services.parsers.un_parser import parse_un_xml
from app.services.parsers.eu_parser import parse_eu_csv, parse_eu_xml
from app.services.parsers.ofsi_parser import parse_ofsi_csv, parse_ofsi_excel
from app.services.parsers.ofac_consolidated_parser import parse_ofac_consolidated_xml
from app.services.parsers.france_gel_parser import parse_france_gel_json, parse_france_gel_xml
from app.services.parsers.uksl_parser import parse_uksl_csv



def safe_text(value, max_length: int):
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    if len(value) > max_length:
        return value[:max_length]

    return value


def normalize_sanction_item_lengths(item: dict) -> dict:
    """
    Protège la base contre les textes trop longs.
    Les longueurs doivent correspondre aux colonnes String(...) du modèle.
    """
    item["source_liste"] = safe_text(item.get("source_liste"), 50)
    item["type_entite"] = safe_text(item.get("type_entite"), 50)

    item["nom"] = safe_text(item.get("nom"), 150)
    item["prenom"] = safe_text(item.get("prenom"), 150)
    item["nom_complet"] = safe_text(item.get("nom_complet"), 255)

    item["nationalite"] = safe_text(item.get("nationalite"), 100)
    item["pays"] = safe_text(item.get("pays"), 100)
    item["num_passeport"] = safe_text(item.get("num_passeport"), 100)

    item["motif_sanction"] = safe_text(item.get("motif_sanction"), 500)
    item["statut"] = safe_text(item.get("statut"), 30)
    item["hash_signature"] = safe_text(item.get("hash_signature"), 255)

    clean_aliases = []

    for alias in item.get("aliases", []):
        alias_value = safe_text(alias, 255)

        if alias_value:
            clean_aliases.append(alias_value)

    item["aliases"] = clean_aliases

    return item

def parse_date(value: str | None) -> date | None:
    if not value:
        return None

    value = value.strip()

    if not value:
        return None

    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def generate_hash_signature(
    source_liste: str,
    nom: str,
    prenom: str | None,
    date_naissance: date | None,
    num_passeport: str | None
) -> str:
    raw_value = f"{source_liste}|{nom}|{prenom}|{date_naissance}|{num_passeport}"
    return hashlib.sha256(raw_value.upper().encode("utf-8")).hexdigest()


def import_afb_ppe_csv(
    db: Session,
    file_content: bytes
) -> dict:
    decoded_content = file_content.decode("utf-8-sig")
    csv_file = StringIO(decoded_content)

    reader = csv.DictReader(csv_file)

    total_records = 0
    inserted_records = 0
    updated_records = 0
    duplicate_records = 0
    rejected_records = 0

    required_columns = [
        "nom",
        "prenom",
        "date_naissance",
        "nationalite",
        "pays",
        "num_passeport",
        "motif_sanction",
        "date_inscription",
        "statut"
    ]

    if not reader.fieldnames:
        raise ValueError("Le fichier CSV est vide ou invalide.")

    missing_columns = [
        col for col in required_columns
        if col not in reader.fieldnames
    ]

    if missing_columns:
        raise ValueError(
            f"Colonnes manquantes dans le CSV : {', '.join(missing_columns)}"
        )

    for row in reader:
        total_records += 1

        nom = row.get("nom", "").strip().upper()
        prenom = row.get("prenom", "").strip().upper()
        date_naissance = parse_date(row.get("date_naissance"))
        nationalite = row.get("nationalite", "").strip().upper()
        pays = row.get("pays", "").strip().upper()
        num_passeport = row.get("num_passeport", "").strip().upper()
        motif_sanction = row.get("motif_sanction", "").strip()
        date_inscription = parse_date(row.get("date_inscription"))
        statut = row.get("statut", "ACTIF").strip().upper() or "ACTIF"

        if not nom:
            rejected_records += 1
            continue

        nom_complet = f"{prenom} {nom}".strip()

        hash_signature = generate_hash_signature(
            source_liste="AFB_PPE",
            nom=nom,
            prenom=prenom,
            date_naissance=date_naissance,
            num_passeport=num_passeport
        )

        existing_entry = db.query(SanctionEntry).filter(
            SanctionEntry.hash_signature == hash_signature
        ).first()

        if existing_entry:
            existing_entry.nom = nom
            existing_entry.prenom = prenom
            existing_entry.nom_complet = nom_complet
            existing_entry.date_naissance = date_naissance
            existing_entry.nationalite = nationalite
            existing_entry.pays = pays
            existing_entry.num_passeport = num_passeport
            existing_entry.motif_sanction = motif_sanction
            existing_entry.date_inscription = date_inscription
            existing_entry.statut = statut

            updated_records += 1
            duplicate_records += 1

        else:
            new_entry = SanctionEntry(
                source_liste="AFB_PPE",
                type_entite="PERSONNE_PHYSIQUE",
                nom=nom,
                prenom=prenom,
                nom_complet=nom_complet,
                date_naissance=date_naissance,
                nationalite=nationalite,
                pays=pays,
                num_passeport=num_passeport,
                motif_sanction=motif_sanction,
                date_inscription=date_inscription,
                statut=statut,
                hash_signature=hash_signature
            )

            db.add(new_entry)
            inserted_records += 1

    return {
        "total_records": total_records,
        "inserted_records": inserted_records,
        "updated_records": updated_records,
        "duplicate_records": duplicate_records,
        "rejected_records": rejected_records
    }

def import_ofac_sdn_xml(
    db: Session,
    file_content: bytes
) -> dict:
    entries = parse_ofac_sdn_xml(file_content)

    total_records = 0
    inserted_records = 0
    updated_records = 0
    duplicate_records = 0
    rejected_records = 0

    for item in entries:
        total_records += 1

        nom = item.get("nom")
        nom_complet = item.get("nom_complet")

        if not nom and not nom_complet:
            rejected_records += 1
            continue

        hash_signature = item.get("hash_signature")

        existing_entry = None

        if hash_signature:
            existing_entry = db.query(SanctionEntry).filter(
                SanctionEntry.hash_signature == hash_signature
            ).first()

        if existing_entry:
            existing_entry.source_liste = item.get("source_liste")
            existing_entry.type_entite = item.get("type_entite")
            existing_entry.nom = item.get("nom")
            existing_entry.prenom = item.get("prenom")
            existing_entry.nom_complet = item.get("nom_complet")
            existing_entry.date_naissance = item.get("date_naissance")
            existing_entry.nationalite = item.get("nationalite")
            existing_entry.pays = item.get("pays")
            existing_entry.num_passeport = item.get("num_passeport")
            existing_entry.motif_sanction = item.get("motif_sanction")
            existing_entry.date_inscription = item.get("date_inscription")
            existing_entry.date_suppression = item.get("date_suppression")
            existing_entry.statut = item.get("statut")

            # Remplacer les anciens alias par ceux du nouveau fichier
            db.query(SanctionAlias).filter(
                SanctionAlias.sanction_entry_id == existing_entry.id
            ).delete()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=existing_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            updated_records += 1
            duplicate_records += 1

        else:
            new_entry = SanctionEntry(
                source_liste=item.get("source_liste"),
                type_entite=item.get("type_entite"),
                nom=item.get("nom"),
                prenom=item.get("prenom"),
                nom_complet=item.get("nom_complet"),
                date_naissance=item.get("date_naissance"),
                nationalite=item.get("nationalite"),
                pays=item.get("pays"),
                num_passeport=item.get("num_passeport"),
                motif_sanction=item.get("motif_sanction"),
                date_inscription=item.get("date_inscription"),
                date_suppression=item.get("date_suppression"),
                statut=item.get("statut"),
                hash_signature=item.get("hash_signature")
            )

            db.add(new_entry)
            db.flush()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=new_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            inserted_records += 1

    return {
        "total_records": total_records,
        "inserted_records": inserted_records,
        "updated_records": updated_records,
        "duplicate_records": duplicate_records,
        "rejected_records": rejected_records
    }

def import_un_xml(
    db: Session,
    file_content: bytes
) -> dict:
    entries = parse_un_xml(file_content)

    total_records = 0
    inserted_records = 0
    updated_records = 0
    duplicate_records = 0
    rejected_records = 0

    for item in entries:
        total_records += 1

        nom = item.get("nom")
        nom_complet = item.get("nom_complet")

        if not nom and not nom_complet:
            rejected_records += 1
            continue

        hash_signature = item.get("hash_signature")

        existing_entry = None

        if hash_signature:
            existing_entry = db.query(SanctionEntry).filter(
                SanctionEntry.hash_signature == hash_signature
            ).first()

        if existing_entry:
            existing_entry.source_liste = item.get("source_liste")
            existing_entry.type_entite = item.get("type_entite")
            existing_entry.nom = item.get("nom")
            existing_entry.prenom = item.get("prenom")
            existing_entry.nom_complet = item.get("nom_complet")
            existing_entry.date_naissance = item.get("date_naissance")
            existing_entry.nationalite = item.get("nationalite")
            existing_entry.pays = item.get("pays")
            existing_entry.num_passeport = item.get("num_passeport")
            existing_entry.motif_sanction = item.get("motif_sanction")
            existing_entry.date_inscription = item.get("date_inscription")
            existing_entry.date_suppression = item.get("date_suppression")
            existing_entry.statut = item.get("statut")

            db.query(SanctionAlias).filter(
                SanctionAlias.sanction_entry_id == existing_entry.id
            ).delete()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=existing_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            updated_records += 1
            duplicate_records += 1

        else:
            new_entry = SanctionEntry(
                source_liste=item.get("source_liste"),
                type_entite=item.get("type_entite"),
                nom=item.get("nom"),
                prenom=item.get("prenom"),
                nom_complet=item.get("nom_complet"),
                date_naissance=item.get("date_naissance"),
                nationalite=item.get("nationalite"),
                pays=item.get("pays"),
                num_passeport=item.get("num_passeport"),
                motif_sanction=item.get("motif_sanction"),
                date_inscription=item.get("date_inscription"),
                date_suppression=item.get("date_suppression"),
                statut=item.get("statut"),
                hash_signature=item.get("hash_signature")
            )

            db.add(new_entry)
            db.flush()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=new_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            inserted_records += 1

    return {
        "total_records": total_records,
        "inserted_records": inserted_records,
        "updated_records": updated_records,
        "duplicate_records": duplicate_records,
        "rejected_records": rejected_records
    }

def import_eu_csv(
    db: Session,
    file_content: bytes
) -> dict:
    entries = parse_eu_csv(file_content)

    total_records = 0
    inserted_records = 0
    updated_records = 0
    duplicate_records = 0
    rejected_records = 0

    for item in entries:
        total_records += 1

        nom = item.get("nom")
        nom_complet = item.get("nom_complet")

        if not nom and not nom_complet:
            rejected_records += 1
            continue

        hash_signature = item.get("hash_signature")

        existing_entry = None

        if hash_signature:
            existing_entry = db.query(SanctionEntry).filter(
                SanctionEntry.hash_signature == hash_signature
            ).first()

        if existing_entry:
            existing_entry.source_liste = item.get("source_liste")
            existing_entry.type_entite = item.get("type_entite")
            existing_entry.nom = item.get("nom")
            existing_entry.prenom = item.get("prenom")
            existing_entry.nom_complet = item.get("nom_complet")
            existing_entry.date_naissance = item.get("date_naissance")
            existing_entry.nationalite = item.get("nationalite")
            existing_entry.pays = item.get("pays")
            existing_entry.num_passeport = item.get("num_passeport")
            existing_entry.motif_sanction = item.get("motif_sanction")
            existing_entry.date_inscription = item.get("date_inscription")
            existing_entry.date_suppression = item.get("date_suppression")
            existing_entry.statut = item.get("statut")

            db.query(SanctionAlias).filter(
                SanctionAlias.sanction_entry_id == existing_entry.id
            ).delete()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=existing_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            updated_records += 1
            duplicate_records += 1

        else:
            new_entry = SanctionEntry(
                source_liste=item.get("source_liste"),
                type_entite=item.get("type_entite"),
                nom=item.get("nom"),
                prenom=item.get("prenom"),
                nom_complet=item.get("nom_complet"),
                date_naissance=item.get("date_naissance"),
                nationalite=item.get("nationalite"),
                pays=item.get("pays"),
                num_passeport=item.get("num_passeport"),
                motif_sanction=item.get("motif_sanction"),
                date_inscription=item.get("date_inscription"),
                date_suppression=item.get("date_suppression"),
                statut=item.get("statut"),
                hash_signature=item.get("hash_signature")
            )

            db.add(new_entry)
            db.flush()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=new_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            inserted_records += 1

    return {
        "total_records": total_records,
        "inserted_records": inserted_records,
        "updated_records": updated_records,
        "duplicate_records": duplicate_records,
        "rejected_records": rejected_records
    }

def import_ofsi_csv(
    db: Session,
    file_content: bytes
) -> dict:
    entries = parse_ofsi_csv(file_content)

    total_records = 0
    inserted_records = 0
    updated_records = 0
    duplicate_records = 0
    rejected_records = 0

    for item in entries:
        total_records += 1

        nom = item.get("nom")
        nom_complet = item.get("nom_complet")

        if not nom and not nom_complet:
            rejected_records += 1
            continue

        hash_signature = item.get("hash_signature")

        existing_entry = None

        if hash_signature:
            existing_entry = db.query(SanctionEntry).filter(
                SanctionEntry.hash_signature == hash_signature
            ).first()

        if existing_entry:
            existing_entry.source_liste = item.get("source_liste")
            existing_entry.type_entite = item.get("type_entite")
            existing_entry.nom = item.get("nom")
            existing_entry.prenom = item.get("prenom")
            existing_entry.nom_complet = item.get("nom_complet")
            existing_entry.date_naissance = item.get("date_naissance")
            existing_entry.nationalite = item.get("nationalite")
            existing_entry.pays = item.get("pays")
            existing_entry.num_passeport = item.get("num_passeport")
            existing_entry.motif_sanction = item.get("motif_sanction")
            existing_entry.date_inscription = item.get("date_inscription")
            existing_entry.date_suppression = item.get("date_suppression")
            existing_entry.statut = item.get("statut")

            db.query(SanctionAlias).filter(
                SanctionAlias.sanction_entry_id == existing_entry.id
            ).delete()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=existing_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            updated_records += 1
            duplicate_records += 1

        else:
            new_entry = SanctionEntry(
                source_liste=item.get("source_liste"),
                type_entite=item.get("type_entite"),
                nom=item.get("nom"),
                prenom=item.get("prenom"),
                nom_complet=item.get("nom_complet"),
                date_naissance=item.get("date_naissance"),
                nationalite=item.get("nationalite"),
                pays=item.get("pays"),
                num_passeport=item.get("num_passeport"),
                motif_sanction=item.get("motif_sanction"),
                date_inscription=item.get("date_inscription"),
                date_suppression=item.get("date_suppression"),
                statut=item.get("statut"),
                hash_signature=item.get("hash_signature")
            )

            db.add(new_entry)
            db.flush()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=new_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            inserted_records += 1

    return {
        "total_records": total_records,
        "inserted_records": inserted_records,
        "updated_records": updated_records,
        "duplicate_records": duplicate_records,
        "rejected_records": rejected_records
    }

def import_ofsi_excel(
    db: Session,
    file_content: bytes
) -> dict:
    entries = parse_ofsi_excel(file_content)

    total_records = 0
    inserted_records = 0
    updated_records = 0
    duplicate_records = 0
    rejected_records = 0

    for item in entries:
        total_records += 1

        nom = item.get("nom")
        nom_complet = item.get("nom_complet")

        if not nom and not nom_complet:
            rejected_records += 1
            continue

        hash_signature = item.get("hash_signature")

        existing_entry = None

        if hash_signature:
            existing_entry = db.query(SanctionEntry).filter(
                SanctionEntry.hash_signature == hash_signature
            ).first()

        if existing_entry:
            existing_entry.source_liste = item.get("source_liste")
            existing_entry.type_entite = item.get("type_entite")
            existing_entry.nom = item.get("nom")
            existing_entry.prenom = item.get("prenom")
            existing_entry.nom_complet = item.get("nom_complet")
            existing_entry.date_naissance = item.get("date_naissance")
            existing_entry.nationalite = item.get("nationalite")
            existing_entry.pays = item.get("pays")
            existing_entry.num_passeport = item.get("num_passeport")
            existing_entry.motif_sanction = item.get("motif_sanction")
            existing_entry.date_inscription = item.get("date_inscription")
            existing_entry.date_suppression = item.get("date_suppression")
            existing_entry.statut = item.get("statut")

            db.query(SanctionAlias).filter(
                SanctionAlias.sanction_entry_id == existing_entry.id
            ).delete()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=existing_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            updated_records += 1
            duplicate_records += 1

        else:
            new_entry = SanctionEntry(
                source_liste=item.get("source_liste"),
                type_entite=item.get("type_entite"),
                nom=item.get("nom"),
                prenom=item.get("prenom"),
                nom_complet=item.get("nom_complet"),
                date_naissance=item.get("date_naissance"),
                nationalite=item.get("nationalite"),
                pays=item.get("pays"),
                num_passeport=item.get("num_passeport"),
                motif_sanction=item.get("motif_sanction"),
                date_inscription=item.get("date_inscription"),
                date_suppression=item.get("date_suppression"),
                statut=item.get("statut"),
                hash_signature=item.get("hash_signature")
            )

            db.add(new_entry)
            db.flush()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=new_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            inserted_records += 1

    return {
        "total_records": total_records,
        "inserted_records": inserted_records,
        "updated_records": updated_records,
        "duplicate_records": duplicate_records,
        "rejected_records": rejected_records
    }

def import_ofac_consolidated_xml(
    db: Session,
    file_content: bytes
) -> dict:
    entries = parse_ofac_consolidated_xml(file_content)

    total_records = 0
    inserted_records = 0
    updated_records = 0
    duplicate_records = 0
    rejected_records = 0

    for item in entries:
        item = normalize_sanction_item_lengths(item)
        total_records += 1

        nom = item.get("nom")
        nom_complet = item.get("nom_complet")

        if not nom and not nom_complet:
            rejected_records += 1
            continue

        hash_signature = item.get("hash_signature")

        existing_entry = None

        if hash_signature:
            existing_entry = db.query(SanctionEntry).filter(
                SanctionEntry.hash_signature == hash_signature
            ).first()

        if existing_entry:
            existing_entry.source_liste = item.get("source_liste")
            existing_entry.type_entite = item.get("type_entite")
            existing_entry.nom = item.get("nom")
            existing_entry.prenom = item.get("prenom")
            existing_entry.nom_complet = item.get("nom_complet")
            existing_entry.date_naissance = item.get("date_naissance")
            existing_entry.nationalite = item.get("nationalite")
            existing_entry.pays = item.get("pays")
            existing_entry.num_passeport = item.get("num_passeport")
            existing_entry.motif_sanction = item.get("motif_sanction")
            existing_entry.date_inscription = item.get("date_inscription")
            existing_entry.date_suppression = item.get("date_suppression")
            existing_entry.statut = item.get("statut")

            db.query(SanctionAlias).filter(
                SanctionAlias.sanction_entry_id == existing_entry.id
            ).delete()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=existing_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            updated_records += 1
            duplicate_records += 1

        else:
            new_entry = SanctionEntry(
                source_liste=item.get("source_liste"),
                type_entite=item.get("type_entite"),
                nom=item.get("nom"),
                prenom=item.get("prenom"),
                nom_complet=item.get("nom_complet"),
                date_naissance=item.get("date_naissance"),
                nationalite=item.get("nationalite"),
                pays=item.get("pays"),
                num_passeport=item.get("num_passeport"),
                motif_sanction=item.get("motif_sanction"),
                date_inscription=item.get("date_inscription"),
                date_suppression=item.get("date_suppression"),
                statut=item.get("statut"),
                hash_signature=item.get("hash_signature")
            )

            db.add(new_entry)
            db.flush()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=new_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            inserted_records += 1

    return {
        "total_records": total_records,
        "inserted_records": inserted_records,
        "updated_records": updated_records,
        "duplicate_records": duplicate_records,
        "rejected_records": rejected_records
    }

import json
import hashlib
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


def import_france_gel_json(
    db: Session,
    file_content: bytes
) -> dict:
    entries = parse_france_gel_json(file_content)

    total_records = 0
    inserted_records = 0
    updated_records = 0
    duplicate_records = 0
    rejected_records = 0

    for item in entries:
        total_records += 1

        nom = item.get("nom")
        nom_complet = item.get("nom_complet")

        if not nom and not nom_complet:
            rejected_records += 1
            continue

        hash_signature = item.get("hash_signature")

        existing_entry = None

        if hash_signature:
            existing_entry = db.query(SanctionEntry).filter(
                SanctionEntry.hash_signature == hash_signature
            ).first()

        if existing_entry:
            existing_entry.source_liste = item.get("source_liste")
            existing_entry.type_entite = item.get("type_entite")
            existing_entry.nom = item.get("nom")
            existing_entry.prenom = item.get("prenom")
            existing_entry.nom_complet = item.get("nom_complet")
            existing_entry.date_naissance = item.get("date_naissance")
            existing_entry.nationalite = item.get("nationalite")
            existing_entry.pays = item.get("pays")
            existing_entry.num_passeport = item.get("num_passeport")
            existing_entry.motif_sanction = item.get("motif_sanction")
            existing_entry.date_inscription = item.get("date_inscription")
            existing_entry.date_suppression = item.get("date_suppression")
            existing_entry.statut = item.get("statut")

            db.query(SanctionAlias).filter(
                SanctionAlias.sanction_entry_id == existing_entry.id
            ).delete()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=existing_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            updated_records += 1
            duplicate_records += 1

        else:
            new_entry = SanctionEntry(
                source_liste=item.get("source_liste"),
                type_entite=item.get("type_entite"),
                nom=item.get("nom"),
                prenom=item.get("prenom"),
                nom_complet=item.get("nom_complet"),
                date_naissance=item.get("date_naissance"),
                nationalite=item.get("nationalite"),
                pays=item.get("pays"),
                num_passeport=item.get("num_passeport"),
                motif_sanction=item.get("motif_sanction"),
                date_inscription=item.get("date_inscription"),
                date_suppression=item.get("date_suppression"),
                statut=item.get("statut"),
                hash_signature=item.get("hash_signature")
            )

            db.add(new_entry)
            db.flush()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=new_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            inserted_records += 1

    return {
        "total_records": total_records,
        "inserted_records": inserted_records,
        "updated_records": updated_records,
        "duplicate_records": duplicate_records,
        "rejected_records": rejected_records
    }

def import_france_gel_xml(
    db: Session,
    file_content: bytes
) -> dict:
    entries = parse_france_gel_xml(file_content)

    total_records = 0
    inserted_records = 0
    updated_records = 0
    duplicate_records = 0
    rejected_records = 0

    for item in entries:
        item = normalize_sanction_item_lengths(item)

        total_records += 1

        nom = item.get("nom")
        nom_complet = item.get("nom_complet")

        if not nom and not nom_complet:
            rejected_records += 1
            continue

        hash_signature = item.get("hash_signature")

        existing_entry = None

        if hash_signature:
            existing_entry = db.query(SanctionEntry).filter(
                SanctionEntry.hash_signature == hash_signature
            ).first()

        if existing_entry:
            existing_entry.source_liste = item.get("source_liste")
            existing_entry.type_entite = item.get("type_entite")
            existing_entry.nom = item.get("nom")
            existing_entry.prenom = item.get("prenom")
            existing_entry.nom_complet = item.get("nom_complet")
            existing_entry.date_naissance = item.get("date_naissance")
            existing_entry.nationalite = item.get("nationalite")
            existing_entry.pays = item.get("pays")
            existing_entry.num_passeport = item.get("num_passeport")
            existing_entry.motif_sanction = item.get("motif_sanction")
            existing_entry.date_inscription = item.get("date_inscription")
            existing_entry.date_suppression = item.get("date_suppression")
            existing_entry.statut = item.get("statut")

            db.query(SanctionAlias).filter(
                SanctionAlias.sanction_entry_id == existing_entry.id
            ).delete()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=existing_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            updated_records += 1
            duplicate_records += 1

        else:
            new_entry = SanctionEntry(
                source_liste=item.get("source_liste"),
                type_entite=item.get("type_entite"),
                nom=item.get("nom"),
                prenom=item.get("prenom"),
                nom_complet=item.get("nom_complet"),
                date_naissance=item.get("date_naissance"),
                nationalite=item.get("nationalite"),
                pays=item.get("pays"),
                num_passeport=item.get("num_passeport"),
                motif_sanction=item.get("motif_sanction"),
                date_inscription=item.get("date_inscription"),
                date_suppression=item.get("date_suppression"),
                statut=item.get("statut"),
                hash_signature=item.get("hash_signature")
            )

            db.add(new_entry)
            db.flush()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=new_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            inserted_records += 1

    return {
        "total_records": total_records,
        "inserted_records": inserted_records,
        "updated_records": updated_records,
        "duplicate_records": duplicate_records,
        "rejected_records": rejected_records
    }

def import_eu_xml(
    db: Session,
    file_content: bytes
) -> dict:
    entries = parse_eu_xml(file_content)

    total_records = 0
    inserted_records = 0
    updated_records = 0
    duplicate_records = 0
    rejected_records = 0

    for item in entries:
        item = normalize_sanction_item_lengths(item)

        total_records += 1

        nom = item.get("nom")
        nom_complet = item.get("nom_complet")

        if not nom and not nom_complet:
            rejected_records += 1
            continue

        hash_signature = item.get("hash_signature")

        existing_entry = None

        if hash_signature:
            existing_entry = db.query(SanctionEntry).filter(
                SanctionEntry.hash_signature == hash_signature
            ).first()

        if existing_entry:
            existing_entry.source_liste = item.get("source_liste")
            existing_entry.type_entite = item.get("type_entite")
            existing_entry.nom = item.get("nom")
            existing_entry.prenom = item.get("prenom")
            existing_entry.nom_complet = item.get("nom_complet")
            existing_entry.date_naissance = item.get("date_naissance")
            existing_entry.nationalite = item.get("nationalite")
            existing_entry.pays = item.get("pays")
            existing_entry.num_passeport = item.get("num_passeport")
            existing_entry.motif_sanction = item.get("motif_sanction")
            existing_entry.date_inscription = item.get("date_inscription")
            existing_entry.date_suppression = item.get("date_suppression")
            existing_entry.statut = item.get("statut")

            db.query(SanctionAlias).filter(
                SanctionAlias.sanction_entry_id == existing_entry.id
            ).delete()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=existing_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            updated_records += 1
            duplicate_records += 1

        else:
            new_entry = SanctionEntry(
                source_liste=item.get("source_liste"),
                type_entite=item.get("type_entite"),
                nom=item.get("nom"),
                prenom=item.get("prenom"),
                nom_complet=item.get("nom_complet"),
                date_naissance=item.get("date_naissance"),
                nationalite=item.get("nationalite"),
                pays=item.get("pays"),
                num_passeport=item.get("num_passeport"),
                motif_sanction=item.get("motif_sanction"),
                date_inscription=item.get("date_inscription"),
                date_suppression=item.get("date_suppression"),
                statut=item.get("statut"),
                hash_signature=item.get("hash_signature")
            )

            db.add(new_entry)
            db.flush()

            for alias_value in item.get("aliases", []):
                if alias_value:
                    db.add(
                        SanctionAlias(
                            sanction_entry_id=new_entry.id,
                            alias=alias_value.upper()
                        )
                    )

            inserted_records += 1

    return {
        "total_records": total_records,
        "inserted_records": inserted_records,
        "updated_records": updated_records,
        "duplicate_records": duplicate_records,
        "rejected_records": rejected_records
    }

def import_uksl_csv(db: Session, file_content: bytes) -> dict:
    """
    Import UK Sanctions List CSV.
    Source normalisée en base : UKSL.

    Correction importante :
    - la UKSL contient plusieurs lignes pour une même entité ;
    - certaines lignes produisent donc le même hash_signature ;
    - on déduplique d'abord en mémoire avant insertion ;
    - on vérifie ensuite la base par hash_signature avant d'ajouter une ligne.
    """

    entries = parse_uksl_csv(file_content)

    total_records = len(entries)
    inserted_records = 0
    updated_records = 0
    duplicate_records = 0
    rejected_records = 0

    unique_items = []
    seen_hashes = set()

    # 1) Déduplication interne du fichier UKSL avant tout db.add()
    for item in entries:
        try:
            item = normalize_sanction_item_lengths(item)

            nom = item.get("nom")
            nom_complet = item.get("nom_complet")
            hash_signature = item.get("hash_signature")

            if not nom and not nom_complet:
                rejected_records += 1
                continue

            if not hash_signature:
                rejected_records += 1
                continue

            if hash_signature in seen_hashes:
                duplicate_records += 1
                continue

            seen_hashes.add(hash_signature)
            unique_items.append(item)

        except Exception as e:
            rejected_records += 1
            print("ERREUR PREPARATION UKSL :", str(e))

    # 2) Chargement des hash déjà présents en base pour éviter les UniqueViolation
    existing_hashes = set()

    if unique_items:
        all_hashes = [
            item.get("hash_signature")
            for item in unique_items
            if item.get("hash_signature")
        ]

        chunk_size = 1000

        for start in range(0, len(all_hashes), chunk_size):
            chunk = all_hashes[start:start + chunk_size]

            rows = db.query(SanctionEntry.hash_signature).filter(
                SanctionEntry.hash_signature.in_(chunk)
            ).all()

            for row in rows:
                existing_hashes.add(row[0])

    # 3) Insertion / mise à jour
    for item in unique_items:
        try:
            hash_signature = item.get("hash_signature")

            existing_entry = None

            if hash_signature in existing_hashes:
                with db.no_autoflush:
                    existing_entry = db.query(SanctionEntry).filter(
                        SanctionEntry.hash_signature == hash_signature
                    ).first()

            if existing_entry:
                existing_entry.source_liste = "UKSL"
                existing_entry.type_entite = item.get("type_entite")
                existing_entry.nom = item.get("nom")
                existing_entry.prenom = item.get("prenom")
                existing_entry.nom_complet = item.get("nom_complet")
                existing_entry.date_naissance = item.get("date_naissance")
                existing_entry.nationalite = item.get("nationalite")
                existing_entry.pays = item.get("pays")
                existing_entry.num_passeport = item.get("num_passeport")
                existing_entry.motif_sanction = item.get("motif_sanction")
                existing_entry.date_inscription = item.get("date_inscription")
                existing_entry.date_suppression = item.get("date_suppression")
                existing_entry.statut = item.get("statut") or "ACTIF"
                existing_entry.hash_signature = hash_signature

                updated_records += 1

            else:
                new_entry = SanctionEntry(
                    source_liste="UKSL",
                    type_entite=item.get("type_entite"),
                    nom=item.get("nom"),
                    prenom=item.get("prenom"),
                    nom_complet=item.get("nom_complet"),
                    date_naissance=item.get("date_naissance"),
                    nationalite=item.get("nationalite"),
                    pays=item.get("pays"),
                    num_passeport=item.get("num_passeport"),
                    motif_sanction=item.get("motif_sanction"),
                    date_inscription=item.get("date_inscription"),
                    date_suppression=item.get("date_suppression"),
                    statut=item.get("statut") or "ACTIF",
                    hash_signature=hash_signature
                )

                db.add(new_entry)
                inserted_records += 1

        except Exception as e:
            rejected_records += 1
            print("ERREUR IMPORT UKSL :", str(e))

    return {
        "total_records": total_records,
        "inserted_records": inserted_records,
        "updated_records": updated_records,
        "duplicate_records": duplicate_records,
        "rejected_records": rejected_records
    }

