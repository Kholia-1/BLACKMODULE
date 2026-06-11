from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from uuid import UUID

from app.services.audit_service import write_audit_log
from app.database import get_db
from app.models import SanctionEntry
from app.schemas import SanctionEntryCreate, SanctionEntryResponse


router = APIRouter(
    prefix="/api/sanctions",
    tags=["Sanctions"]
)


@router.get("/", response_model=list[SanctionEntryResponse])
def list_sanctions(db: Session = Depends(get_db)):
    sanctions = db.query(SanctionEntry).order_by(SanctionEntry.created_at.desc()).all()
    return sanctions


@router.post("/", response_model=SanctionEntryResponse)
def create_sanction(
    sanction: SanctionEntryCreate,
    db: Session = Depends(get_db)
):
    nom_complet = sanction.nom_complet

    if not nom_complet:
        parts = [sanction.prenom, sanction.nom]
        nom_complet = " ".join([p for p in parts if p])

    new_sanction = SanctionEntry(
        source_liste=sanction.source_liste,
        type_entite=sanction.type_entite,
        nom=sanction.nom.upper(),
        prenom=sanction.prenom.upper() if sanction.prenom else None,
        nom_complet=nom_complet.upper() if nom_complet else None,
        date_naissance=sanction.date_naissance,
        nationalite=sanction.nationalite,
        pays=sanction.pays,
        num_passeport=sanction.num_passeport,
        motif_sanction=sanction.motif_sanction,
        date_inscription=sanction.date_inscription,
        statut=sanction.statut
    )

    db.add(new_sanction)
    db.flush()

    write_audit_log(
        db=db,
        user_identifier="SYSTEM",
        action="CREATION_SANCTION",
        entity_type="SanctionEntry",
        entity_id=str(new_sanction.id),
        description=(
            f"Création d'une entrée de sanction : "
            f"{new_sanction.nom_complet} | Source : {new_sanction.source_liste}"
        ),
        ip_address=None
    )

    db.commit()
    db.refresh(new_sanction)

    return new_sanction


@router.get("/{sanction_id}", response_model=SanctionEntryResponse)
def get_sanction(
    sanction_id: UUID,
    db: Session = Depends(get_db)
):
    sanction = db.query(SanctionEntry).filter(
        SanctionEntry.id == sanction_id
    ).first()

    if not sanction:
        raise HTTPException(
            status_code=404,
            detail="Entrée de sanction introuvable"
        )

    return sanction