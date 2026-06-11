from datetime import date, datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class SanctionEntryCreate(BaseModel):
    source_liste: str
    type_entite: str
    nom: str
    prenom: Optional[str] = None
    nom_complet: Optional[str] = None
    date_naissance: Optional[date] = None
    nationalite: Optional[str] = None
    pays: Optional[str] = None
    num_passeport: Optional[str] = None
    motif_sanction: Optional[str] = None
    date_inscription: Optional[date] = None
    statut: Optional[str] = "ACTIF"


class SanctionEntryResponse(BaseModel):
    id: UUID
    source_liste: str
    type_entite: str
    nom: str
    prenom: Optional[str] = None
    nom_complet: Optional[str] = None
    date_naissance: Optional[date] = None
    nationalite: Optional[str] = None
    pays: Optional[str] = None
    num_passeport: Optional[str] = None
    motif_sanction: Optional[str] = None
    statut: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class ClientCheckRequest(BaseModel):
    client_reference: Optional[str] = None
    nom: str
    prenom: Optional[str] = None
    date_naissance: Optional[date] = None
    nationalite: Optional[str] = None
    num_passeport: Optional[str] = None


class MatchResult(BaseModel):
    sanction_id: UUID
    source_liste: str
    listed_name: Optional[str] = None
    score: float
    matching_type: str
    niveau_alerte: str
    action_recommandee: str


class ClientCheckResponse(BaseModel):
    client_reference: Optional[str] = None
    client_name: str
    status: str
    highest_score: float
    action: str
    matches: list[MatchResult]

class AlertResponse(BaseModel):
    id: UUID

    client_reference: Optional[str] = None
    client_nom: Optional[str] = None
    client_prenom: Optional[str] = None
    client_date_naissance: Optional[date] = None

    sanction_entry_id: Optional[UUID] = None
    source_liste: Optional[str] = None

    matching_score: Optional[float] = None
    matching_type: Optional[str] = None

    niveau_alerte: Optional[str] = None
    statut: Optional[str] = None

    action_recommandee: Optional[str] = None

    created_at: Optional[datetime] = None
    treated_at: Optional[datetime] = None
    treated_by: Optional[str] = None
    treatment_comment: Optional[str] = None

    class Config:
        from_attributes = True

class AlertTreatmentRequest(BaseModel):
    statut: str
    treated_by: str
    treatment_comment: Optional[str] = None

class AuditLogResponse(BaseModel):
    id: UUID

    user_identifier: Optional[str] = None
    action: str
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    description: Optional[str] = None
    ip_address: Optional[str] = None

    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class DashboardStatsResponse(BaseModel):
    total_sanctions: int
    active_sanctions: int

    total_alerts: int
    alerts_generee: int
    alerts_en_cours: int
    alerts_confirmee: int
    alerts_faux_positif: int
    alerts_escaladee: int
    alerts_cloturee: int

    alertes_exactes: int
    alertes_probables: int
    alertes_possibles: int

    total_audit_logs: int



class ImportBatchResponse(BaseModel):
    id: UUID

    source_liste: str
    filename: Optional[str] = None
    file_type: Optional[str] = None

    total_records: int
    inserted_records: int
    updated_records: int
    duplicate_records: int
    rejected_records: int

    status: str
    error_message: Optional[str] = None

    imported_by: Optional[str] = None
    imported_at: Optional[datetime] = None

    class Config:
        from_attributes = True