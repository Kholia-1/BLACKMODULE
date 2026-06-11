import uuid
from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    Text,
    Date,
    DateTime,
    Integer,
    Numeric,
    ForeignKey,
    Float
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class SanctionEntry(Base):
    __tablename__ = "sanction_entries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    source_liste = Column(String(50), nullable=False)
    type_entite = Column(String(50), nullable=False)

    nom = Column(String(255), nullable=False)
    prenom = Column(String(255), nullable=True)
    nom_complet = Column(String(500), nullable=True)

    date_naissance = Column(Date, nullable=True)
    nationalite = Column(String(100), nullable=True)
    pays = Column(String(100), nullable=True)

    num_passeport = Column(String(100), nullable=True)
    motif_sanction = Column(Text, nullable=True)

    date_inscription = Column(Date, nullable=True)
    date_suppression = Column(Date, nullable=True)

    statut = Column(String(30), default="ACTIF")
    hash_signature = Column(String(64), unique=True, nullable=True)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    aliases = relationship(
        "SanctionAlias",
        back_populates="sanction_entry",
        cascade="all, delete-orphan"
    )


class SanctionAlias(Base):
    __tablename__ = "sanction_aliases"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    sanction_entry_id = Column(
        UUID(as_uuid=True),
        ForeignKey("sanction_entries.id", ondelete="CASCADE"),
        nullable=False
    )

    alias = Column(String(500), nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    sanction_entry = relationship(
        "SanctionEntry",
        back_populates="aliases"
    )


class ImportBatch(Base):
    __tablename__ = "import_batches"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    source_liste = Column(String(50), nullable=False)
    filename = Column(String(255), nullable=True)
    file_type = Column(String(20), nullable=True)

    total_records = Column(Integer, default=0)
    inserted_records = Column(Integer, default=0)
    updated_records = Column(Integer, default=0)
    duplicate_records = Column(Integer, default=0)
    rejected_records = Column(Integer, default=0)

    status = Column(String(30), default="PENDING")
    error_message = Column(Text, nullable=True)

    imported_by = Column(String(100), nullable=True)
    imported_at = Column(DateTime, server_default=func.now())
    
    file_hash = Column(String(128), nullable=True)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    client_reference = Column(String(100), nullable=True)
    client_nom = Column(String(255), nullable=True)
    client_prenom = Column(String(255), nullable=True)
    client_date_naissance = Column(Date, nullable=True)

    sanction_entry_id = Column(
        UUID(as_uuid=True),
        ForeignKey("sanction_entries.id"),
        nullable=True
    )

    source_liste = Column(String(50), nullable=True)
    matching_score = Column(Numeric(5, 2), nullable=True)
    matching_type = Column(String(50), nullable=True)

    niveau_alerte = Column(String(50), nullable=True)
    statut = Column(String(50), default="GENEREE")

    action_recommandee = Column(String(255), nullable=True)

    created_at = Column(DateTime, server_default=func.now())
    treated_at = Column(DateTime, nullable=True)
    treated_by = Column(String(100), nullable=True)
    treatment_comment = Column(Text, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    user_identifier = Column(String(100), nullable=True)
    action = Column(String(100), nullable=False)
    entity_type = Column(String(100), nullable=True)
    entity_id = Column(String(100), nullable=True)

    description = Column(Text, nullable=True)
    ip_address = Column(String(100), nullable=True)

    created_at = Column(DateTime, server_default=func.now())


class MatchingSetting(Base):
    __tablename__ = "matching_settings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    exact_threshold = Column(Float, nullable=False, default=90.0)
    probable_threshold = Column(Float, nullable=False, default=75.0)
    possible_threshold = Column(Float, nullable=False, default=60.0)

    updated_by = Column(String(100), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    username = Column(String(100), unique=True, nullable=False, index=True)
    full_name = Column(String(150), nullable=True)
    email = Column(String(150), unique=True, nullable=True)

    password_hash = Column(String(255), nullable=False)

    role = Column(String(30), nullable=False, default="LECTEUR")
    statut = Column(String(20), nullable=False, default="ACTIF")

    created_at = Column(DateTime, default=datetime.utcnow)