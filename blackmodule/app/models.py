import uuid
from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    Text,
    Date,
    DateTime,
    Integer,
    Boolean,
    Numeric,
    ForeignKey,
    Float,
    LargeBinary,
    UniqueConstraint,
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
    lieu_naissance = Column(String(255), nullable=True)
    nationalite = Column(String(255), nullable=True)
    pays = Column(String(100), nullable=True)

    num_passeport = Column(String(100), nullable=True)
    autres_documents = Column(Text, nullable=True)
    motif_sanction = Column(Text, nullable=True)

    date_inscription = Column(Date, nullable=True)
    date_suppression = Column(Date, nullable=True)

    statut = Column(String(30), default="ACTIF")
    hash_signature = Column(String(64), unique=True, nullable=True)
    source_record_id = Column(String(255), nullable=True, index=True)
    delisted_at = Column(DateTime, nullable=True)
    delisted_by_version_id = Column(UUID(as_uuid=True), nullable=True)

    # LOT 2C: optional fields for internal records; official imports remain unchanged.
    is_internal_list = Column(Boolean, nullable=False, default=False, server_default="false")
    internal_status = Column(String(30), nullable=True, index=True)
    risk_level = Column(String(30), nullable=True)
    document_type = Column(String(100), nullable=True)
    document_number = Column(String(150), nullable=True)
    source_reference = Column(String(500), nullable=True)
    compliance_comment = Column(Text, nullable=True)
    created_by = Column(String(100), nullable=True)
    updated_by = Column(String(100), nullable=True)
    submitted_by = Column(String(100), nullable=True)
    submitted_at = Column(DateTime, nullable=True)
    validated_by = Column(String(100), nullable=True)
    validated_at = Column(DateTime, nullable=True)
    ppe_type = Column(String(100), nullable=True)
    ppe_function = Column(String(255), nullable=True)
    ppe_institution = Column(String(255), nullable=True)
    ppe_country = Column(String(100), nullable=True)
    ppe_function_start_date = Column(Date, nullable=True)
    ppe_function_end_date = Column(Date, nullable=True)
    ppe_status = Column(String(30), nullable=True)
    ppe_relationship = Column(String(255), nullable=True)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    aliases = relationship(
        "SanctionAlias",
        back_populates="sanction_entry",
        cascade="all, delete-orphan"
    )
    internal_history = relationship(
        "InternalListHistory", back_populates="sanction_entry",
        cascade="all, delete-orphan", order_by="InternalListHistory.created_at",
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


class InternalListHistory(Base):
    """Trace métier des changements internes, sans copier les données dans les logs."""

    __tablename__ = "internal_list_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sanction_entry_id = Column(
        UUID(as_uuid=True), ForeignKey("sanction_entries.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    action = Column(String(50), nullable=False)
    performed_by = Column(String(100), nullable=True)
    old_values = Column(Text, nullable=True)
    new_values = Column(Text, nullable=True)
    comment = Column(Text, nullable=True)
    approval_request_id = Column(UUID(as_uuid=True), ForeignKey("approval_requests.id"), nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    sanction_entry = relationship("SanctionEntry", back_populates="internal_history")


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
    source_url = Column(String(1000), nullable=True)
    downloaded_at = Column(DateTime, nullable=True)
    published_at = Column(DateTime, nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    delisted_records = Column(Integer, default=0)
    reactivated_records = Column(Integer, default=0)


class ListVersion(Base):
    """Persistent, content-addressed snapshot of one official source version."""

    __tablename__ = "list_versions"
    __table_args__ = (
        UniqueConstraint("source_liste", "file_hash", name="uq_list_versions_source_hash"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_liste = Column(String(50), nullable=False, index=True)
    technical_version = Column(String(100), nullable=False)
    import_batch_id = Column(UUID(as_uuid=True), ForeignKey("import_batches.id"), nullable=True)
    source_url = Column(String(1000), nullable=True)
    downloaded_at = Column(DateTime, nullable=True)
    published_at = Column(DateTime, nullable=True)
    file_hash = Column(String(128), nullable=False)
    archive_content = Column(LargeBinary, nullable=False)
    archive_compression = Column(String(20), nullable=False, default="gzip")
    total_entries = Column(Integer, default=0, nullable=False)
    active_entries = Column(Integer, default=0, nullable=False)
    added_entries = Column(Integer, default=0, nullable=False)
    modified_entries = Column(Integer, default=0, nullable=False)
    delisted_entries = Column(Integer, default=0, nullable=False)
    reactivated_entries = Column(Integer, default=0, nullable=False)
    status = Column(String(30), default="ACTIVE", nullable=False)
    created_at = Column(DateTime, server_default=func.now())


class ListVersionActivation(Base):
    """Immutable activation trail for imports and approved restorations."""

    __tablename__ = "list_version_activations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_liste = Column(String(50), nullable=False, index=True)
    version_id = Column(UUID(as_uuid=True), ForeignKey("list_versions.id"), nullable=False, index=True)
    previous_version_id = Column(UUID(as_uuid=True), ForeignKey("list_versions.id"), nullable=True)
    activation_type = Column(String(30), nullable=False)
    reason = Column(Text, nullable=True)
    activated_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class ListVersionEntry(Base):
    """Immutable entry snapshot and change classification for a list version."""

    __tablename__ = "list_version_entries"
    __table_args__ = (
        UniqueConstraint("list_version_id", "sanction_entry_id", name="uq_list_version_entry"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    list_version_id = Column(UUID(as_uuid=True), ForeignKey("list_versions.id"), nullable=False, index=True)
    sanction_entry_id = Column(UUID(as_uuid=True), ForeignKey("sanction_entries.id"), nullable=False, index=True)
    source_record_id = Column(String(255), nullable=False)
    change_type = Column(String(30), nullable=False)
    entry_snapshot = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    client_reference = Column(String(100), nullable=True)
    client_nom = Column(String(255), nullable=True)
    client_prenom = Column(String(255), nullable=True)
    client_date_naissance = Column(Date, nullable=True)
    client_nationalite = Column(String(100), nullable=True)
    client_pays_residence = Column(String(100), nullable=True)
    client_ville_residence = Column(String(150), nullable=True)
    client_type_piece = Column(String(50), nullable=True)
    client_num_piece = Column(String(100), nullable=True)
    client_num_passeport = Column(String(100), nullable=True)

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


class AlertDecisionHistory(Base):
    """Traçabilité métier d'une décision sans modifier l'alerte historique."""

    __tablename__ = "alert_decision_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=False, index=True)
    approval_request_id = Column(
        UUID(as_uuid=True), ForeignKey("approval_requests.id"), nullable=True,
        unique=True, index=True,
    )
    old_status = Column(String(50), nullable=True)
    requested_status = Column(String(50), nullable=False)
    decision_status = Column(String(30), nullable=False)
    initiated_by = Column(String(100), nullable=False)
    initiated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    reason = Column(Text, nullable=True)
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    reviewer_comment = Column(Text, nullable=True)
    applied_at = Column(DateTime, nullable=True)


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

    role = Column(String(50), nullable=False, default="CONSULTATION")
    statut = Column(String(20), nullable=False, default="ACTIF")

    created_at = Column(DateTime, default=datetime.utcnow)
    role_assigned_at = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    last_activity_at = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_at = Column(DateTime, nullable=True)


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    operation_type = Column(String(100), nullable=False)
    status = Column(String(30), nullable=False, default="EN_ATTENTE_VALIDATION")

    initiator_user_id = Column(String(100), nullable=True)
    initiated_by = Column(String(100), nullable=False)
    reviewer_user_id = Column(String(100), nullable=True)
    reviewed_by = Column(String(100), nullable=True)

    target_entity_type = Column(String(100), nullable=False)
    target_entity_id = Column(String(100), nullable=False)
    old_values = Column(Text, nullable=True)
    new_values = Column(Text, nullable=True)
    initiator_comment = Column(Text, nullable=True)
    reviewer_comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    reviewed_at = Column(DateTime, nullable=True)
