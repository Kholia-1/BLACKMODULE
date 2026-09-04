"""Adopte et reproduit le schéma BLACKMODULE courant sans perte de données.

Revision ID: p3_0001_current_schema
Revises: None
"""

from alembic import op
import sqlalchemy as sa


revision = "p3_0001_current_schema"
down_revision = None
branch_labels = None
depends_on = None


def _execute(sql: str) -> None:
    op.get_bind().execute(sa.text(sql))


def _add_columns(table: str, definitions: list[str]) -> None:
    for definition in definitions:
        _execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {definition}")


def upgrade() -> None:
    # Une base neuve est créée depuis les modèles courants. Sur une base
    # existante, create_all est non destructif et les adaptations historiques
    # idempotentes ci-dessous complètent les tables déjà présentes.
    from app import models  # noqa: F401
    from app.database import Base

    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)

    _add_columns(
        "alerts",
        [
            "client_nationalite VARCHAR(100)",
            "client_pays_residence VARCHAR(100)",
            "client_ville_residence VARCHAR(150)",
            "client_type_piece VARCHAR(50)",
            "client_num_piece VARCHAR(100)",
            "client_num_passeport VARCHAR(100)",
            "assigned_to_user_id UUID",
            "assigned_to VARCHAR(100)",
            "assigned_at TIMESTAMP",
            "supervisor_escalated_at TIMESTAMP",
            "supervisor_escalated_by VARCHAR(100)",
        ],
    )
    _add_columns(
        "corrective_actions",
        ["supervisor_escalated_at TIMESTAMP"],
    )
    _add_columns(
        "sanction_entries",
        [
            "lieu_naissance VARCHAR(255)",
            "autres_documents TEXT",
            "source_record_id VARCHAR(255)",
            "delisted_at TIMESTAMP",
            "delisted_by_version_id UUID",
            "is_internal_list BOOLEAN NOT NULL DEFAULT FALSE",
            "internal_status VARCHAR(30)",
            "risk_level VARCHAR(30)",
            "document_type VARCHAR(100)",
            "document_number VARCHAR(150)",
            "source_reference VARCHAR(500)",
            "compliance_comment TEXT",
            "created_by VARCHAR(100)",
            "updated_by VARCHAR(100)",
            "submitted_by VARCHAR(100)",
            "submitted_at TIMESTAMP",
            "validated_by VARCHAR(100)",
            "validated_at TIMESTAMP",
            "ppe_type VARCHAR(100)",
            "ppe_function VARCHAR(255)",
            "ppe_institution VARCHAR(255)",
            "ppe_country VARCHAR(100)",
            "ppe_function_start_date DATE",
            "ppe_function_end_date DATE",
            "ppe_status VARCHAR(30)",
            "ppe_relationship VARCHAR(255)",
        ],
    )
    _execute("ALTER TABLE sanction_entries ALTER COLUMN nationalite TYPE VARCHAR(255)")
    _add_columns(
        "import_batches",
        [
            "source_url VARCHAR(1000)",
            "downloaded_at TIMESTAMP",
            "published_at TIMESTAMP",
            "file_size_bytes INTEGER",
            "delisted_records INTEGER DEFAULT 0",
            "reactivated_records INTEGER DEFAULT 0",
        ],
    )
    _add_columns(
        "list_versions",
        ["archive_compression VARCHAR(20) NOT NULL DEFAULT 'none'"],
    )
    _add_columns(
        "users",
        [
            "role_assigned_at TIMESTAMP",
            "last_login_at TIMESTAMP",
            "last_activity_at TIMESTAMP",
            "failed_login_attempts INTEGER NOT NULL DEFAULT 0",
            "locked_at TIMESTAMP",
        ],
    )
    # Élargissement non destructif : le modèle courant autorise 50 caractères.
    _execute("ALTER TABLE users ALTER COLUMN role TYPE VARCHAR(50)")

    for statement in [
        "CREATE INDEX IF NOT EXISTS ix_sanction_source_record ON sanction_entries (source_liste, source_record_id)",
        "CREATE INDEX IF NOT EXISTS ix_sanction_internal_status ON sanction_entries (is_internal_list, internal_status)",
        "CREATE INDEX IF NOT EXISTS ix_alerts_client_reference_created_at ON alerts (client_reference, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_alerts_queue ON alerts (statut, niveau_alerte, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_alerts_assigned_to_user_id ON alerts (assigned_to_user_id)",
        "CREATE INDEX IF NOT EXISTS ix_alert_assignment_history_alert_created ON alert_assignment_history (alert_id, created_at)",
    ]:
        _execute(statement)

    _execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conrelid = 'alerts'::regclass
                  AND contype = 'f'
                  AND pg_get_constraintdef(oid) LIKE 'FOREIGN KEY (assigned_to_user_id)%'
            ) THEN
                ALTER TABLE alerts
                ADD CONSTRAINT fk_alerts_assigned_to_user_id
                FOREIGN KEY (assigned_to_user_id) REFERENCES users(id) ON DELETE SET NULL;
            END IF;
        END $$
        """
    )

    _execute(
        """
        UPDATE users
        SET role = CASE role
            WHEN 'ADMIN' THEN 'ADMIN_TECHNIQUE'
            WHEN 'SUPERVISEUR' THEN 'SUPERVISEUR_CONFORMITE'
            WHEN 'OPERATEUR' THEN 'ANALYSTE_CONFORMITE'
            WHEN 'LECTEUR' THEN 'CONSULTATION'
            ELSE role
        END
        WHERE role IN ('ADMIN', 'SUPERVISEUR', 'OPERATEUR', 'LECTEUR')
        """
    )
    _execute(
        """
        UPDATE users SET role = 'CONSULTATION'
        WHERE role IS NULL OR role NOT IN (
            'ADMIN_TECHNIQUE', 'SUPERVISEUR_CONFORMITE',
            'ANALYSTE_CONFORMITE', 'GESTIONNAIRE_LISTES',
            'CONSULTATION', 'AUDITEUR'
        )
        """
    )
    _execute(
        """
        UPDATE users
        SET role_assigned_at = COALESCE(role_assigned_at, created_at, NOW())
        WHERE role_assigned_at IS NULL
        """
    )

    for function_name, table_name, trigger_name in [
        (
            "prevent_alert_quality_review_mutation",
            "alert_quality_reviews",
            "trg_alert_quality_review_immutable",
        ),
        (
            "prevent_corrective_action_history_mutation",
            "corrective_action_history",
            "trg_corrective_action_history_immutable",
        ),
        (
            "prevent_user_notification_history_mutation",
            "user_notification_history",
            "trg_user_notification_history_immutable",
        ),
        (
            "prevent_external_notification_attempt_mutation",
            "external_notification_attempts",
            "trg_external_notification_attempt_immutable",
        ),
    ]:
        _execute(
            f"""
            CREATE OR REPLACE FUNCTION {function_name}()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION '{table_name} is append-only';
            END;
            $$ LANGUAGE plpgsql
            """
        )
        _execute(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = '{trigger_name}') THEN
                    CREATE TRIGGER {trigger_name}
                    BEFORE UPDATE OR DELETE ON {table_name}
                    FOR EACH ROW EXECUTE FUNCTION {function_name}();
                END IF;
            END $$
            """
        )

    # Réinstalle aussi les index déclarés dans les modèles quand la table
    # préexistait avant leur ajout (create_all ne les ajoute alors pas).
    for table in Base.metadata.sorted_tables:
        for index in table.indexes:
            index.create(bind=bind, checkfirst=True)

    # Extensions et index LOT 0A/2C : ils sont désormais provisionnés par une
    # opération d'administration Alembic, jamais par le démarrage applicatif.
    _execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    _execute("CREATE EXTENSION IF NOT EXISTS unaccent")
    for statement in [
        "CREATE INDEX IF NOT EXISTS idx_sanction_entries_source_statut_created ON sanction_entries (source_liste, statut, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_sanction_entries_statut_created ON sanction_entries (statut, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_sanction_entries_birth_date ON sanction_entries (date_naissance) WHERE date_naissance IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_sanction_entries_passport_upper ON sanction_entries (upper(num_passeport)) WHERE num_passeport IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_internal_source_reference_upper ON sanction_entries (source_liste, upper(source_reference)) WHERE is_internal_list AND source_reference IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_internal_document_number_upper ON sanction_entries (upper(document_number)) WHERE is_internal_list AND document_number IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_internal_name_birth_date ON sanction_entries (upper(nom), date_naissance) WHERE is_internal_list AND date_naissance IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_sanction_entries_nom_trgm ON sanction_entries USING gin (nom gin_trgm_ops)",
        "CREATE INDEX IF NOT EXISTS idx_sanction_entries_prenom_trgm ON sanction_entries USING gin (prenom gin_trgm_ops)",
        "CREATE INDEX IF NOT EXISTS idx_sanction_entries_nom_complet_trgm ON sanction_entries USING gin (nom_complet gin_trgm_ops)",
        "CREATE INDEX IF NOT EXISTS idx_sanction_aliases_alias_trgm ON sanction_aliases USING gin (alias gin_trgm_ops)",
        "CREATE INDEX IF NOT EXISTS idx_sanction_aliases_entry_id ON sanction_aliases (sanction_entry_id)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_client_sanction_type_status ON alerts (client_reference, sanction_entry_id, matching_type, statut)",
    ]:
        _execute(statement)


def downgrade() -> None:
    # Migration d'adoption d'un schéma contenant des données : revenir à base
    # retire uniquement le marquage Alembic. Le schéma, les index, les triggers
    # et les données restent volontairement intacts.
    pass
