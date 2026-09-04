"""Ajoute l'état de sécurité des identifiants bootstrap.

Revision ID: p4_0002_security_hardening
Revises: p3_0001_current_schema
"""

from alembic import op
import sqlalchemy as sa


revision = "p4_0002_security_hardening"
down_revision = "p3_0001_current_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    for definition in (
        "must_change_password BOOLEAN NOT NULL DEFAULT FALSE",
        "password_changed_at TIMESTAMP",
        "bootstrap_credential_expires_at TIMESTAMP",
    ):
        bind.execute(sa.text(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {definition}"))

    # Le compte `admin` est le compte bootstrap historique de BLACKMODULE.
    # Il doit remplacer son secret dans les 24 heures suivant cette migration.
    bind.execute(
        sa.text(
            """
            UPDATE users
            SET must_change_password = TRUE,
                bootstrap_credential_expires_at = COALESCE(
                    bootstrap_credential_expires_at,
                    NOW() + INTERVAL '24 hours'
                )
            WHERE username = 'admin'
              AND password_changed_at IS NULL
            """
        )
    )


def downgrade() -> None:
    # Les colonnes sont conservées afin de ne perdre ni l'état de sécurité ni
    # la date de changement de mot de passe. Alembic retire seulement la
    # révision, ce qui permet une réapplication idempotente.
    pass
