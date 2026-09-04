from dotenv import load_dotenv

load_dotenv()

import secrets

from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import text
from starlette.middleware.sessions import SessionMiddleware

from app.config import (
    BLACKMODULE_API_KEY,
    INITIAL_ADMIN_PASSWORD,
    IS_PRODUCTION,
    SECRET_KEY,
    SESSION_HTTPS_ONLY,
)
from app.database import Base, engine, get_db, SessionLocal
from app import models
from app.services.auth_service import create_default_admin
from app.security import (
    CSRFMiddleware,
    ForcedPasswordChangeMiddleware,
    SecurityRateLimitMiddleware,
)
from app.services.session_security_service import SessionActivityMiddleware
from app.services.observability_service import (
    ObservabilityMiddleware,
    configure_structured_logging,
    monitoring_registry,
    record_health,
)

from app.routers import sanctions
from app.routers import matching
from app.routers import alerts
from app.routers import audit_logs
from app.routers import dashboard
from app.routers import imports
from app.routers import web
from app.routers import exports
from app.scheduler import get_scheduler_status, start_scheduler
from app.routers import external_api
from app.routers import internal_lists
from app.routers import notifications

configure_structured_logging()


app = FastAPI(
    title="BLACKMODULE API",
    description="Prototype API REST pour le filtrage des clients blacklistés",
    version="1.0.0",
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)

app.add_middleware(CSRFMiddleware)
app.add_middleware(SessionActivityMiddleware)
app.add_middleware(SecurityRateLimitMiddleware)
app.add_middleware(ForcedPasswordChangeMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    same_site="lax",
    https_only=SESSION_HTTPS_ONLY,
)
app.add_middleware(ObservabilityMiddleware)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

REQUIRED_SCHEMA_REVISION = "p4_0002_security_hardening"


def _verify_managed_schema():
    """Refuse un démarrage de production sur un schéma non migré."""
    with engine.connect() as conn:
        version_table_exists = conn.execute(
            text("SELECT to_regclass('public.alembic_version') IS NOT NULL")
        ).scalar()
        current_revision = None
        if version_table_exists:
            current_revision = conn.execute(
                text("SELECT version_num FROM alembic_version LIMIT 1")
            ).scalar()

    if current_revision != REQUIRED_SCHEMA_REVISION:
        raise RuntimeError(
            "Schéma PostgreSQL non migré pour cette version de BLACKMODULE. "
            "Exécuter 'alembic upgrade head' avant de démarrer l'application."
        )


@app.on_event("startup")
def startup():
    if IS_PRODUCTION:
        _verify_managed_schema()
    else:
        _initialize_local_schema()

    db = SessionLocal()
    try:
        create_default_admin(db, INITIAL_ADMIN_PASSWORD)
    finally:
        db.close()

    start_scheduler()
    record_health("application", True)
    record_health("scheduler", get_scheduler_status()["running"])


def _initialize_local_schema():
    """Compatibilité locale historique ; la production passe par Alembic."""
    Base.metadata.create_all(bind=engine)

    with engine.begin() as conn:
        conn.execute(text("""
            CREATE OR REPLACE FUNCTION prevent_alert_quality_review_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'alert_quality_reviews is append-only';
            END;
            $$ LANGUAGE plpgsql
        """))
        conn.execute(text("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_trigger
                    WHERE tgname = 'trg_alert_quality_review_immutable'
                ) THEN
                    CREATE TRIGGER trg_alert_quality_review_immutable
                    BEFORE UPDATE OR DELETE ON alert_quality_reviews
                    FOR EACH ROW EXECUTE FUNCTION prevent_alert_quality_review_mutation();
                END IF;
            END $$
        """))
        conn.execute(text("""
            CREATE OR REPLACE FUNCTION prevent_corrective_action_history_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'corrective_action_history is append-only';
            END;
            $$ LANGUAGE plpgsql
        """))
        conn.execute(text("""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_corrective_action_history_immutable') THEN
                    CREATE TRIGGER trg_corrective_action_history_immutable
                    BEFORE UPDATE OR DELETE ON corrective_action_history
                    FOR EACH ROW EXECUTE FUNCTION prevent_corrective_action_history_mutation();
                END IF;
            END $$
        """))
        conn.execute(text("""
            CREATE OR REPLACE FUNCTION prevent_user_notification_history_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'user_notification_history is append-only';
            END;
            $$ LANGUAGE plpgsql
        """))
        conn.execute(text("""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_user_notification_history_immutable') THEN
                    CREATE TRIGGER trg_user_notification_history_immutable
                    BEFORE UPDATE OR DELETE ON user_notification_history
                    FOR EACH ROW EXECUTE FUNCTION prevent_user_notification_history_mutation();
                END IF;
            END $$
        """))
        conn.execute(text("""
            CREATE OR REPLACE FUNCTION prevent_external_notification_attempt_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'external_notification_attempts is append-only';
            END;
            $$ LANGUAGE plpgsql
        """))
        conn.execute(text("""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_external_notification_attempt_immutable') THEN
                    CREATE TRIGGER trg_external_notification_attempt_immutable
                    BEFORE UPDATE OR DELETE ON external_notification_attempts
                    FOR EACH ROW EXECUTE FUNCTION prevent_external_notification_attempt_mutation();
                END IF;
            END $$
        """))

        for column_def in [
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
        ]:
            conn.execute(text(f"ALTER TABLE alerts ADD COLUMN IF NOT EXISTS {column_def}"))

        conn.execute(text(
            "ALTER TABLE corrective_actions ADD COLUMN IF NOT EXISTS "
            "supervisor_escalated_at TIMESTAMP"
        ))

        for column_def in [
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
        ]:
            conn.execute(text(f"ALTER TABLE sanction_entries ADD COLUMN IF NOT EXISTS {column_def}"))

        conn.execute(text(
            "ALTER TABLE sanction_entries ALTER COLUMN nationalite TYPE VARCHAR(255)"
        ))

        for column_def in [
            "source_url VARCHAR(1000)",
            "downloaded_at TIMESTAMP",
            "published_at TIMESTAMP",
            "file_size_bytes INTEGER",
            "delisted_records INTEGER DEFAULT 0",
            "reactivated_records INTEGER DEFAULT 0",
        ]:
            conn.execute(text(f"ALTER TABLE import_batches ADD COLUMN IF NOT EXISTS {column_def}"))

        conn.execute(text(
            "ALTER TABLE list_versions ADD COLUMN IF NOT EXISTS "
            "archive_compression VARCHAR(20) NOT NULL DEFAULT 'none'"
        ))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_sanction_source_record "
            "ON sanction_entries (source_liste, source_record_id)"
        ))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_sanction_internal_status "
            "ON sanction_entries (is_internal_list, internal_status)"
        ))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_alerts_client_reference_created_at "
            "ON alerts (client_reference, created_at)"
        ))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_alerts_queue "
            "ON alerts (statut, niveau_alerte, created_at)"
        ))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_alerts_assigned_to_user_id "
            "ON alerts (assigned_to_user_id)"
        ))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_alert_assignment_history_alert_created "
            "ON alert_assignment_history (alert_id, created_at)"
        ))
        conn.execute(text("""
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
        """))

        for column_def in [
            "role_assigned_at TIMESTAMP",
            "last_login_at TIMESTAMP",
            "last_activity_at TIMESTAMP",
            "failed_login_attempts INTEGER NOT NULL DEFAULT 0",
            "locked_at TIMESTAMP",
            "must_change_password BOOLEAN NOT NULL DEFAULT FALSE",
            "password_changed_at TIMESTAMP",
            "bootstrap_credential_expires_at TIMESTAMP",
        ]:
            conn.execute(text(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {column_def}"))

        conn.execute(text("""
            UPDATE users
            SET role = CASE role
                WHEN 'ADMIN' THEN 'ADMIN_TECHNIQUE'
                WHEN 'SUPERVISEUR' THEN 'SUPERVISEUR_CONFORMITE'
                WHEN 'OPERATEUR' THEN 'ANALYSTE_CONFORMITE'
                WHEN 'LECTEUR' THEN 'CONSULTATION'
                ELSE role
            END
            WHERE role IN ('ADMIN', 'SUPERVISEUR', 'OPERATEUR', 'LECTEUR')
        """))
        conn.execute(text("""
            UPDATE users
            SET role = 'CONSULTATION'
            WHERE role IS NULL OR role NOT IN (
                'ADMIN_TECHNIQUE', 'SUPERVISEUR_CONFORMITE',
                'ANALYSTE_CONFORMITE', 'GESTIONNAIRE_LISTES',
                'CONSULTATION', 'AUDITEUR'
            )
        """))
        conn.execute(text("""
            UPDATE users
            SET role_assigned_at = COALESCE(role_assigned_at, created_at, NOW())
            WHERE role_assigned_at IS NULL
        """))

app.include_router(sanctions.router)
app.include_router(matching.router)
app.include_router(alerts.router)
app.include_router(audit_logs.router)
app.include_router(dashboard.router)
app.include_router(imports.router)
app.include_router(web.router)
app.include_router(exports.router)
app.include_router(external_api.router)
app.include_router(internal_lists.router)
app.include_router(notifications.router)

@app.get("/")
def home():
    return {
        "message": "BLACKMODULE API is running",
        "status": "OK"
    }


@app.get("/health/live")
def health_live():
    record_health("application", True)
    return {"status": "OK"}


@app.get("/health/ready")
def health_ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1")).scalar()
    except Exception:
        record_health("database", False)
        raise HTTPException(status_code=503, detail="Database unavailable")
    record_health("database", True)
    record_health("scheduler", get_scheduler_status()["running"])
    return {"status": "OK", "database": "ready"}


@app.get("/health/metrics")
def health_metrics(x_api_key: str | None = Header(None)):
    """Expose non-sensitive process metrics for an authorized local collector."""
    if IS_PRODUCTION and not (
        isinstance(x_api_key, str)
        and secrets.compare_digest(x_api_key.strip(), BLACKMODULE_API_KEY.strip())
    ):
        raise HTTPException(status_code=403, detail="Monitoring access denied")
    scheduler_status = get_scheduler_status()
    record_health("scheduler", scheduler_status["running"])
    result = monitoring_registry.snapshot()
    result["scheduler"] = {
        "running": scheduler_status["running"],
        "jobs_count": len(scheduler_status["jobs"]),
    }
    return result


@app.get("/db-check")
def db_check(db: Session = Depends(get_db)):
    if IS_PRODUCTION:
        raise HTTPException(status_code=404, detail="Not found")
    try:
        result = db.execute(text("SELECT 1")).scalar()

        return {
            "database": "PostgreSQL",
            "connection": "SUCCESS",
            "test_result": result,
            "message": "FastAPI est bien connecté à PostgreSQL"
        }

    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable")
