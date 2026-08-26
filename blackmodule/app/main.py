from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import text
from starlette.middleware.sessions import SessionMiddleware

from app.config import INITIAL_ADMIN_PASSWORD, SECRET_KEY, SESSION_HTTPS_ONLY
from app.database import Base, engine, get_db, SessionLocal
from app import models
from app.services.auth_service import create_default_admin
from app.security import CSRFMiddleware
from app.services.session_security_service import SessionActivityMiddleware

from app.routers import sanctions
from app.routers import matching
from app.routers import alerts
from app.routers import audit_logs
from app.routers import dashboard
from app.routers import imports
from app.routers import web
from app.routers import exports
from app.scheduler import start_scheduler
from app.routers import external_api

app = FastAPI(
    title="BLACKMODULE API",
    description="Prototype API REST pour le filtrage des clients blacklistés",
    version="1.0.0"
)

app.add_middleware(CSRFMiddleware)
app.add_middleware(SessionActivityMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    same_site="lax",
    https_only=SESSION_HTTPS_ONLY,
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

    with engine.begin() as conn:
        for column_def in [
            "client_nationalite VARCHAR(100)",
            "client_pays_residence VARCHAR(100)",
            "client_ville_residence VARCHAR(150)",
            "client_type_piece VARCHAR(50)",
            "client_num_piece VARCHAR(100)",
            "client_num_passeport VARCHAR(100)",
        ]:
            conn.execute(text(f"ALTER TABLE alerts ADD COLUMN IF NOT EXISTS {column_def}"))

        for column_def in [
            "lieu_naissance VARCHAR(255)",
            "autres_documents TEXT",
        ]:
            conn.execute(text(f"ALTER TABLE sanction_entries ADD COLUMN IF NOT EXISTS {column_def}"))

        conn.execute(text(
            "ALTER TABLE sanction_entries ALTER COLUMN nationalite TYPE VARCHAR(255)"
        ))

        for column_def in [
            "role_assigned_at TIMESTAMP",
            "last_login_at TIMESTAMP",
            "last_activity_at TIMESTAMP",
            "failed_login_attempts INTEGER NOT NULL DEFAULT 0",
            "locked_at TIMESTAMP",
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

    db = SessionLocal()
    try:
        create_default_admin(db, INITIAL_ADMIN_PASSWORD)
    finally:
        db.close()

    start_scheduler()


app.include_router(sanctions.router)
app.include_router(matching.router)
app.include_router(alerts.router)
app.include_router(audit_logs.router)
app.include_router(dashboard.router)
app.include_router(imports.router)
app.include_router(web.router)
app.include_router(exports.router)
app.include_router(external_api.router)

@app.get("/")
def home():
    return {
        "message": "BLACKMODULE API is running",
        "status": "OK"
    }


@app.get("/health/live")
def health_live():
    return {"status": "OK"}


@app.get("/health/ready")
def health_ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1")).scalar()
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return {"status": "OK", "database": "ready"}


@app.get("/db-check")
def db_check(db: Session = Depends(get_db)):
    try:
        result = db.execute(text("SELECT 1")).scalar()

        return {
            "database": "PostgreSQL",
            "connection": "SUCCESS",
            "test_result": result,
            "message": "FastAPI est bien connecté à PostgreSQL"
        }

    except Exception as e:
        return {
            "database": "PostgreSQL",
            "connection": "FAILED",
            "error": str(e),
            "message": "FastAPI n'arrive pas à se connecter à PostgreSQL"
        }
