from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from starlette.middleware.sessions import SessionMiddleware

from app.database import Base, engine, get_db, SessionLocal
from app import models
from app.services.auth_service import create_default_admin

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

app.add_middleware(
    SessionMiddleware,
    secret_key="blackmodule_secret_key_change_later"
)


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        create_default_admin(db)
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