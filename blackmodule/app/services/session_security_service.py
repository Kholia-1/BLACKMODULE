from __future__ import annotations

from datetime import datetime, timedelta

from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import SESSION_ACTIVITY_PERSIST_INTERVAL_MINUTES, SESSION_IDLE_TIMEOUT_MINUTES
from app.database import SessionLocal
from app.models import User
from app.services.audit_service import write_audit_log


class SessionActivityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        session = request.session
        user = session.get("user")
        if not user or request.url.path.startswith("/static"):
            return await call_next(request)

        now = datetime.utcnow()
        try:
            last_activity = datetime.fromisoformat(session.get("last_activity_at", ""))
        except ValueError:
            last_activity = now

        if now - last_activity > timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES):
            self._audit_expiration(user, request)
            session.clear()
            if request.url.path.startswith("/web"):
                return RedirectResponse("/web/login?message=session_expired", status_code=303)
            return JSONResponse({"detail": "Session expirée par inactivité."}, status_code=401)

        session["last_activity_at"] = now.isoformat()
        try:
            persisted_at = datetime.fromisoformat(session.get("last_activity_persisted_at", ""))
        except ValueError:
            persisted_at = now - timedelta(minutes=SESSION_ACTIVITY_PERSIST_INTERVAL_MINUTES + 1)
        if now - persisted_at >= timedelta(minutes=SESSION_ACTIVITY_PERSIST_INTERVAL_MINUTES):
            self._persist_activity(user, now)
            session["last_activity_persisted_at"] = now.isoformat()
        return await call_next(request)

    @staticmethod
    def _persist_activity(session_user: dict, now: datetime) -> None:
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.id == session_user.get("id")).first()
            if user:
                user.last_activity_at = now
                db.commit()
        finally:
            db.close()

    @staticmethod
    def _audit_expiration(session_user: dict, request) -> None:
        db = SessionLocal()
        try:
            write_audit_log(
                db, session_user.get("username"), "SESSION_EXPIRED", "User",
                session_user.get("id"), "Session expirée après inactivité.",
                request.client.host if request.client else None,
            )
            db.commit()
        finally:
            db.close()
