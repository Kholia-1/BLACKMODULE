from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import SESSION_ACTIVITY_PERSIST_INTERVAL_MINUTES, SESSION_IDLE_TIMEOUT_MINUTES
from app.database import SessionLocal
from app.models import AuditLog, User
from app.services.audit_service import write_audit_log


USER_DEACTIVATED_ACTION = "USER_DEACTIVATED"
SESSION_DEACTIVATION_REVISION_KEY = "account_deactivation_revision"


def account_deactivation_revision(db, user_id) -> int:
    """Return the immutable deactivation-event count for a user account."""
    return db.query(AuditLog).filter(
        AuditLog.action == USER_DEACTIVATED_ACTION,
        AuditLog.entity_type == "User",
        AuditLog.entity_id == str(user_id),
    ).count()


class SessionActivityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, session_factory=None):
        super().__init__(app)
        self._session_factory = session_factory or SessionLocal

    async def dispatch(self, request, call_next):
        session = request.session
        user = session.get("user")
        if not user or request.url.path.startswith("/static"):
            return await call_next(request)

        account_status, current_revision = self._account_session_state(user)
        stored_revision = session.get(SESSION_DEACTIVATION_REVISION_KEY)
        invalid_account = account_status != "ACTIF"
        invalid_revision = stored_revision is not None and stored_revision != current_revision
        if invalid_account or invalid_revision:
            session.clear()
            if request.url.path == "/web/login":
                return await call_next(request)
            if request.url.path.startswith("/web"):
                message = "account_inactive" if invalid_account else "session_revoked"
                return RedirectResponse(f"/web/login?message={message}", status_code=303)
            return JSONResponse({"detail": "Session invalide."}, status_code=401)

        # Preserve already-open sessions created before this revision marker
        # existed. The first request upgrades them without disconnecting an
        # account that is still active.
        if stored_revision is None:
            session[SESSION_DEACTIVATION_REVISION_KEY] = current_revision

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

    def _account_session_state(self, session_user: dict) -> tuple[str | None, int | None]:
        try:
            user_id = UUID(str(session_user.get("id")))
        except (TypeError, ValueError):
            return None, None

        db = self._session_factory()
        try:
            account = db.query(User).filter(User.id == user_id).first()
            if not account:
                return None, None
            if account.statut != "ACTIF":
                return account.statut, None
            return account.statut, account_deactivation_revision(db, account.id)
        finally:
            db.close()

    def _persist_activity(self, session_user: dict, now: datetime) -> None:
        db = self._session_factory()
        try:
            user = db.query(User).filter(User.id == session_user.get("id")).first()
            if user:
                user.last_activity_at = now
                db.commit()
        finally:
            db.close()

    def _audit_expiration(self, session_user: dict, request) -> None:
        db = self._session_factory()
        try:
            write_audit_log(
                db, session_user.get("username"), "SESSION_EXPIRED", "User",
                session_user.get("id"), "Session expirée après inactivité.",
                request.client.host if request.client else None,
            )
            db.commit()
        finally:
            db.close()
