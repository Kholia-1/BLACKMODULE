import secrets
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from math import ceil
from threading import Lock
from time import monotonic

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import (
    IS_PRODUCTION,
    LOGIN_RATE_LIMIT_ATTEMPTS,
    LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    SENSITIVE_RATE_LIMIT_ATTEMPTS,
    SENSITIVE_RATE_LIMIT_WINDOW_SECONDS,
)
from app.database import SessionLocal
from app.services.audit_service import write_audit_log


CSRF_SESSION_KEY = "csrf_token"


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after: int = 0
    should_log: bool = False


class SlidingWindowRateLimiter:
    """Limiteur local borné et thread-safe, sans dépendance d'infrastructure."""

    def __init__(self, max_buckets: int = 10000):
        self._events = defaultdict(deque)
        self._last_rejection_log = {}
        self._lock = Lock()
        self._max_buckets = max_buckets

    def consume(self, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        now = monotonic()
        with self._lock:
            events = self._events[key]
            threshold = now - window_seconds
            while events and events[0] <= threshold:
                events.popleft()

            if len(events) >= limit:
                retry_after = max(1, ceil(events[0] + window_seconds - now))
                last_log = self._last_rejection_log.get(key, 0.0)
                should_log = now - last_log >= max(1, window_seconds / 2)
                if should_log:
                    self._last_rejection_log[key] = now
                return RateLimitResult(False, retry_after, should_log)

            events.append(now)
            if len(self._events) > self._max_buckets:
                self._prune(threshold)
            return RateLimitResult(True)

    def _prune(self, threshold: float) -> None:
        stale_keys = [
            key for key, events in self._events.items()
            if not events or events[-1] <= threshold
        ]
        for key in stale_keys:
            self._events.pop(key, None)
            self._last_rejection_log.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._last_rejection_log.clear()


security_rate_limiter = SlidingWindowRateLimiter()


def _rate_limit_policy(request: Request):
    path = request.url.path
    if request.method == "POST" and path == "/web/login":
        return "login", LOGIN_RATE_LIMIT_ATTEMPTS, LOGIN_RATE_LIMIT_WINDOW_SECONDS
    if path.startswith("/api/external/"):
        return "external", SENSITIVE_RATE_LIMIT_ATTEMPTS, SENSITIVE_RATE_LIMIT_WINDOW_SECONDS
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and (
        path.startswith("/web/") or path.startswith("/api/")
    ):
        return "sensitive", SENSITIVE_RATE_LIMIT_ATTEMPTS, SENSITIVE_RATE_LIMIT_WINDOW_SECONDS
    if request.method == "GET" and path.startswith("/api/exports/"):
        return "export", SENSITIVE_RATE_LIMIT_ATTEMPTS, SENSITIVE_RATE_LIMIT_WINDOW_SECONDS
    return None


class SecurityRateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        policy = _rate_limit_policy(request)
        if not policy:
            return await call_next(request)

        policy_name, limit, window = policy
        session_user = request.session.get("user") or {}
        actor = session_user.get("username") or "ANONYMOUS"
        client_ip = request.client.host if request.client else "UNKNOWN"
        result = security_rate_limiter.consume(
            f"{policy_name}:{client_ip}:{actor}", limit, window
        )
        if result.allowed:
            return await call_next(request)

        if result.should_log:
            self._audit_rejection(actor, request)
        return JSONResponse(
            status_code=429,
            content={"detail": "Trop de requêtes. Réessayez ultérieurement."},
            headers={"Retry-After": str(result.retry_after)},
        )

    @staticmethod
    def _audit_rejection(actor: str, request: Request) -> None:
        db = SessionLocal()
        try:
            write_audit_log(
                db=db,
                user_identifier=actor,
                action="RATE_LIMIT_EXCEEDED",
                entity_type="Endpoint",
                entity_id=request.url.path,
                description="Limite de requêtes dépassée.",
                ip_address=request.client.host if request.client else None,
            )
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()


class ForcedPasswordChangeMiddleware(BaseHTTPMiddleware):
    """Isole une session bootstrap jusqu'au remplacement de son secret."""

    ALLOWED_PATHS = {
        "/web/change-password",
        "/web/logout",
        "/health/live",
        "/health/ready",
    }

    async def dispatch(self, request: Request, call_next):
        user = request.session.get("user") or {}
        path = request.url.path
        legacy_bootstrap_session = (
            IS_PRODUCTION
            and user.get("username") == "admin"
            and "must_change_password" not in user
        )
        if legacy_bootstrap_session:
            request.session.clear()
            return self._expired_response(path)

        requires_change = user.get("must_change_password")
        expiry_value = user.get("bootstrap_credential_expires_at")
        if requires_change and expiry_value:
            try:
                expired = datetime.utcnow() >= datetime.fromisoformat(expiry_value)
            except (TypeError, ValueError):
                expired = True
            if expired:
                self._audit_expiration(user, request)
                request.session.clear()
                return self._expired_response(path)
        if (
            requires_change
            and path not in self.ALLOWED_PATHS
            and not path.startswith("/static/")
        ):
            if path.startswith("/web/"):
                return RedirectResponse("/web/change-password", status_code=303)
            return JSONResponse(
                {"detail": "Changement de mot de passe obligatoire."}, status_code=403
            )
        return await call_next(request)

    @staticmethod
    def _expired_response(path: str):
        if path.startswith("/web/"):
            return RedirectResponse("/web/login?message=bootstrap_expired", status_code=303)
        return JSONResponse({"detail": "Session bootstrap expirée."}, status_code=401)

    @staticmethod
    def _audit_expiration(user: dict, request: Request) -> None:
        db = SessionLocal()
        try:
            write_audit_log(
                db=db,
                user_identifier=user.get("username"),
                action="BOOTSTRAP_SESSION_EXPIRED",
                entity_type="User",
                entity_id=user.get("id"),
                description="Session bootstrap expirée avant changement du mot de passe.",
                ip_address=request.client.host if request.client else None,
            )
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()


def get_csrf_token(request: Request) -> str:
    """Return the per-session token exposed only to same-origin templates."""
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[CSRF_SESSION_KEY] = token
    return token


class CSRFMiddleware(BaseHTTPMiddleware):
    """Require a per-session token for state-changing browser routes."""

    async def dispatch(self, request: Request, call_next):
        if (
            request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and request.url.path.startswith("/web/")
        ):
            # Cache the body before parsing it so Starlette can replay it to
            # the downstream endpoint (including multipart file uploads).
            await request.body()
            form = await request.form()
            received_token = form.get("csrf_token")
            expected_token = request.session.get(CSRF_SESSION_KEY)

            if not (
                isinstance(received_token, str)
                and isinstance(expected_token, str)
                and secrets.compare_digest(received_token, expected_token)
            ):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Jeton CSRF invalide ou manquant."},
                )

        return await call_next(request)
