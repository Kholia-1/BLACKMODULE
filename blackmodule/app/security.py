import secrets

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


CSRF_SESSION_KEY = "csrf_token"


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
