from fastapi import Depends, HTTPException, Request

from app.services.authorization_service import canonical_role, has_permission


def get_session_user(request: Request) -> dict:
    user = request.session.get("user")

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentification requise. Veuillez vous connecter."
        )

    return user


def require_permission(permission: str):
    def dependency(user: dict = Depends(get_session_user)) -> dict:
        if not has_permission(user, permission):
            raise HTTPException(
                status_code=403,
                detail="Accès refusé : permission insuffisante pour cette action.",
            )
        return user

    return dependency


def require_roles(*allowed_roles: str):
    """Compatibilité pour les routes historiques pendant leur conversion."""
    canonical_allowed = {canonical_role(role) for role in allowed_roles}

    def dependency(user: dict = Depends(get_session_user)) -> dict:
        if canonical_role(user.get("role")) not in canonical_allowed:
            raise HTTPException(
                status_code=403,
                detail="Accès refusé : rôle insuffisant pour cette action."
            )

        return user

    return dependency
