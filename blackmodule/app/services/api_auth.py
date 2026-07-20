from fastapi import Depends, HTTPException, Request


def get_session_user(request: Request) -> dict:
    user = request.session.get("user")

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentification requise. Veuillez vous connecter."
        )

    return user


def require_roles(*allowed_roles: str):
    def dependency(user: dict = Depends(get_session_user)) -> dict:
        if user.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail="Accès refusé : rôle insuffisant pour cette action."
            )

        return user

    return dependency
