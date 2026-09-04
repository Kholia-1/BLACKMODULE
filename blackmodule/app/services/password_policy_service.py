import re

from app.config import IS_PRODUCTION, PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH


COMMON_PASSWORDS = {
    "admin", "admin123", "administrator", "blackmodule", "changeme",
    "password", "password123", "qwerty", "welcome", "welcome123",
}


def validate_password_policy(
    password: str,
    *,
    username: str | None = None,
    production: bool | None = None,
) -> str | None:
    """Retourne un message utilisateur sans jamais inclure le mot de passe."""
    enforced_production = IS_PRODUCTION if production is None else production
    minimum = PASSWORD_MIN_LENGTH if enforced_production else 6

    if not password or len(password) < minimum:
        return f"Le mot de passe doit contenir au moins {minimum} caractères."
    if len(password) > PASSWORD_MAX_LENGTH:
        return f"Le mot de passe ne doit pas dépasser {PASSWORD_MAX_LENGTH} caractères."
    if not enforced_production:
        return None

    if password.casefold() in COMMON_PASSWORDS:
        return "Ce mot de passe est trop courant."
    if username and username.strip() and username.strip().casefold() in password.casefold():
        return "Le mot de passe ne doit pas contenir l'identifiant utilisateur."
    required_classes = (
        re.search(r"[a-z]", password),
        re.search(r"[A-Z]", password),
        re.search(r"\d", password),
        re.search(r"[^A-Za-z0-9]", password),
    )
    if not all(required_classes):
        return (
            "Le mot de passe doit contenir une minuscule, une majuscule, "
            "un chiffre et un caractère spécial."
        )
    return None
