from dataclasses import dataclass
from datetime import datetime, timedelta

from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.config import BOOTSTRAP_PASSWORD_TTL_HOURS, IS_PRODUCTION, MAX_FAILED_LOGIN_ATTEMPTS
from app.models import User
from app.services.authorization_service import ROLE_ADMIN_TECHNIQUE
from app.services.password_policy_service import validate_password_policy


pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto"
)


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Le mot de passe ne peut pas être vide.")

    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    if not plain_password or not password_hash:
        return False

    return pwd_context.verify(plain_password, password_hash)


@dataclass
class AuthenticationResult:
    user: User | None
    reason: str
    locked_now: bool = False


def authenticate_user(
    db: Session,
    username: str,
    password: str
):
    user = db.query(User).filter(User.username == username.strip()).first()

    if not user or user.statut != "ACTIF":
        return AuthenticationResult(user=None, reason="INVALID")

    if user.locked_at is not None:
        return AuthenticationResult(user=None, reason="LOCKED")

    if (
        user.must_change_password
        and user.bootstrap_credential_expires_at
        and datetime.utcnow() >= user.bootstrap_credential_expires_at
    ):
        return AuthenticationResult(user=None, reason="BOOTSTRAP_EXPIRED")

    if not verify_password(password, user.password_hash):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        locked_now = user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS
        if locked_now:
            user.locked_at = datetime.utcnow()
        return AuthenticationResult(user=None, reason="INVALID", locked_now=locked_now)

    user.failed_login_attempts = 0
    user.locked_at = None
    user.last_login_at = datetime.utcnow()
    user.last_activity_at = user.last_login_at
    return AuthenticationResult(user=user, reason="SUCCESS")


def create_default_admin(
    db: Session,
    initial_password: str | None = None,
    *,
    production: bool | None = None,
):
    existing_admin = db.query(User).filter(
        User.username == "admin"
    ).first()

    if existing_admin:
        return existing_admin

    if not initial_password:
        raise RuntimeError(
            "INITIAL_ADMIN_PASSWORD doit être défini pour initialiser une base vide."
        )

    enforced_production = IS_PRODUCTION if production is None else production
    policy_error = validate_password_policy(
        initial_password, username="admin", production=enforced_production
    )
    if policy_error:
        raise RuntimeError(f"INITIAL_ADMIN_PASSWORD non conforme : {policy_error}")

    now = datetime.utcnow()

    admin = User(
        username="admin",
        full_name="Administrateur BLACKMODULE",
        email="admin@blackmodule.local",
        password_hash=hash_password(initial_password),
        role=ROLE_ADMIN_TECHNIQUE,
        statut="ACTIF",
        role_assigned_at=now,
        must_change_password=enforced_production,
        bootstrap_credential_expires_at=(
            now + timedelta(hours=BOOTSTRAP_PASSWORD_TTL_HOURS)
            if enforced_production else None
        ),
    )

    db.add(admin)
    db.commit()
    db.refresh(admin)

    return admin
