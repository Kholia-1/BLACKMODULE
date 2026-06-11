from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.models import User


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


def authenticate_user(
    db: Session,
    username: str,
    password: str
):
    user = db.query(User).filter(
        User.username == username,
        User.statut == "ACTIF"
    ).first()

    if not user:
        return None

    if not verify_password(password, user.password_hash):
        return None

    return user


def create_default_admin(db: Session):
    existing_admin = db.query(User).filter(
        User.username == "admin"
    ).first()

    if existing_admin:
        return existing_admin

    admin = User(
        username="admin",
        full_name="Administrateur BLACKMODULE",
        email="admin@blackmodule.local",
        password_hash=hash_password("admin"),
        role="ADMIN",
        statut="ACTIF"
    )

    db.add(admin)
    db.commit()
    db.refresh(admin)

    return admin