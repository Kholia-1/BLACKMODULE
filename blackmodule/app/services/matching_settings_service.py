from datetime import datetime
from sqlalchemy.orm import Session

from app.models import MatchingSetting


def get_or_create_matching_settings(db: Session) -> MatchingSetting:
    settings = db.query(MatchingSetting).first()

    if settings:
        return settings

    settings = MatchingSetting(
        exact_threshold=90.0,
        probable_threshold=75.0,
        possible_threshold=60.0,
        updated_by="SYSTEM",
        updated_at=datetime.utcnow()
    )

    db.add(settings)
    db.commit()
    db.refresh(settings)

    return settings


def update_matching_settings(
    db: Session,
    exact_threshold: float,
    probable_threshold: float,
    possible_threshold: float,
    updated_by: str
) -> MatchingSetting:

    settings = get_or_create_matching_settings(db)

    settings.exact_threshold = exact_threshold
    settings.probable_threshold = probable_threshold
    settings.possible_threshold = possible_threshold
    settings.updated_by = updated_by
    settings.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(settings)

    return settings