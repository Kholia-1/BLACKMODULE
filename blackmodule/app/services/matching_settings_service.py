from datetime import datetime
from sqlalchemy.orm import Session

from app.models import MatchingSetting


def validate_matching_thresholds(
    exact_threshold: float,
    probable_threshold: float,
    possible_threshold: float,
) -> None:
    if not 0 <= possible_threshold <= probable_threshold <= exact_threshold <= 100:
        raise ValueError(
            "Les seuils doivent respecter 0 <= possible <= probable <= exact <= 100."
        )


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
    updated_by: str,
    commit: bool = True,
) -> MatchingSetting:

    validate_matching_thresholds(exact_threshold, probable_threshold, possible_threshold)

    settings = get_or_create_matching_settings(db)

    settings.exact_threshold = exact_threshold
    settings.probable_threshold = probable_threshold
    settings.possible_threshold = possible_threshold
    settings.updated_by = updated_by
    settings.updated_at = datetime.utcnow()

    if commit:
        db.commit()
        db.refresh(settings)

    return settings
