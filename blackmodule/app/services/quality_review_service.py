"""Read-only quality control over applied alert decisions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import Query, Session

from app.models import (
    Alert,
    AlertDecisionHistory,
    AlertQualityReview,
    ApprovalRequest,
)
from app.services.alert_decision_service import APPLIED_DECISION, APPROVED_DECISION
from app.services.authorization_service import ROLE_ANALYSTE_CONFORMITE, canonical_role
from app.services.reporting_service import resolve_reporting_filters


REVIEW_PENDING = "A_REVOIR"
REVIEW_COMPLIANT = "CONFORME"
REVIEW_NON_COMPLIANT = "NON_CONFORME"
QUALITY_REVIEW_STATUSES = (REVIEW_PENDING, REVIEW_COMPLIANT, REVIEW_NON_COMPLIANT)
REVIEWABLE_DECISIONS = ("FAUX_POSITIF", "CONFIRMEE")
APPLIED_DECISION_STATUSES = (APPLIED_DECISION, APPROVED_DECISION)
QUALITY_REVIEW_MAX_SAMPLE = 200

REVIEW_STATUS_LABELS = {
    REVIEW_PENDING: "À revoir",
    REVIEW_COMPLIANT: "Conforme",
    REVIEW_NON_COMPLIANT: "Non conforme",
}
DECISION_LABELS = {
    "FAUX_POSITIF": "Faux positif",
    "CONFIRMEE": "Confirmation",
}
APPROVAL_STATUS_LABELS = {
    "EN_ATTENTE_VALIDATION": "En attente",
    "VALIDE": "Validée",
    "REJETE": "Rejetée",
    "OBSOLETE": "Obsolète",
}


class QualityReviewError(ValueError):
    pass


@dataclass(frozen=True)
class QualityReviewFilters:
    period: str
    start_at: datetime
    end_at: datetime
    source: str | None = None
    analyst: str | None = None
    decision: str | None = None
    review_status: str | None = None
    sample_size: int = 50

    @property
    def start_date(self):
        return self.start_at.date()

    @property
    def end_date(self):
        return (self.end_at - timedelta(days=1)).date()


def resolve_quality_review_filters(
    *,
    period: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    source: str | None = None,
    analyst: str | None = None,
    decision: str | None = None,
    review_status: str | None = None,
    sample_size: int | str | None = None,
    now: datetime | None = None,
) -> QualityReviewFilters:
    reporting = resolve_reporting_filters(
        period=period,
        date_from=date_from,
        date_to=date_to,
        source=source,
        now=now,
    )
    selected_decision = (decision or "").strip().upper() or None
    if selected_decision and selected_decision not in REVIEWABLE_DECISIONS:
        raise QualityReviewError("Décision qualité invalide.")
    selected_review = (review_status or "").strip().upper() or None
    if selected_review and selected_review not in QUALITY_REVIEW_STATUSES:
        raise QualityReviewError("Statut de revue invalide.")
    try:
        selected_size = int(sample_size or 50)
    except (TypeError, ValueError) as exc:
        raise QualityReviewError("Taille d’échantillon invalide.") from exc
    selected_size = max(1, min(selected_size, QUALITY_REVIEW_MAX_SAMPLE))
    return QualityReviewFilters(
        period=reporting.period,
        start_at=reporting.start_at,
        end_at=reporting.end_at,
        source=reporting.source,
        analyst=(analyst or "").strip() or None,
        decision=selected_decision,
        review_status=selected_review,
        sample_size=selected_size,
    )


def _eligible_decisions(db: Session, filters: QualityReviewFilters) -> Query:
    query = db.query(AlertDecisionHistory).join(
        Alert, Alert.id == AlertDecisionHistory.alert_id,
    ).filter(
        AlertDecisionHistory.decision_status.in_(APPLIED_DECISION_STATUSES),
        AlertDecisionHistory.requested_status.in_(REVIEWABLE_DECISIONS),
        AlertDecisionHistory.applied_at.is_not(None),
        AlertDecisionHistory.applied_at >= filters.start_at,
        AlertDecisionHistory.applied_at < filters.end_at,
    )
    if filters.source:
        query = query.filter(Alert.source_liste == filters.source)
    if filters.analyst:
        query = query.filter(AlertDecisionHistory.initiated_by == filters.analyst)
    if filters.decision:
        query = query.filter(AlertDecisionHistory.requested_status == filters.decision)
    return query


def _latest_reviews(db: Session):
    return db.query(
        AlertQualityReview.id.label("review_id"),
        AlertQualityReview.decision_history_id.label("decision_id"),
        AlertQualityReview.review_status,
        AlertQualityReview.quality_comment,
        AlertQualityReview.reviewed_by,
        AlertQualityReview.reviewed_at,
        func.row_number().over(
            partition_by=AlertQualityReview.decision_history_id,
            order_by=(AlertQualityReview.reviewed_at.desc(), AlertQualityReview.id.desc()),
        ).label("review_rank"),
    ).subquery()


def _with_latest_review(query: Query, latest, filters: QualityReviewFilters) -> Query:
    query = query.outerjoin(
        latest,
        and_(
            latest.c.decision_id == AlertDecisionHistory.id,
            latest.c.review_rank == 1,
        ),
    )
    if filters.review_status == REVIEW_PENDING:
        query = query.filter(or_(
            latest.c.review_id.is_(None),
            latest.c.review_status == REVIEW_PENDING,
        ))
    elif filters.review_status:
        query = query.filter(latest.c.review_status == filters.review_status)
    return query


def _quality_kpis(db: Session, filters: QualityReviewFilters, latest) -> tuple[dict, list[dict]]:
    query = _with_latest_review(_eligible_decisions(db, filters), latest, filters)
    rows = query.with_entities(
        AlertDecisionHistory.initiated_by,
        func.count(AlertDecisionHistory.id),
        func.coalesce(func.sum(case((latest.c.review_status == REVIEW_COMPLIANT, 1), else_=0)), 0),
        func.coalesce(func.sum(case((latest.c.review_status == REVIEW_NON_COMPLIANT, 1), else_=0)), 0),
    ).group_by(AlertDecisionHistory.initiated_by).order_by(AlertDecisionHistory.initiated_by).all()
    analysts = []
    total = compliant = non_compliant = 0
    for analyst, count, analyst_compliant, analyst_non_compliant in rows:
        count = int(count or 0)
        analyst_compliant = int(analyst_compliant or 0)
        analyst_non_compliant = int(analyst_non_compliant or 0)
        reviewed = analyst_compliant + analyst_non_compliant
        analysts.append({
            "analyst": analyst or "Non renseigné",
            "total": count,
            "pending": count - reviewed,
            "compliant": analyst_compliant,
            "non_compliant": analyst_non_compliant,
            "compliance_rate": round(analyst_compliant / reviewed * 100, 1) if reviewed else 0.0,
            "non_compliance_rate": round(analyst_non_compliant / reviewed * 100, 1) if reviewed else 0.0,
        })
        total += count
        compliant += analyst_compliant
        non_compliant += analyst_non_compliant
    reviewed = compliant + non_compliant
    return {
        "total": total,
        "pending": total - reviewed,
        "reviewed": reviewed,
        "compliant": compliant,
        "non_compliant": non_compliant,
        "compliance_rate": round(compliant / reviewed * 100, 1) if reviewed else 0.0,
        "non_compliance_rate": round(non_compliant / reviewed * 100, 1) if reviewed else 0.0,
    }, analysts


def build_quality_review_dashboard(db: Session, filters: QualityReviewFilters) -> dict:
    latest = _latest_reviews(db)
    kpis, analyst_kpis = _quality_kpis(db, filters, latest)
    query = _with_latest_review(_eligible_decisions(db, filters), latest, filters).outerjoin(
        ApprovalRequest,
        ApprovalRequest.id == AlertDecisionHistory.approval_request_id,
    )
    rows = query.with_entities(
        AlertDecisionHistory.id,
        Alert.id,
        Alert.source_liste,
        AlertDecisionHistory.requested_status,
        AlertDecisionHistory.initiated_by,
        AlertDecisionHistory.applied_at,
        ApprovalRequest.status,
        latest.c.review_status,
        latest.c.quality_comment,
        latest.c.reviewed_by,
        latest.c.reviewed_at,
    ).order_by(
        AlertDecisionHistory.applied_at.desc(),
        AlertDecisionHistory.id,
    ).limit(filters.sample_size).all()
    decision_ids = [row[0] for row in rows]
    history_rows = db.query(AlertQualityReview).filter(
        AlertQualityReview.decision_history_id.in_(decision_ids),
    ).order_by(
        AlertQualityReview.reviewed_at.desc(), AlertQualityReview.id.desc(),
    ).all()
    histories: dict[str, list[dict]] = {str(decision_id): [] for decision_id in decision_ids}
    for review in history_rows:
        histories[str(review.decision_history_id)].append({
            "status": review.review_status,
            "status_label": REVIEW_STATUS_LABELS.get(review.review_status, review.review_status),
            "comment": review.quality_comment,
            "reviewed_by": review.reviewed_by,
            "reviewed_at": review.reviewed_at,
        })
    items = []
    for row in rows:
        decision_id = str(row[0])
        review_status = row[7] or REVIEW_PENDING
        items.append({
            "decision_id": decision_id,
            "alert_id": str(row[1]),
            "source": row[2] or "Source inconnue",
            "decision": row[3],
            "decision_label": DECISION_LABELS.get(row[3], row[3]),
            "analyst": row[4] or "Non renseigné",
            "decision_at": row[5],
            "approval_status": APPROVAL_STATUS_LABELS.get(row[6], row[6] or "Sans demande liée"),
            "review_status": review_status,
            "review_status_label": REVIEW_STATUS_LABELS.get(review_status, review_status),
            "quality_comment": row[8],
            "reviewed_by": row[9],
            "reviewed_at": row[10],
            "history": histories.get(decision_id, []),
        })

    option_query = db.query(AlertDecisionHistory).join(
        Alert, Alert.id == AlertDecisionHistory.alert_id,
    ).filter(
        AlertDecisionHistory.decision_status.in_(APPLIED_DECISION_STATUSES),
        AlertDecisionHistory.requested_status.in_(REVIEWABLE_DECISIONS),
        AlertDecisionHistory.applied_at >= filters.start_at,
        AlertDecisionHistory.applied_at < filters.end_at,
    )
    sources = [
        row[0] for row in option_query.with_entities(Alert.source_liste)
        .filter(Alert.source_liste.is_not(None))
        .group_by(Alert.source_liste).order_by(Alert.source_liste).all()
    ]
    analysts = [
        row[0] for row in option_query.with_entities(AlertDecisionHistory.initiated_by)
        .filter(AlertDecisionHistory.initiated_by.is_not(None))
        .group_by(AlertDecisionHistory.initiated_by)
        .order_by(AlertDecisionHistory.initiated_by).all()
    ]
    return {
        "filters": filters,
        "kpis": kpis,
        "analyst_kpis": analyst_kpis,
        "items": items,
        "options": {
            "sources": sources,
            "analysts": analysts,
            "decisions": DECISION_LABELS,
            "review_statuses": REVIEW_STATUS_LABELS,
        },
    }


def create_quality_review(
    db: Session,
    *,
    decision_id: UUID | str,
    review_status: str,
    quality_comment: str | None,
    actor: dict,
    reviewed_at: datetime | None = None,
) -> AlertQualityReview:
    status = (review_status or "").strip().upper()
    if status not in QUALITY_REVIEW_STATUSES:
        raise QualityReviewError("Statut de revue invalide.")
    comment = (quality_comment or "").strip() or None
    if comment and len(comment) > 2000:
        raise QualityReviewError("Le commentaire qualité est limité à 2 000 caractères.")
    if status == REVIEW_NON_COMPLIANT and not comment:
        raise QualityReviewError("Un commentaire qualité est obligatoire pour une non-conformité.")
    decision = db.query(AlertDecisionHistory).filter(
        AlertDecisionHistory.id == decision_id,
        AlertDecisionHistory.decision_status.in_(APPLIED_DECISION_STATUSES),
        AlertDecisionHistory.requested_status.in_(REVIEWABLE_DECISIONS),
    ).first()
    if not decision:
        raise QualityReviewError("Décision traitée introuvable.")
    username = (actor.get("username") or "").strip()
    if not username or not actor.get("id"):
        raise QualityReviewError("Contrôleur qualité invalide.")
    try:
        reviewer_user_id = UUID(str(actor["id"]))
    except (TypeError, ValueError) as exc:
        raise QualityReviewError("Contrôleur qualité invalide.") from exc
    if (
        canonical_role(actor.get("role")) == ROLE_ANALYSTE_CONFORMITE
        and username.casefold() == (decision.initiated_by or "").casefold()
    ):
        raise PermissionError("Un analyste ne peut pas contrôler sa propre décision.")
    review = AlertQualityReview(
        alert_id=decision.alert_id,
        decision_history_id=decision.id,
        review_status=status,
        quality_comment=comment,
        reviewed_by_user_id=reviewer_user_id,
        reviewed_by=username,
        reviewed_at=reviewed_at or datetime.utcnow(),
    )
    db.add(review)
    db.flush()
    return review


def quality_review_export_rows(report: dict) -> list[list]:
    """Build a filtered export without client data or quality comments."""
    rows = [
        ["Revue qualité BLACKMODULE"],
        ["Période", report["filters"].start_date, report["filters"].end_date],
        [],
        ["Indicateur", "Valeur"],
        ["Décisions éligibles", report["kpis"]["total"]],
        ["À revoir", report["kpis"]["pending"]],
        ["Conformes", report["kpis"]["compliant"]],
        ["Non conformes", report["kpis"]["non_compliant"]],
        ["Taux de conformité (%)", report["kpis"]["compliance_rate"]],
        ["Taux de non-conformité (%)", report["kpis"]["non_compliance_rate"]],
        [],
        [
            "ID alerte", "Source", "Décision", "Analyste", "Décidée le",
            "Validation quatre-yeux", "Statut revue", "Contrôleur", "Revue le",
        ],
    ]
    rows.extend([
        [
            item["alert_id"], item["source"], item["decision_label"], item["analyst"],
            item["decision_at"], item["approval_status"], item["review_status_label"],
            item["reviewed_by"], item["reviewed_at"],
        ]
        for item in report["items"]
    ])
    return rows
