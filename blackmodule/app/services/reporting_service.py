"""Read-only compliance reporting built from existing alert workflow data."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from statistics import median
from uuid import UUID

from sqlalchemy import and_, case, exists, func, not_, or_
from sqlalchemy.orm import Query, Session

from app.config import ALERT_INACTIVITY_HOURS
from app.models import Alert, AlertAssignmentHistory, AlertDecisionHistory, User
from app.services.alert_decision_service import APPLIED_DECISION, APPROVED_DECISION
from app.services.alert_queue_service import (
    SLA_BREACHED,
    SLA_NEAR,
    SLA_OK,
    TERMINAL_ALERT_STATUSES,
    sla_sql_conditions,
)
from app.services.authorization_service import ROLE_ANALYSTE_CONFORMITE


MAX_REPORT_DAYS = 366
FINAL_DECISION_STATUSES = ("FAUX_POSITIF", "CONFIRMEE", "CLOTUREE")
APPLIED_HISTORY_STATUSES = (APPLIED_DECISION, APPROVED_DECISION)
MANAGEMENT_COMPARISON_KEYS = (
    "backlog_total",
    "backlog_critical",
    "backlog_out_sla",
    "created",
    "closed",
    "closure_rate",
    "false_positive_rate",
    "confirmation_rate",
    "average_hours",
    "median_hours",
    "sla_compliance_rate",
)


@dataclass(frozen=True)
class ReportingFilters:
    period: str
    start_at: datetime
    end_at: datetime
    source: str | None = None
    status: str | None = None
    analyst_id: UUID | None = None

    @property
    def start_date(self) -> date:
        return self.start_at.date()

    @property
    def end_date(self) -> date:
        return (self.end_at - timedelta(days=1)).date()


def resolve_reporting_filters(
    *,
    period: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    source: str | None = None,
    status: str | None = None,
    analyst: str | None = None,
    now: datetime | None = None,
) -> ReportingFilters:
    today = (now or datetime.utcnow()).date()
    selected_period = (period or "30").strip().lower()
    if selected_period not in {"7", "30", "custom"}:
        selected_period = "30"

    if selected_period == "custom":
        try:
            start_day = date.fromisoformat(date_from or "")
            end_day = date.fromisoformat(date_to or "")
        except ValueError as exc:
            raise ValueError("Les dates de début et de fin sont obligatoires pour une période personnalisée.") from exc
        if end_day < start_day:
            raise ValueError("La date de fin doit être postérieure ou égale à la date de début.")
    else:
        days = int(selected_period)
        end_day = today
        start_day = today - timedelta(days=days - 1)

    day_count = (end_day - start_day).days + 1
    if day_count > MAX_REPORT_DAYS:
        raise ValueError(f"La période de reporting est limitée à {MAX_REPORT_DAYS} jours.")

    analyst_id = None
    if analyst:
        try:
            analyst_id = UUID(str(analyst))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("Analyste invalide.") from exc

    return ReportingFilters(
        period=selected_period,
        start_at=datetime.combine(start_day, time.min),
        end_at=datetime.combine(end_day + timedelta(days=1), time.min),
        source=(source or "").strip().upper() or None,
        status=(status or "").strip().upper() or None,
        analyst_id=analyst_id,
    )


def _apply_dimensions(query: Query, filters: ReportingFilters, *, include_period: bool) -> Query:
    if include_period:
        query = query.filter(
            Alert.created_at >= filters.start_at,
            Alert.created_at < filters.end_at,
        )
    if filters.source:
        query = query.filter(Alert.source_liste == filters.source)
    if filters.status:
        query = query.filter(Alert.statut == filters.status)
    if filters.analyst_id:
        query = query.filter(Alert.assigned_to_user_id == filters.analyst_id)
    return query


def _count_case(condition):
    return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)


def _inactivity_condition(now: datetime):
    cutoff = now - timedelta(hours=ALERT_INACTIVITY_HOURS)
    recent_assignment = exists().where(and_(
        AlertAssignmentHistory.alert_id == Alert.id,
        AlertAssignmentHistory.created_at >= cutoff,
    ))
    recent_decision = exists().where(and_(
        AlertDecisionHistory.alert_id == Alert.id,
        or_(
            AlertDecisionHistory.initiated_at >= cutoff,
            AlertDecisionHistory.reviewed_at >= cutoff,
            AlertDecisionHistory.applied_at >= cutoff,
        ),
    ))
    active = or_(Alert.statut.is_(None), ~Alert.statut.in_(TERMINAL_ALERT_STATUSES))
    return and_(
        active,
        Alert.created_at < cutoff,
        or_(Alert.assigned_at.is_(None), Alert.assigned_at < cutoff),
        or_(Alert.supervisor_escalated_at.is_(None), Alert.supervisor_escalated_at < cutoff),
        or_(Alert.treated_at.is_(None), Alert.treated_at < cutoff),
        not_(recent_assignment),
        not_(recent_decision),
    )


def _distribution(query: Query, column, label: str) -> list[dict]:
    rows = query.with_entities(
        column.label("key"), func.count(Alert.id).label("count"),
    ).group_by(column).order_by(func.count(Alert.id).desc(), column).all()
    total = sum(int(row.count) for row in rows)
    return [
        {
            "label": row.key or label,
            "count": int(row.count),
            "percent": round((int(row.count) / total * 100) if total else 0, 1),
        }
        for row in rows
    ]


def _duration_metrics(db: Session, filters: ReportingFilters) -> tuple[dict, list[tuple]]:
    query = _apply_dimensions(db.query(Alert), filters, include_period=False).filter(
        Alert.statut.in_(FINAL_DECISION_STATUSES),
        Alert.treated_at.is_not(None),
        Alert.treated_at >= filters.start_at,
        Alert.treated_at < filters.end_at,
    )
    rows = query.with_entities(
        Alert.assigned_to_user_id, Alert.statut, Alert.created_at, Alert.treated_at,
    ).all()
    durations = [
        max(0.0, (treated_at - created_at).total_seconds() / 3600)
        for _, _, created_at, treated_at in rows
        if created_at and treated_at
    ]
    return {
        "average_hours": round(sum(durations) / len(durations), 2) if durations else 0.0,
        "median_hours": round(float(median(durations)), 2) if durations else 0.0,
        "closed_volume": sum(status == "CLOTUREE" for _, status, _, _ in rows),
    }, rows


def _decision_rates(db: Session, filters: ReportingFilters) -> dict:
    query = db.query(AlertDecisionHistory).join(
        Alert, Alert.id == AlertDecisionHistory.alert_id,
    ).filter(
        AlertDecisionHistory.decision_status.in_(APPLIED_HISTORY_STATUSES),
        AlertDecisionHistory.applied_at >= filters.start_at,
        AlertDecisionHistory.applied_at < filters.end_at,
        AlertDecisionHistory.requested_status.in_(("FAUX_POSITIF", "CONFIRMEE")),
    )
    query = _apply_dimensions(query, filters, include_period=False)
    rows = query.with_entities(
        AlertDecisionHistory.requested_status,
        func.count(func.distinct(AlertDecisionHistory.alert_id)),
    ).group_by(AlertDecisionHistory.requested_status).all()
    counts = {status: int(count) for status, count in rows}
    decided = counts.get("FAUX_POSITIF", 0) + counts.get("CONFIRMEE", 0)
    return {
        "decided": decided,
        "false_positive_rate": round(counts.get("FAUX_POSITIF", 0) / decided * 100, 1) if decided else 0.0,
        "confirmation_rate": round(counts.get("CONFIRMEE", 0) / decided * 100, 1) if decided else 0.0,
    }


def _report_kpis(db: Session, filters: ReportingFilters, current_time: datetime) -> dict:
    base_query = _apply_dimensions(db.query(Alert), filters, include_period=True)
    sla_conditions = sla_sql_conditions(now=current_time)
    row = base_query.with_entities(
        func.count(Alert.id),
        _count_case(Alert.statut == "GENEREE"),
        _count_case(Alert.statut == "EN_COURS"),
        _count_case(Alert.statut == "CONFIRMEE"),
        _count_case(Alert.statut == "FAUX_POSITIF"),
        _count_case(Alert.statut == "CLOTUREE"),
        _count_case(Alert.niveau_alerte == "ALERTE_EXACTE"),
        _count_case(and_(sla_conditions["active"], Alert.assigned_to_user_id.is_(None))),
        _count_case(and_(sla_conditions["active"], Alert.supervisor_escalated_at.is_not(None))),
        _count_case(sla_conditions[SLA_OK]),
        _count_case(sla_conditions[SLA_NEAR]),
        _count_case(sla_conditions[SLA_BREACHED]),
        _count_case(_inactivity_condition(current_time)),
    ).one()
    names = (
        "total", "generated", "in_progress", "confirmed", "false_positive", "closed",
        "critical", "unassigned", "escalated", "within_sla", "near_sla", "out_sla",
        "inactive",
    )
    return {name: int(value or 0) for name, value in zip(names, row)}


def _analyst_supervision(
    db: Session,
    base_query: Query,
    filters: ReportingFilters,
    duration_rows: list[tuple],
    sla_conditions: dict,
) -> tuple[list[dict], list[dict]]:
    analysts = db.query(User).filter(
        User.role == ROLE_ANALYSTE_CONFORMITE,
        User.statut == "ACTIF",
    ).order_by(User.full_name, User.username).all()
    grouped = base_query.filter(Alert.assigned_to_user_id.is_not(None)).with_entities(
        Alert.assigned_to_user_id,
        _count_case(sla_conditions["active"]).label("active"),
        _count_case(sla_conditions[SLA_BREACHED]).label("out_sla"),
    ).group_by(Alert.assigned_to_user_id).all()
    counts = {
        str(user_id): {
            "active": int(active), "out_sla": int(out_sla), "closed": 0,
        }
        for user_id, active, out_sla in grouped
    }
    durations_by_analyst: dict[str, list[float]] = {}
    closed_by_analyst: dict[str, int] = {}
    for user_id, status, created_at, treated_at in duration_rows:
        if not user_id or not created_at or not treated_at:
            continue
        key = str(user_id)
        durations_by_analyst.setdefault(key, []).append(
            max(0.0, (treated_at - created_at).total_seconds() / 3600),
        )
        if status == "CLOTUREE":
            closed_by_analyst[key] = closed_by_analyst.get(key, 0) + 1
    result = []
    options = [
        {
            "id": str(analyst.id),
            "full_name": analyst.full_name or analyst.username,
            "username": analyst.username,
        }
        for analyst in analysts
    ]
    for analyst in analysts:
        if filters.analyst_id and analyst.id != filters.analyst_id:
            continue
        key = str(analyst.id)
        item = counts.get(key, {"active": 0, "out_sla": 0, "closed": 0})
        item["closed"] = closed_by_analyst.get(key, 0)
        durations = durations_by_analyst.get(key, [])
        result.append({
            "id": key,
            "full_name": analyst.full_name or analyst.username,
            "username": analyst.username,
            **item,
            "average_hours": round(sum(durations) / len(durations), 2) if durations else 0.0,
        })
    return result, options


def _trends(db: Session, filters: ReportingFilters) -> list[dict]:
    days = []
    current = filters.start_date
    while current <= filters.end_date:
        days.append(current)
        current += timedelta(days=1)
    trend = {
        day.isoformat(): {
            "date": day.isoformat(), "created": 0, "closed": 0,
            "false_positive": 0, "confirmed": 0,
        }
        for day in days
    }
    created_query = _apply_dimensions(db.query(Alert), filters, include_period=True)
    created_rows = created_query.with_entities(
        func.date(Alert.created_at), func.count(Alert.id),
    ).group_by(func.date(Alert.created_at)).all()
    for day, count in created_rows:
        key = str(day)
        if key in trend:
            trend[key]["created"] = int(count)

    decision_query = db.query(AlertDecisionHistory).join(
        Alert, Alert.id == AlertDecisionHistory.alert_id,
    ).filter(
        AlertDecisionHistory.decision_status.in_(APPLIED_HISTORY_STATUSES),
        AlertDecisionHistory.applied_at >= filters.start_at,
        AlertDecisionHistory.applied_at < filters.end_at,
        AlertDecisionHistory.requested_status.in_(FINAL_DECISION_STATUSES),
    )
    decision_query = _apply_dimensions(decision_query, filters, include_period=False)
    decision_rows = decision_query.with_entities(
        func.date(AlertDecisionHistory.applied_at),
        AlertDecisionHistory.requested_status,
        func.count(func.distinct(AlertDecisionHistory.alert_id)),
    ).group_by(
        func.date(AlertDecisionHistory.applied_at),
        AlertDecisionHistory.requested_status,
    ).all()
    keys = {"CLOTUREE": "closed", "FAUX_POSITIF": "false_positive", "CONFIRMEE": "confirmed"}
    for day, status, count in decision_rows:
        key = str(day)
        if key in trend:
            trend[key][keys[status]] = int(count)
    return list(trend.values())


def build_compliance_report(
    db: Session,
    filters: ReportingFilters,
    *,
    now: datetime | None = None,
) -> dict:
    current_time = now or datetime.utcnow()
    base_query = _apply_dimensions(db.query(Alert), filters, include_period=True)
    sla_conditions = sla_sql_conditions(now=current_time)
    kpis = _report_kpis(db, filters, current_time)
    performance, duration_rows = _duration_metrics(db, filters)
    performance.update(_decision_rates(db, filters))

    analysts, analyst_options = _analyst_supervision(
        db, base_query, filters, duration_rows, sla_conditions,
    )
    sources = [
        row[0] for row in db.query(Alert.source_liste)
        .filter(Alert.source_liste.is_not(None))
        .group_by(Alert.source_liste).order_by(Alert.source_liste).all()
    ]
    statuses = [
        row[0] for row in db.query(Alert.statut)
        .filter(Alert.statut.is_not(None))
        .group_by(Alert.statut).order_by(Alert.statut).all()
    ]
    return {
        "filters": filters,
        "kpis": kpis,
        "performance": performance,
        "distributions": {
            "sources": _distribution(base_query, Alert.source_liste, "Source inconnue"),
            "levels": _distribution(base_query, Alert.niveau_alerte, "Niveau inconnu"),
            "matching_types": _distribution(base_query, Alert.matching_type, "Type inconnu"),
            "statuses": _distribution(base_query, Alert.statut, "Statut inconnu"),
        },
        "analysts": analysts,
        "trends": _trends(db, filters),
        "options": {"sources": sources, "statuses": statuses, "analysts": analyst_options},
        "inactivity_hours": ALERT_INACTIVITY_HOURS,
    }


def previous_reporting_filters(filters: ReportingFilters) -> ReportingFilters:
    """Return the immediately preceding period with identical dimensions."""
    duration = filters.end_at - filters.start_at
    return ReportingFilters(
        period="previous",
        start_at=filters.start_at - duration,
        end_at=filters.start_at,
        source=filters.source,
        status=filters.status,
        analyst_id=filters.analyst_id,
    )


def _terminal_before(as_of: datetime):
    history_terminal = exists().where(and_(
        AlertDecisionHistory.alert_id == Alert.id,
        AlertDecisionHistory.decision_status.in_(APPLIED_HISTORY_STATUSES),
        AlertDecisionHistory.requested_status.in_(TERMINAL_ALERT_STATUSES),
        AlertDecisionHistory.applied_at.is_not(None),
        AlertDecisionHistory.applied_at < as_of,
    ))
    legacy_terminal = and_(
        Alert.statut.is_not(None),
        Alert.statut.in_(TERMINAL_ALERT_STATUSES),
        or_(Alert.treated_at.is_(None), Alert.treated_at < as_of),
    )
    return or_(history_terminal, legacy_terminal)


def _backlog_snapshot(db: Session, filters: ReportingFilters, as_of: datetime) -> dict:
    """Aggregate the backlog as it stood at ``as_of`` without loading alerts."""
    active_at = not_(_terminal_before(as_of))
    query = _apply_dimensions(db.query(Alert), filters, include_period=False).filter(
        Alert.created_at.is_not(None),
        Alert.created_at < as_of,
    )
    sla_conditions = sla_sql_conditions(now=as_of, active_condition=active_at)
    one_day = as_of - timedelta(days=1)
    three_days = as_of - timedelta(days=3)
    seven_days = as_of - timedelta(days=7)
    row = query.with_entities(
        _count_case(active_at),
        _count_case(and_(active_at, Alert.niveau_alerte == "ALERTE_EXACTE")),
        _count_case(sla_conditions[SLA_BREACHED]),
        _count_case(and_(active_at, Alert.created_at >= one_day)),
        _count_case(and_(active_at, Alert.created_at < one_day, Alert.created_at >= three_days)),
        _count_case(and_(active_at, Alert.created_at < three_days, Alert.created_at >= seven_days)),
        _count_case(and_(active_at, Alert.created_at < seven_days)),
    ).one()
    total, critical, out_sla, less_24h, one_to_three, three_to_seven, over_seven = (
        int(value or 0) for value in row
    )
    return {
        "total": total,
        "critical": critical,
        "out_sla": out_sla,
        "sla_compliance_rate": round((total - out_sla) / total * 100, 1) if total else 100.0,
        "age_buckets": [
            {"label": "Moins de 24 h", "count": less_24h},
            {"label": "1 à 3 jours", "count": one_to_three},
            {"label": "3 à 7 jours", "count": three_to_seven},
            {"label": "Plus de 7 jours", "count": over_seven},
        ],
    }


def _period_summary(db: Session, filters: ReportingFilters, as_of: datetime) -> dict:
    created = int(
        _apply_dimensions(db.query(func.count(Alert.id)), filters, include_period=True).scalar() or 0
    )
    performance, _ = _duration_metrics(db, filters)
    performance.update(_decision_rates(db, filters))
    backlog = _backlog_snapshot(db, filters, as_of)
    closed = int(performance["closed_volume"])
    return {
        "backlog_total": backlog["total"],
        "backlog_critical": backlog["critical"],
        "backlog_out_sla": backlog["out_sla"],
        "created": created,
        "closed": closed,
        "closure_rate": round(closed / created * 100, 1) if created else 0.0,
        "false_positive_rate": performance["false_positive_rate"],
        "confirmation_rate": performance["confirmation_rate"],
        "average_hours": performance["average_hours"],
        "median_hours": performance["median_hours"],
        "sla_compliance_rate": backlog["sla_compliance_rate"],
        "age_buckets": backlog["age_buckets"],
    }


def _variation(current, previous) -> dict:
    absolute = round(float(current) - float(previous), 2)
    if float(previous) == 0:
        percent = 0.0 if float(current) == 0 else None
    else:
        percent = round(absolute / abs(float(previous)) * 100, 1)
    return {
        "current": current,
        "previous": previous,
        "absolute": absolute,
        "percent": percent,
    }


def _management_attention(current: dict, previous: dict) -> list[dict]:
    points = []
    if current["backlog_critical"]:
        points.append({
            "level": "critical",
            "message": f'{current["backlog_critical"]} alerte(s) critique(s) dans le backlog.',
        })
    if current["backlog_out_sla"]:
        points.append({
            "level": "warning",
            "message": f'{current["backlog_out_sla"]} alerte(s) hors SLA à traiter en priorité.',
        })
    if current["created"] > current["closed"]:
        points.append({
            "level": "warning",
            "message": "Le volume d’alertes créées dépasse le volume clôturé sur la période.",
        })
    if current["closure_rate"] < previous["closure_rate"]:
        points.append({
            "level": "info",
            "message": "Le taux de clôture est inférieur à celui de la période précédente.",
        })
    if not points:
        points.append({"level": "ok", "message": "Aucun point d’attention majeur détecté."})
    return points


def build_management_report(
    db: Session,
    filters: ReportingFilters,
    *,
    now: datetime | None = None,
) -> dict:
    """Build the management view from LOT 5A aggregates and historical snapshots."""
    current_time = now or datetime.utcnow()
    current_report = build_compliance_report(db, filters, now=current_time)
    current_snapshot_at = min(filters.end_at, current_time)
    current_backlog = _backlog_snapshot(db, filters, current_snapshot_at)
    current = {
        "backlog_total": current_backlog["total"],
        "backlog_critical": current_backlog["critical"],
        "backlog_out_sla": current_backlog["out_sla"],
        "created": current_report["kpis"]["total"],
        "closed": current_report["performance"]["closed_volume"],
        "false_positive_rate": current_report["performance"]["false_positive_rate"],
        "confirmation_rate": current_report["performance"]["confirmation_rate"],
        "average_hours": current_report["performance"]["average_hours"],
        "median_hours": current_report["performance"]["median_hours"],
        "sla_compliance_rate": current_backlog["sla_compliance_rate"],
        "closure_rate": round(
            current_report["performance"]["closed_volume"] / current_report["kpis"]["total"] * 100,
            1,
        ) if current_report["kpis"]["total"] else 0.0,
        "age_buckets": current_backlog["age_buckets"],
    }
    previous_filters = previous_reporting_filters(filters)
    previous = _period_summary(db, previous_filters, previous_filters.end_at)
    comparisons = {
        key: _variation(current[key], previous[key])
        for key in MANAGEMENT_COMPARISON_KEYS
    }
    return {
        "filters": filters,
        "previous_filters": previous_filters,
        "current": current,
        "previous": previous,
        "comparisons": comparisons,
        "top_sources": current_report["distributions"]["sources"][:5],
        "top_matching_types": current_report["distributions"]["matching_types"][:5],
        "analysts": current_report["analysts"],
        "trends": current_report["trends"],
        "attention_points": _management_attention(current, previous),
        "options": current_report["options"],
    }


def management_export_rows(report: dict) -> list[list]:
    """Return aggregate-only rows shared by CSV and XLSX exports."""
    labels = {
        "backlog_total": "Backlog total",
        "backlog_critical": "Backlog critique",
        "backlog_out_sla": "Backlog hors SLA",
        "created": "Alertes créées",
        "closed": "Alertes clôturées",
        "closure_rate": "Taux de clôture (%)",
        "false_positive_rate": "Taux de faux positifs (%)",
        "confirmation_rate": "Taux de confirmation (%)",
        "average_hours": "Délai moyen (h)",
        "median_hours": "Délai médian (h)",
        "sla_compliance_rate": "Respect SLA (%)",
    }
    rows = [
        ["Synthèse management BLACKMODULE"],
        ["Période courante", report["filters"].start_date, report["filters"].end_date],
        ["Période précédente", report["previous_filters"].start_date, report["previous_filters"].end_date],
        [],
        ["Indicateur", "Période courante", "Période précédente", "Variation absolue", "Variation (%)"],
    ]
    for key in MANAGEMENT_COMPARISON_KEYS:
        item = report["comparisons"][key]
        rows.append([labels[key], item["current"], item["previous"], item["absolute"], item["percent"]])
    rows.extend([[], ["Backlog par ancienneté", "Volume"]])
    rows.extend([[item["label"], item["count"]] for item in report["current"]["age_buckets"]])
    rows.extend([[], ["Top sources", "Volume", "Part (%)"]])
    rows.extend([[item["label"], item["count"], item["percent"]] for item in report["top_sources"]])
    rows.extend([[], ["Top types de matching", "Volume", "Part (%)"]])
    rows.extend([[item["label"], item["count"], item["percent"]] for item in report["top_matching_types"]])
    rows.extend([[], ["Analyste", "Identifiant", "Dossiers actifs", "Hors SLA", "Clôturés", "Délai moyen (h)"]])
    rows.extend([
        [
            item["full_name"], item["username"], item["active"],
            item["out_sla"], item["closed"], item["average_hours"],
        ]
        for item in report["analysts"]
    ])
    rows.extend([[], ["Date", "Créées", "Clôturées", "Faux positifs", "Confirmées"]])
    rows.extend([
        [item["date"], item["created"], item["closed"], item["false_positive"], item["confirmed"]]
        for item in report["trends"]
    ])
    return rows
