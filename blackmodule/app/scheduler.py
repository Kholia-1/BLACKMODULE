import logging
import time

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import text

from app.config import MONITORING_HEALTHCHECK_INTERVAL_SECONDS
from app.database import SessionLocal, engine
from app.services.list_update_service import (
    auto_update_ofac_sdn,
    auto_update_ofac_consolidated,
    auto_update_france_gel,
    auto_update_eu_xml,
    auto_update_un_xml,
    auto_update_uksl_csv,
    emit_list_freshness_alerts,
    interrupted_official_updates,
    mark_interrupted_update_failed,
    OFFICIAL_SOURCES,
)
from app.services.notification_service import dispatch_corrective_action_notifications
from app.services.external_notification_service import process_pending_email_deliveries
from app.services.observability_service import monitoring_registry, record_health


scheduler = BackgroundScheduler()
logger = logging.getLogger("blackmodule.scheduler")


def _job_finished(job_id: str, started_at: float, success: bool) -> None:
    monitoring_registry.record_scheduler_job(
        job_id, success, (time.perf_counter() - started_at) * 1000
    )


MANUAL_UPDATE_FUNCTIONS = {
    "OFAC_SDN": auto_update_ofac_sdn,
    "OFAC_CONSOLIDATED": auto_update_ofac_consolidated,
    "FR_GEL": auto_update_france_gel,
    "UE": auto_update_eu_xml,
    "ONU": auto_update_un_xml,
    "UKSL": auto_update_uksl_csv,
}


def run_job(job_name: str, update_function, imported_by: str):
    started_at = time.perf_counter()
    db = SessionLocal()

    try:
        logger.info(
            "Scheduler job started.",
            extra={"event": "scheduler_job_started", "job_id": job_name},
        )

        update_function(
            db=db,
            imported_by=imported_by
        )

        _job_finished(job_name, started_at, True)
        logger.info(
            "Scheduler job completed.",
            extra={"event": "scheduler_job_completed", "job_id": job_name},
        )

    except Exception as error:
        _job_finished(job_name, started_at, False)
        logger.error(
            "Scheduler job failed.",
            extra={
                "event": "scheduler_job_failed",
                "job_id": job_name,
                "error_type": type(error).__name__,
            },
        )

    finally:
        db.close()


def run_manual_update(source_key: str, batch_id, imported_by: str) -> None:
    started_at = time.perf_counter()
    job_id = f"manual_update_{source_key}"
    db = SessionLocal()
    try:
        MANUAL_UPDATE_FUNCTIONS[source_key](
            db=db, imported_by=imported_by, existing_batch_id=batch_id,
        )
        _job_finished(job_id, started_at, True)
    except Exception as error:
        db.rollback()
        mark_interrupted_update_failed(db, batch_id, source_key, imported_by, error)
        _job_finished(job_id, started_at, False)
        logger.error(
            "Scheduled list update failed.",
            extra={
                "event": "scheduler_job_failed",
                "job_id": job_id,
                "error_type": type(error).__name__,
            },
        )
    finally:
        db.close()


def enqueue_manual_update(source_key: str, batch_id, imported_by: str) -> None:
    """Use the in-process scheduler already used for official automatic jobs."""
    scheduler.add_job(
        run_manual_update,
        trigger="date",
        id=f"manual_update_{batch_id}",
        replace_existing=False,
        args=[source_key, batch_id, imported_by],
    )


def run_queued_restore(approval_id: str) -> None:
    started_at = time.perf_counter()
    job_id = "queued_restore"
    from app.services.approval_service import process_queued_restore
    db = SessionLocal()
    try:
        process_queued_restore(db, approval_id)
        _job_finished(job_id, started_at, True)
    except Exception as error:
        db.rollback()
        _job_finished(job_id, started_at, False)
        logger.error(
            "Scheduled restore failed.",
            extra={
                "event": "scheduler_job_failed",
                "job_id": job_id,
                "error_type": type(error).__name__,
            },
        )
    finally:
        db.close()


def enqueue_restore_approval(approval_id: str) -> None:
    scheduler.add_job(
        run_queued_restore, trigger="date", id=f"restore_{approval_id}",
        replace_existing=False, args=[approval_id],
    )


def recover_interrupted_work() -> tuple[int, int]:
    """Requeue durable EN_COURS work after an application restart."""
    from app.models import ApprovalRequest
    from app.services.approval_service import IN_PROGRESS, OP_LIST_VERSION_RESTORE
    db = SessionLocal()
    try:
        updates = [
            (batch.source_liste, batch.id, batch.imported_by or "SCHEDULER")
            for batch in interrupted_official_updates(db)
        ]
        restores = [
            approval.id for approval in db.query(ApprovalRequest).filter(
                ApprovalRequest.status == IN_PROGRESS,
                ApprovalRequest.operation_type == OP_LIST_VERSION_RESTORE,
            ).all()
        ]
    finally:
        db.close()
    source_keys = {source.source_liste: key for key, source in OFFICIAL_SOURCES.items()}
    for source_liste, batch_id, imported_by in updates:
        enqueue_manual_update(source_keys[source_liste], batch_id, imported_by)
    for approval_id in restores:
        enqueue_restore_approval(str(approval_id))
    return len(updates), len(restores)


def run_freshness_check():
    started_at = time.perf_counter()
    job_id = "list_freshness_check"
    db = SessionLocal()
    try:
        alerts = emit_list_freshness_alerts(db=db)
        _job_finished(job_id, started_at, True)
        logger.info(
            "List freshness check completed.",
            extra={
                "event": "scheduler_job_completed",
                "job_id": job_id,
                "result_count": len(alerts),
            },
        )
    except Exception as error:
        _job_finished(job_id, started_at, False)
        logger.error(
            "List freshness check failed.",
            extra={
                "event": "scheduler_job_failed",
                "job_id": job_id,
                "error_type": type(error).__name__,
            },
        )
    finally:
        db.close()


def run_corrective_action_notification_check():
    """Deliver deduplicated deadline reminders and overdue escalations."""
    started_at = time.perf_counter()
    job_id = "corrective_action_notifications"
    db = SessionLocal()
    try:
        result = dispatch_corrective_action_notifications(db)
        db.commit()
        _job_finished(job_id, started_at, True)
        logger.info(
            "Corrective action notification check completed.",
            extra={
                "event": "scheduler_job_completed",
                "job_id": job_id,
                "result_count": sum(result[key] for key in ("due_soon", "overdue", "escalated")),
            },
        )
    except Exception as error:
        db.rollback()
        _job_finished(job_id, started_at, False)
        logger.error(
            "Corrective action notification check failed.",
            extra={
                "event": "scheduler_job_failed",
                "job_id": job_id,
                "error_type": type(error).__name__,
            },
        )
    finally:
        db.close()


def run_external_notification_delivery():
    """Process the optional durable e-mail outbox without affecting in-app flow."""
    started_at = time.perf_counter()
    job_id = "external_notification_delivery"
    db = SessionLocal()
    try:
        result = process_pending_email_deliveries(db)
        db.commit()
        _job_finished(job_id, started_at, True)
        if result["enabled"]:
            logger.info(
                "External notification delivery completed.",
                extra={
                    "event": "scheduler_job_completed",
                    "job_id": job_id,
                    "result_count": result["sent"] + result["failed"],
                },
            )
    except Exception as error:
        db.rollback()
        _job_finished(job_id, started_at, False)
        logger.error(
            "External notification delivery failed.",
            extra={
                "event": "scheduler_job_failed",
                "job_id": job_id,
                "error_type": type(error).__name__,
            },
        )
    finally:
        db.close()


def run_health_supervision_check():
    """Probe dependencies and expose only component-level health state."""
    started_at = time.perf_counter()
    database_ready = False
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1")).scalar()
        database_ready = True
    except Exception as error:
        logger.error(
            "Database health probe failed.",
            extra={
                "event": "health_probe_failed",
                "component": "database",
                "error_type": type(error).__name__,
            },
        )
    record_health("database", database_ready)
    record_health("scheduler", scheduler.running)
    success = database_ready and scheduler.running
    _job_finished("health_supervision", started_at, success)


def start_scheduler():
    if scheduler.running:
        return

    scheduler.add_job(
        run_job,
        trigger="cron",
        hour=2,
        minute=0,
        id="auto_update_ofac_sdn",
        replace_existing=True,
        args=["OFAC SDN", auto_update_ofac_sdn, "DAILY_SCHEDULER"]
    )

    scheduler.add_job(
        run_job,
        trigger="cron",
        hour=2,
        minute=15,
        id="auto_update_ofac_consolidated",
        replace_existing=True,
        args=["OFAC Consolidated", auto_update_ofac_consolidated, "DAILY_SCHEDULER"]
    )

    scheduler.add_job(
        run_job,
        trigger="cron",
        hour=2,
        minute=30,
        id="auto_update_france_gel",
        replace_existing=True,
        args=["France Gel", auto_update_france_gel, "DAILY_SCHEDULER"]
    )

    scheduler.add_job(
        run_job,
        trigger="cron",
        day_of_week="mon",
        hour=3,
        minute=0,
        id="auto_update_eu_xml",
        replace_existing=True,
        args=["UE Financial Sanctions", auto_update_eu_xml, "WEEKLY_SCHEDULER"]
    )

    scheduler.add_job(
        run_job,
        trigger="cron",
        day_of_week="mon",
        hour=3,
        minute=15,
        id="auto_update_un_xml",
        replace_existing=True,
        args=["ONU UNSC", auto_update_un_xml, "WEEKLY_SCHEDULER"]
    )

    scheduler.add_job(
        run_job,
        trigger="cron",
        day=1,
        hour=3,
        minute=30,
        id="auto_update_uksl_csv",
        replace_existing=True,
        args=["UK Sanctions List", auto_update_uksl_csv, "MONTHLY_SCHEDULER"]
    )

    scheduler.add_job(
        run_freshness_check,
        trigger="cron",
        hour=4,
        minute=0,
        id="list_freshness_check",
        replace_existing=True,
    )

    scheduler.add_job(
        run_corrective_action_notification_check,
        trigger="cron",
        minute=10,
        id="corrective_action_notifications",
        replace_existing=True,
    )

    scheduler.add_job(
        run_external_notification_delivery,
        trigger="cron",
        minute="*/5",
        id="external_notification_delivery",
        replace_existing=True,
    )

    scheduler.add_job(
        run_health_supervision_check,
        trigger="interval",
        seconds=MONITORING_HEALTHCHECK_INTERVAL_SECONDS,
        id="health_supervision",
        replace_existing=True,
    )

    scheduler.start()

    recovered_updates, recovered_restores = recover_interrupted_work()
    if recovered_updates or recovered_restores:
        logger.info(
            "Interrupted work recovery completed.",
            extra={
                "event": "scheduler_recovery_completed",
                "job_id": "startup_recovery",
                "result_count": recovered_updates + recovered_restores,
            },
        )

    logger.info(
        "Scheduler started.",
        extra={"event": "scheduler_started", "job_id": "scheduler"},
    )


def get_scheduler_status():
    jobs = []

    for job in scheduler.get_jobs():
        jobs.append({
            "id": job.id,
            "next_run_time": job.next_run_time
        })

    return {
        "running": scheduler.running,
        "jobs": jobs
    }

