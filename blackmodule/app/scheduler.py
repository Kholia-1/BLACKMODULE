from apscheduler.schedulers.background import BackgroundScheduler

from app.database import SessionLocal
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


scheduler = BackgroundScheduler()


MANUAL_UPDATE_FUNCTIONS = {
    "OFAC_SDN": auto_update_ofac_sdn,
    "OFAC_CONSOLIDATED": auto_update_ofac_consolidated,
    "FR_GEL": auto_update_france_gel,
    "UE": auto_update_eu_xml,
    "ONU": auto_update_un_xml,
    "UKSL": auto_update_uksl_csv,
}


def run_job(job_name: str, update_function, imported_by: str):
    db = SessionLocal()

    try:
        print(f"[BLACKMODULE] Début job : {job_name}")

        update_function(
            db=db,
            imported_by=imported_by
        )

        print(f"[BLACKMODULE] Fin job : {job_name}")

    except Exception as e:
        print(f"[BLACKMODULE] Erreur job {job_name} : {e}")

    finally:
        db.close()


def run_manual_update(source_key: str, batch_id, imported_by: str) -> None:
    db = SessionLocal()
    try:
        MANUAL_UPDATE_FUNCTIONS[source_key](
            db=db, imported_by=imported_by, existing_batch_id=batch_id,
        )
    except Exception as error:
        db.rollback()
        mark_interrupted_update_failed(db, batch_id, source_key, imported_by, error)
        print(f"[BLACKMODULE] Erreur mise a jour programmee {source_key}: {error}")
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
    from app.services.approval_service import process_queued_restore
    db = SessionLocal()
    try:
        process_queued_restore(db, approval_id)
    except Exception as error:
        db.rollback()
        print(f"[BLACKMODULE] Erreur restauration programmee {approval_id}: {error}")
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
    db = SessionLocal()
    try:
        alerts = emit_list_freshness_alerts(db=db)
        print(f"[BLACKMODULE] Controle de fraicheur des listes: {len(alerts)} alerte(s).")
    except Exception as error:
        print(f"[BLACKMODULE] Erreur controle de fraicheur des listes: {error}")
    finally:
        db.close()


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

    scheduler.start()

    recovered_updates, recovered_restores = recover_interrupted_work()
    if recovered_updates or recovered_restores:
        print(f"[BLACKMODULE] Reprise: {recovered_updates} mise(s) à jour, {recovered_restores} restauration(s).")

    print("[BLACKMODULE] Scheduler multi-listes actif.")


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

