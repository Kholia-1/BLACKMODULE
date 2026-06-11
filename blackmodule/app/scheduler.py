from apscheduler.schedulers.background import BackgroundScheduler

from app.database import SessionLocal
from app.services.list_update_service import (
    auto_update_ofac_sdn,
    auto_update_ofac_consolidated,
    auto_update_france_gel,
    auto_update_eu_xml,
    auto_update_un_xml,
)


scheduler = BackgroundScheduler()


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

    scheduler.start()

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