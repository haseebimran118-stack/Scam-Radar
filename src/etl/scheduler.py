from apscheduler.schedulers.blocking import BlockingScheduler
from run_pipeline import run_pipeline


def safe_run_pipeline():
    try:
        print("\nStarting scheduled pipeline...")
        run_pipeline()

    except Exception as error:
        print(f"Pipeline failed: {error}")


def start_scheduler():
    scheduler = BlockingScheduler(
        timezone="Asia/Karachi"
    )

    # Run immediately when scheduler starts
    scheduler.add_job(
        safe_run_pipeline,
        trigger="date",
        id="initial_pipeline"
    )

    # Repeat every hour
    scheduler.add_job(
        safe_run_pipeline,
        trigger="interval",
        hours=1,
        id="scam_radar_pipeline",
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    print("Scam Radar scheduler started.")
    print("Timezone: Asia/Karachi")
    print("Pipeline runs immediately and every hour.")

    try:
        scheduler.start()

    except (KeyboardInterrupt, SystemExit):
        print("Scheduler stopped.")
        scheduler.shutdown()


if __name__ == "__main__":
    start_scheduler()