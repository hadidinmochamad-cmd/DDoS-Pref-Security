import time
from log_watcher import fetch_new_events
from unified_platform import process_events
from report_generator import generate_report

def run_live_pipeline(interval_seconds: int = 5):
    print("=" * 60)
    print(f"LIVE INPUT DAEMON STARTED (Polling every {interval_seconds}s)")
    print("=" * 60)

    last_position = 0

    try:
        while True:
            events, last_position = fetch_new_events(last_position)
            
            if not events.empty:
                print(f"\n[LIVE] Found {len(events)} new raw log event(s)...")
                incidents = process_events(events)
                print(f"[LIVE] Incident Store Updated. Total Incidents: {len(incidents)}")
                generate_report()
            else:
                print(".", end="", flush=True)  # Indicator heartbeat

            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        print("\n\n[LIVE] Monitoring Daemon Stopped by User.")

if __name__ == "__main__":
    run_live_pipeline(interval_seconds=3)