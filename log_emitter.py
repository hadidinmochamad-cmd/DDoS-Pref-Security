import time
from pathlib import Path
from datetime import datetime, timezone

LOG_FILE = Path(__file__).resolve().parent / "data" / "network_live.log"
LOG_FILE.parent.mkdir(exist_ok=True)

# Contoh log mentah dari sistem monitoring
SIMULATED_LOGS = [
    "2026-08-17T04:40:00+00:00 [BGP_DAEMON] WARNING Prefix 157.85.223.0/24 hijacked by AS66666",
    "2026-08-17T04:41:00+00:00 [FASTNETMON] CRITICAL UDP flood detected on 157.85.223.0/24 target AS59132",
    "2026-08-17T04:43:00+00:00 [PING_CHECKER] ERROR Outage detected on 157.85.223.0/24 target AS59132",
    "2026-08-17T04:45:00+00:00 [FASTNETMON] INFO UDP flood attack mitigation finished on 157.85.223.0/24 target AS59132",
]

def emit_logs():
    print("[LOG EMITTER] Starting live network log stream simulation...")
    with open(LOG_FILE, "a") as f:
        for log in SIMULATED_LOGS:
            f.write(log + "\n")
            f.flush()
            print(f"[EMITTED]: {log}")
            time.sleep(3)  # Menulis log setiap 3 detik

if __name__ == "__main__":
    emit_logs()