import re
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
import pandas as pd

LOG_FILE = Path(__file__).resolve().parent / "data" / "network_live.log"


def parse_log_line(line: str) -> dict | None:
    """Mengubah baris mentah log menjadi struktur event platform."""
    line = line.strip()
    if not line:
        return None

    pattern = r"^(?P<timestamp>\S+)\s+\[(?P<source>\w+)\]\s+(?P<level>\w+)\s+(?P<message>.*)$"
    match = re.match(pattern, line)
    if not match:
        return None

    data = match.groupdict()
    msg = data["message"]
    timestamp = data["timestamp"]

    # Parsing BGP Hijack
    if "hijacked by" in msg:
        prefix = msg.split("Prefix ")[1].split(" ")[0]
        asn = msg.split("hijacked by ")[1]
        return {
            "Timestamp": timestamp,
            "Domain": "BGP/RPKI",
            "Event Type": "BGP_HIJACK",
            "Severity": "CRITICAL",
            "Prefix": prefix,
            "ASN": asn,
        }
    # Parsing DDoS (UDP Flood)
    elif "UDP flood detected" in msg:
        prefix = msg.split("on ")[1].split(" ")[0]
        asn = msg.split("target ")[1]
        return {
            "Timestamp": timestamp,
            "Domain": "DDoS",
            "Event Type": "UDP_FLOOD",
            "Severity": "CRITICAL",
            "Prefix": prefix,
            "ASN": asn,
        }
    # Parsing Prefix Outage
    elif "Outage detected" in msg:
        prefix = msg.split("on ")[1].split(" ")[0]
        asn = msg.split("target ")[1]
        return {
            "Timestamp": timestamp,
            "Domain": "Prefix",
            "Event Type": "PREFIX_OUTAGE",
            "Severity": "HIGH",
            "Prefix": prefix,
            "ASN": asn,
        }
    # Parsing Recovery / Attack Finished
    elif "finished" in msg or "RECOVERY" in msg:
        prefix = msg.split("on ")[1].split(" ")[0]
        asn = msg.split("target ")[1]
        return {
            "Timestamp": timestamp,
            "Domain": "DDoS",
            "Event Type": "RECOVERY",
            "Severity": "NORMAL",
            "Prefix": prefix,
            "ASN": asn,
        }

    return None


def fetch_new_events(last_position: int) -> tuple[pd.DataFrame, int]:
    """Membaca log dari offset posisi terakhir file log."""
    if not LOG_FILE.exists():
        return pd.DataFrame(), 0

    events = []
    with open(LOG_FILE, "r") as f:
        f.seek(last_position)
        lines = f.readlines()
        new_position = f.tell()

    for line in lines:
        parsed = parse_log_line(line)
        if parsed:
            events.append(parsed)

    return pd.DataFrame(events), new_position