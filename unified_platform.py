from __future__ import annotations

import json
from pathlib import Path
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo
import pandas as pd
import requests

# =========================================================
# CONFIG & PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

INCIDENT_FILE = DATA_DIR / "unified_incidents.csv"
REPORT_FILE = DATA_DIR / "executive_report.csv"

# Masukkan Token dan Chat ID Telegram jika ingin mengaktifkan Notifikasi
TELEGRAM_BOT_TOKEN = "" 
TELEGRAM_CHAT_ID = ""

INCIDENT_COLUMNS = [
    "Incident ID",
    "Domain",
    "Prefix",
    "ASN",
    "Event Type",
    "Severity",
    "Status",
    "Opened At",
    "Resolved At",
]

EVENT_DOMAINS = {
    "TRAFFIC_SPIKE": "DDoS",
    "VOLUMETRIC_DDOS": "DDoS",
    "TCP_SYN_FLOOD": "DDoS",
    "UDP_FLOOD": "DDoS",
    "ICMP_FLOOD": "DDoS",
    "BGP_HIJACK": "BGP/RPKI",
    "RPKI_INVALID": "BGP/RPKI",
    "PREFIX_OUTAGE": "Prefix",
    "PREFIX_FLAPPING": "Prefix",
}


# =========================================================
# HELPER: ZONA WAKTU INDONESIA (WIB)
# =========================================================

def convert_to_wib(utc_time_str: str) -> str:
    """Mengonversi ISO timestamp (+00:00) ke format lokal WIB (+07:00)."""
    if not utc_time_str or utc_time_str in ["None", "nan", ""]:
        return ""
    
    try:
        dt = datetime.fromisoformat(utc_time_str)
        dt_wib = dt.astimezone(ZoneInfo("Asia/Jakarta"))
        return dt_wib.strftime("%Y-%m-%d %H:%M:%S WIB")
    except Exception:
        return str(utc_time_str)


# =========================================================
# NOTIFIER MODULE
# =========================================================

def send_telegram_alert(message: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[ALERT LOCAL LOG]: {message}")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as err:
        print(f"[NOTIFIER ERROR]: Gagal mengirim pesan Telegram - {err}")


# =========================================================
# CORE ENGINE
# =========================================================

def load_incidents() -> pd.DataFrame:
    if INCIDENT_FILE.exists():
        df = pd.read_csv(INCIDENT_FILE)
        df["Resolved At"] = df["Resolved At"].fillna("").astype(str)
        df["Opened At"] = df["Opened At"].fillna("").astype(str)
        return df
    return pd.DataFrame(columns=INCIDENT_COLUMNS)


def save_incidents(df: pd.DataFrame) -> None:
    df.to_csv(INCIDENT_FILE, index=False)


def process_events(events: pd.DataFrame) -> pd.DataFrame:
    incidents = load_incidents()

    if events is None or events.empty:
        return incidents

    for _, event in events.iterrows():
        event_type = event.get("Event Type")
        severity = event.get("Severity")

        # Process Recovery
        if event_type == "RECOVERY":
            prefix = event.get("Prefix")
            asn = event.get("ASN")
            rec_domain = event.get("Domain")

            target_mask = (
                (incidents["Prefix"] == prefix)
                & (incidents["ASN"] == asn)
                & (incidents["Status"] == "OPEN")
            )
            if rec_domain:
                target_mask &= incidents["Domain"] == rec_domain

            if target_mask.any():
                incidents.loc[target_mask, "Status"] = "RESOLVED"
                incidents.loc[target_mask, "Resolved At"] = str(event.get("Timestamp"))
                
                for _, row in incidents[target_mask].iterrows():
                    time_wib = convert_to_wib(str(event.get("Timestamp")))
                    msg = (
                        f"🟢 *INCIDENT RESOLVED*\n"
                        f"• ID: `{row['Incident ID']}`\n"
                        f"• Domain: *{row['Domain']}*\n"
                        f"• Target: `{row['Prefix']}` ({row['ASN']})\n"
                        f"• Resolved At: `{time_wib}`"
                    )
                    send_telegram_alert(msg)
            continue

        if severity == "NORMAL" or event_type not in EVENT_DOMAINS:
            continue

        domain = EVENT_DOMAINS[event_type]
        prefix = event.get("Prefix")
        asn = event.get("ASN")
        event_time = str(event.get("Timestamp"))

        open_mask = (
            (incidents["Domain"] == domain)
            & (incidents["Prefix"] == prefix)
            & (incidents["ASN"] == asn)
            & (incidents["Status"] == "OPEN")
        )

        resolved_replay_mask = (
            (incidents["Domain"] == domain)
            & (incidents["Prefix"] == prefix)
            & (incidents["ASN"] == asn)
            & (incidents["Status"] == "RESOLVED")
            & (incidents["Opened At"] <= event_time)
            & (incidents["Resolved At"].astype(str) >= event_time)
        )

        if open_mask.any():
            incidents.loc[open_mask, "Event Type"] = event_type
            incidents.loc[open_mask, "Severity"] = severity
        elif resolved_replay_mask.any():
            continue
        else:
            new_id = f"INC-{domain[:3]}-{uuid.uuid4().hex[:8].upper()}"
            new_row = {
                "Incident ID": new_id,
                "Domain": domain,
                "Prefix": prefix,
                "ASN": asn,
                "Event Type": event_type,
                "Severity": severity,
                "Status": "OPEN",
                "Opened At": event_time,
                "Resolved At": "",
            }
            incidents = pd.concat([incidents, pd.DataFrame([new_row])], ignore_index=True)
            
            time_wib = convert_to_wib(event_time)
            msg = (
                f"🚨 *NEW INCIDENT DETECTED*\n"
                f"• ID: `{new_id}`\n"
                f"• Domain: *{domain}*\n"
                f"• Type: `{event_type}` ({severity})\n"
                f"• Target: `{prefix}` ({asn})\n"
                f"• Opened At: `{time_wib}`"
            )
            send_telegram_alert(msg)

    save_incidents(incidents)
    return incidents