import time
import pandas as pd
from unified_platform import process_events, load_incidents
from report_generator import generate_report

PREFIX = "157.85.223.0/24"
ASN = "AS59132"

def build_simulated_stream():
    """Simulasi aliran event jaringan secara bertahap."""
    return [
        # Batch 1: BGP Hijack & DDoS Attack
        pd.DataFrame([
            {
                "Timestamp": "2026-08-17T04:05:00+00:00",
                "Domain": "BGP/RPKI",
                "Event Type": "BGP_HIJACK",
                "Severity": "CRITICAL",
                "Prefix": PREFIX,
                "ASN": "AS66666",
            },
            {
                "Timestamp": "2026-08-17T04:10:00+00:00",
                "Domain": "DDoS",
                "Event Type": "TRAFFIC_SPIKE",
                "Severity": "CRITICAL",
                "Prefix": PREFIX,
                "ASN": ASN,
            },
        ]),
        # Batch 2: TCP Flood & Prefix Outage
        pd.DataFrame([
            {
                "Timestamp": "2026-08-17T04:12:00+00:00",
                "Domain": "DDoS",
                "Event Type": "TCP_SYN_FLOOD",
                "Severity": "CRITICAL",
                "Prefix": PREFIX,
                "ASN": ASN,
            },
            {
                "Timestamp": "2026-08-17T04:15:00+00:00",
                "Domain": "Prefix",
                "Event Type": "PREFIX_OUTAGE",
                "Severity": "HIGH",
                "Prefix": PREFIX,
                "ASN": ASN,
            },
        ]),
        # Batch 3: Recovery All Domains
        pd.DataFrame([
            {
                "Timestamp": "2026-08-17T04:25:00+00:00",
                "Domain": "BGP/RPKI",
                "Event Type": "RECOVERY",
                "Severity": "NORMAL",
                "Prefix": PREFIX,
                "ASN": "AS66666",
            },
            {
                "Timestamp": "2026-08-17T04:30:00+00:00",
                "Domain": "DDoS",
                "Event Type": "RECOVERY",
                "Severity": "NORMAL",
                "Prefix": PREFIX,
                "ASN": ASN,
            },
            {
                "Timestamp": "2026-08-17T04:35:00+00:00",
                "Domain": "Prefix",
                "Event Type": "RECOVERY",
                "Severity": "NORMAL",
                "Prefix": PREFIX,
                "ASN": ASN,
            },
        ]),
    ]

def main():
    print("=" * 60)
    print("STARTING V15 UNIFIED SECURITY MONITORING ENGINE")
    print("=" * 60)

    batches = build_simulated_stream()

    for idx, batch in enumerate(batches, 1):
        print(f"\n[STREAM] Processing Batch {idx}/{len(batches)}...")
        incidents = process_events(batch)
        print(f"[STATUS] Total Incidents in Store: {len(incidents)}")
        time.sleep(2)  # Jeda simulasi real-time

    print("\n[REPORT] Generating Excel Executive Report...")
    generate_report()

    print("\n=" * 60)
    print("PROCESSING COMPLETED SUCCESSFULLY")
    print("=" * 60)

if __name__ == "__main__":
    main()