import pandas as pd
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parent / "data" / "unified_incidents.csv"
REPORT_OUTPUT = Path(__file__).resolve().parent / "data" / "Executive_Incident_Report.xlsx"

def generate_report():
    if not DATA_FILE.exists():
        print("Data insiden tidak ditemukan.")
        return

    df = pd.read_csv(DATA_FILE)
    
    with pd.ExcelWriter(REPORT_OUTPUT, engine="openpyxl") as writer:
        # Sheet 1: Executive Summary
        summary = pd.DataFrame({
            "Metric": ["Total Incidents", "Active Open", "Resolved"],
            "Value": [len(df), len(df[df["Status"] == "OPEN"]), len(df[df["Status"] == "RESOLVED"])]
        })
        summary.to_excel(writer, sheet_name="Summary", index=False)
        
        # Sheet 2: All Incidents
        df.to_excel(writer, sheet_name="Incident Details", index=False)

    print(f"Laporan berhasil dibuat: {REPORT_OUTPUT}")

if __name__ == "__main__":
    generate_report()