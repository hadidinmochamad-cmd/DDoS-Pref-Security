import csv
import json
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

# =========================================================
# ⚙️ CONFIGURATION (PREFIX & ASN MONITORING ONLY)
# =========================================================
ORGANIZATION = "Bank Indonesia"
PRIMARY_ASN = "AS59132"
PRIMARY_PREFIX = "157.85.223.0/24"

# Ambang Batas BGP Peer minimum (jika peer drop di bawah angka ini -> Pemicu Alert)
MIN_EXPECTED_PEERS = 100 

POLLING_INTERVAL_SECONDS = 15  # Polling interval 24/7

DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
CSV_FILE = DATA_DIR / "unified_incidents.csv"
FIELDNAMES = [
    "Incident ID", "Opened At", "Resolved At", "Domain",
    "Event Type", "Severity", "Status", "Prefix", "ASN"
]


def get_current_utc_iso():
    return datetime.now(ZoneInfo("UTC")).isoformat()


def load_incidents():
    if not CSV_FILE.exists():
        return []
    try:
        with open(CSV_FILE, mode="r", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except Exception as e:
        print(f"[ERR] Gagal membaca CSV: {e}")
        return []


def save_incidents(incidents):
    temp_file = CSV_FILE.with_suffix(".tmp")
    try:
        with open(temp_file, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerows(incidents)
        temp_file.replace(CSV_FILE)
    except Exception as e:
        print(f"[ERR] Gagal menyimpan data CSV: {e}")


# =========================================================
# 📡 1. RPKI & BGP ORIGIN VALIDATION
# =========================================================
def check_rpki_status(prefix, asn):
    """
    Memeriksa RPKI ROA Origin ASN untuk mendeteksi BGP Hijacking.
    """
    clean_asn = asn.replace("AS", "").strip()
    url = f"https://stat.ripe.net/data/rpki-validation/data.json?resource={clean_asn}&prefix={prefix}"
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SOC-Prefix-Engine/3.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            status = data.get("data", {}).get("status", "UNKNOWN")
            
            if status == "INVALID":
                return True, "RPKI Status INVALID: Terindikasi BGP Route Hijacking / Unauthorized Origin!"
            elif status == "NOT_FOUND":
                return False, "RPKI Status NOT_FOUND: Prefix belum memiliki ROA Record (Warning)"
            return False, "RPKI Status VALID: Origin ASN AS59132 Terverifikasi Sah secara Global"
    except Exception as e:
        return False, f"RPKI Check Standby ({e})"


# =========================================================
# 🌐 2. PREFIX VISIBILITY & ROUTE STABILITY (DDoS / LEAK INDICATOR)
# =========================================================
def check_prefix_health(prefix):
    """
    Memantau keterlihatan Prefix 157.85.223.0/24 di BGP Peer Global.
    Menggunakan RIPE Stat Routing Status API.
    """
    url = f"https://stat.ripe.net/data/routing-status/data.json?resource={prefix}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SOC-Prefix-Engine/3.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            visibility = data.get("data", {}).get("visibility", {})
            peers_count = visibility.get("v4", {}).get("ris_peers_seeing", 0)
            
            # 1. Total Route Withdrawn (Prefix hilang dari BGP Table)
            if peers_count == 0:
                return True, True, "CRITICAL: Prefix Unannounced / Total Route Withdrawal di BGP Global!"
            
            # 2. Degradasi Parah BGP Peer (Indikasi Volumetric Attack / Upstream Outage)
            if peers_count < MIN_EXPECTED_PEERS:
                return False, True, f"WARNING: Anomali BGP Peers Drop Signifikan! Hanya terdeteksi {peers_count} Peers Global"

            return False, False, f"Prefix Active & Announced Normal (Terjangkau oleh {peers_count} BGP Peers Global)"
            
    except Exception as e:
        return False, False, f"Prefix Telemetry Standby ({e})"


# =========================================================
# 🔄 CORE 24/7 MONITORING ENGINE
# =========================================================
def run_soc_engine():
    print("======================================================================")
    print(f"🛡️  SOC ENGINE: PURE PREFIX & BGP TELEMETRY (NO HOST / NO SNMP)")
    print(f"🏢 ORGANISASI     : {ORGANIZATION}")
    print(f"📌 TARGET ASN     : {PRIMARY_ASN}")
    print(f"🌐 TARGET PREFIX  : {PRIMARY_PREFIX}")
    print(f"⏱️  POLLING RATE   : Setiap {POLLING_INTERVAL_SECONDS} Detik")
    print("======================================================================\n")

    incident_counter = 1000

    while True:
        try:
            timestamp_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            incidents = load_incidents()
            
            if incidents:
                max_id = max(
                    [int(str(inc["Incident ID"]).replace("INC-", "")) 
                     for inc in incidents if "INC-" in str(inc["Incident ID"])], 
                    default=0
                )
                if max_id > 0:
                    incident_counter = max_id

            # Evaluasi Telemetri BGP
            rpki_fail, rpki_msg = check_rpki_status(PRIMARY_PREFIX, PRIMARY_ASN)
            pref_fail, ddos_bgp_fail, pref_msg = check_prefix_health(PRIMARY_PREFIX)

            checks = {
                "BGP/RPKI": {"fail": rpki_fail, "msg": rpki_msg, "sev": "CRITICAL"},
                "Prefix Monitoring": {"fail": pref_fail, "msg": pref_msg, "sev": "HIGH"},
                "DDoS": {"fail": ddos_bgp_fail, "msg": pref_msg, "sev": "CRITICAL"}
            }

            has_changes = False

            # Output Terminal Real-time
            print(f"⏱️ [{timestamp_now}] Status Polling Check:")
            print(f"   ├─ BGP/RPKI Status : {'🚨 FAIL' if rpki_fail else '🟢 OK'} | {rpki_msg}")
            print(f"   ├─ Prefix Status   : {'🚨 FAIL' if pref_fail else '🟢 OK'} | {pref_msg}")
            print(f"   └─ Volumetric/DDoS : {'🚨 FAIL' if ddos_bgp_fail else '🟢 OK'} | Status berbasis Telemetri BGP Global")
            print("-" * 75)

            # Logika Pembuatan & Auto-Resolve Insiden
            for domain, data in checks.items():
                open_inc = next((inc for inc in incidents if inc["Domain"] == domain and inc["Status"] == "OPEN"), None)

                if data["fail"] and not open_inc:
                    incident_counter += 1
                    new_id = f"INC-{incident_counter}"
                    incidents.append({
                        "Incident ID": new_id,
                        "Opened At": get_current_utc_iso(),
                        "Resolved At": "-",
                        "Domain": domain,
                        "Event Type": data["msg"],
                        "Severity": data["sev"],
                        "Status": "OPEN",
                        "Prefix": PRIMARY_PREFIX,
                        "ASN": PRIMARY_ASN
                    })
                    has_changes = True
                    print(f"\n🚨 [ALERT GENERATED] {new_id} | Domain: {domain} | Msg: {data['msg']}\n")

                elif not data["fail"] and open_inc:
                    open_inc["Status"] = "RESOLVED"
                    open_inc["Resolved At"] = get_current_utc_iso()
                    has_changes = True
                    print(f"\n🟢 [ALERT RESOLVED] {open_inc['Incident ID']} | Domain: {domain} sudah normal kembali.\n")

            if has_changes:
                save_incidents(incidents)

        except Exception as e:
            print(f"⚠️ Error pada Loop Monitoring: {e}")

        time.sleep(POLLING_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_soc_engine()