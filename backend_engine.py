import csv
import json
import socket
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

# =========================================================
# ⚙️ CONFIGURATION (NO-SNMP REALTIME SOC ENGINE)
# =========================================================
ORGANIZATION = "Bank Indonesia"
PRIMARY_ASN = "AS59132"
PRIMARY_PREFIX = "157.85.223.0/24"

# Multi-Target Host/IP Probe di dalam Prefix untuk Akurasi DDoS
# Ganti/Tambahkan IP Public & Domain aktif milik organisasi Anda
DDOS_TARGET_HOSTS = [
    "www.bi.go.id",       # Web Portal Utama (Domain)
    "157.85.223.1",       # Edge Gateway IP
    "157.85.223.10"       # Public Service IP
]
DDOS_TARGET_PORT = 443    # Port HTTPS (443) atau HTTP (80)
LATENCY_THRESHOLD_MS = 2000.0  # Batas Latency (2 Detik)

POLLING_INTERVAL_SECONDS = 10  # Polling interval 24/7

# Direktori & File Penyimpanan Data Insiden
DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
CSV_FILE = DATA_DIR / "unified_incidents.csv"
FIELDNAMES = [
    "Incident ID", "Opened At", "Resolved At", "Domain",
    "Event Type", "Severity", "Status", "Prefix", "ASN"
]


def get_current_utc_iso():
    """Mengembalikan stempel waktu UTC berformat ISO 8601."""
    return datetime.now(ZoneInfo("UTC")).isoformat()


def load_incidents():
    """Membaca daftar insiden dari CSV."""
    if not CSV_FILE.exists():
        return []
    try:
        with open(CSV_FILE, mode="r", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except Exception as e:
        print(f"[ERR] Gagal membaca CSV: {e}")
        return []


def save_incidents(incidents):
    """Menyimpan pembaruan insiden ke CSV secara meyakinkan (Atomic Write)."""
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
# 📡 1. MONITORING BGP / RPKI (RIPE STAT API)
# =========================================================
def check_bgp_rpki_status(prefix, asn):
    """
    Memeriksa Status Validasi RPKI secara Real-time.
    Mendeteksi RPKI Invalid (Indikasi BGP Hijack / Route Leak).
    """
    clean_asn = asn.replace("AS", "").strip()
    url = f"https://stat.ripe.net/data/rpki-validation/data.json?resource={clean_asn}&prefix={prefix}"
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SOC-Realtime-Engine/2.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            status = data.get("data", {}).get("status", "UNKNOWN")
            
            if status == "INVALID":
                return True, "RPKI Status INVALID: Terindikasi BGP Route Hijacking / Route Leak!"
            elif status == "NOT_FOUND":
                return False, "RPKI Status NOT_FOUND: Prefix belum terdaftar ROA (Perlu Perhatian)"
            return False, "RPKI Status VALID: OID Origin ASN Terverifikasi Resmi"
    except Exception as e:
        # Fallback jika RIPE API mengalami masalah koneksi sementara
        return False, f"BGP/RPKI Check Standby ({e})"


# =========================================================
# 🌐 2. MONITORING PREFIX VISIBILITY (GLOBAL BGP PEERS)
# =========================================================
def check_prefix_visibility(prefix):
    """
    Memeriksa apakah Prefix IP aktif disiarkan dan terlihat di BGP Peers Global.
    """
    url = f"https://stat.ripe.net/data/routing-status/data.json?resource={prefix}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SOC-Realtime-Engine/2.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            visibility = data.get("data", {}).get("visibility", {})
            peers_count = visibility.get("v4", {}).get("ris_peers_seeing", 0)
            
            if peers_count == 0:
                return True, "CRITICAL: Prefix Unannounced / Route Withdrawn dari BGP Global!"
            return False, f"Prefix Announced Normal (Terdeteksi oleh {peers_count} BGP Peers Global)"
    except Exception as e:
        return False, f"Prefix Visibility Standby ({e})"


# =========================================================
# 🌊 3. MONITORING DDOS (MULTI-TARGET SYNTHETIC PROBE)
# =========================================================
def check_ddos_synthetic_probe(hosts, port=443):
    """
    Memeriksa ketersediaan & Latency jaringan pada beberapa target host di dalam Prefix.
    Jika >= 50% target timeout/degradasi parah -> Pemicu DDoS Alert.
    """
    total_hosts = len(hosts)
    failed_count = 0
    latency_details = []

    for host in hosts:
        start_time = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.5)  # Timeout 2.5 detik per probe
        
        try:
            s.connect((host, port))
            s.close()
            latency_ms = (time.time() - start_time) * 1000
            
            if latency_ms > LATENCY_THRESHOLD_MS:
                failed_count += 1
                latency_details.append(f"{host}: HIGH LATENCY ({latency_ms:.0f}ms)")
            else:
                latency_details.append(f"{host}: OK ({latency_ms:.0f}ms)")
                
        except (socket.timeout, socket.error):
            failed_count += 1
            latency_details.append(f"{host}: TIMEOUT/UNREACHABLE")

    # Evaluasi Ambang Batas Kegagalan
    failure_ratio = failed_count / total_hosts
    details_str = " | ".join(latency_details)

    if failure_ratio >= 0.5:
        return True, f"Volumetric DDoS / Pipe Saturation Detected! ({failed_count}/{total_hosts} Target Down/Degraded) -> [{details_str}]"
    
    return False, f"DDoS Health Clean ({total_hosts - failed_count}/{total_hosts} Target Normal) -> [{details_str}]"


# =========================================================
# 🔄 CORE 24/7 MONITORING LOOP ENGINE
# =========================================================
def run_soc_engine():
    print("======================================================================")
    print(f"🛡️  SOC REALTIME MONITORING ENGINE (NO-SNMP / PUBLIC TELEMETRY)")
    print(f"🏢 ORGANISASI     : {ORGANIZATION}")
    print(f"📌 TARGET ASN     : {PRIMARY_ASN}")
    print(f"🌐 TARGET PREFIX  : {PRIMARY_PREFIX}")
    print(f"🎯 DDOS TARGETS   : {', '.join(DDOS_TARGET_HOSTS)}")
    print(f"⏱️  POLLING RATE   : Setiap {POLLING_INTERVAL_SECONDS} Detik")
    print("======================================================================\n")

    incident_counter = 1000

    while True:
        try:
            timestamp_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            incidents = load_incidents()
            
            # Auto-increment ID Insiden
            if incidents:
                max_id = max(
                    [int(str(inc["Incident ID"]).replace("INC-", "")) 
                     for inc in incidents if "INC-" in str(inc["Incident ID"])], 
                    default=0
                )
                if max_id > 0:
                    incident_counter = max_id

            # 1. Jalankan Seluruh modul pengecekan
            bgp_fail, bgp_msg = check_bgp_rpki_status(PRIMARY_PREFIX, PRIMARY_ASN)
            pref_fail, pref_msg = check_prefix_visibility(PRIMARY_PREFIX)
            ddos_fail, ddos_msg = check_ddos_synthetic_probe(DDOS_TARGET_HOSTS, DDOS_TARGET_PORT)

            checks = {
                "BGP/RPKI": {"fail": bgp_fail, "msg": bgp_msg, "sev": "CRITICAL"},
                "Prefix Monitoring": {"fail": pref_fail, "msg": pref_msg, "sev": "HIGH"},
                "DDoS": {"fail": ddos_fail, "msg": ddos_msg, "sev": "CRITICAL"}
            }

            has_changes = False

            # Print Heartbeat Status di Terminal
            print(f"⏱️ [{timestamp_now}] Status Polling Check:")
            print(f"   ├─ BGP/RPKI Status : {'🚨 FAIL' if bgp_fail else '🟢 OK'} | {bgp_msg}")
            print(f"   ├─ Prefix Status   : {'🚨 FAIL' if pref_fail else '🟢 OK'} | {pref_msg}")
            print(f"   └─ DDoS Status     : {'🚨 FAIL' if ddos_fail else '🟢 OK'} | {ddos_msg}")
            print("-" * 70)

            # 2. Logika Pembuatan & Penyelesaian Insiden
            for domain, data in checks.items():
                open_inc = next((inc for inc in incidents if inc["Domain"] == domain and inc["Status"] == "OPEN"), None)

                # Jika ada anomali & belum ada insiden yang OPEN -> Buka Insiden Baru
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

                # Jika kondisi sudah pulih & ada insiden OPEN -> Auto-Resolve
                elif not data["fail"] and open_inc:
                    open_inc["Status"] = "RESOLVED"
                    open_inc["Resolved At"] = get_current_utc_iso()
                    has_changes = True
                    print(f"\n🟢 [ALERT RESOLVED] {open_inc['Incident ID']} | Domain: {domain} sudah pulih.\n")

            if has_changes:
                save_incidents(incidents)

        except Exception as e:
            print(f"⚠️ Error pada Loop Monitoring: {e}")

        # Pause sesuai interval
        time.sleep(POLLING_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_soc_engine()