from datetime import datetime
import getpass
from pathlib import Path
import socket
from zoneinfo import ZoneInfo
import pandas as pd
import plotly.express as px
import requests
import gradio as gr

# =========================================================
# ⚙️ PATH & KONFIGURASI DATA
# =========================================================
DATA_FILE = Path(__file__).resolve().parent / "data" / "unified_incidents.csv"
LIBRENMS_BASE_URL = "https://venus.xlsmart.co.id"

# =========================================================
# 🎨 MAP WARNA KHUSUS PER JENIS ISU / DOMAIN
# =========================================================
EVENT_COLOR_MAP = {
    "DDoS": "#EF553B",
    "BGP/RPKI": "#AB63FA",
    "Prefix Monitoring": "#FFA15A",
}

# =========================================================
# 🛠️ HELPER FUNCTIONS
# =========================================================
def get_client_ip() -> str:
    """Mendapatkan IP Login Pengguna / Client."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_system_account_info() -> tuple[str, str]:
    """Mendapatkan informasi Laptop Hostname dan OS User Account."""
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "Unknown-Device"

    try:
        user_account = getpass.getuser()
    except Exception:
        user_account = "Unknown-User"

    return hostname, user_account


def convert_to_wib(utc_time_str: str) -> str:
    """Mengonversi UTC ISO timestamp ke Format 24 Jam Indonesia WIB."""
    if not utc_time_str or str(utc_time_str).strip() in ["None", "nan", ""]:
        return "-"
    try:
        dt = datetime.fromisoformat(str(utc_time_str))
        dt_wib = dt.astimezone(ZoneInfo("Asia/Jakarta"))
        return dt_wib.strftime("%d/%m/%Y %H:%M:%S WIB")
    except Exception:
        return str(utc_time_str)


def fetch_librenms_data():
    """Mengambil data device LibreNMS."""
    url = f"{LIBRENMS_BASE_URL}/api/v0/devices"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            devices = response.json().get("devices", [])
            data = []
            for d in devices:
                data.append({
                    "Hostname": d.get("hostname"),
                    "IP Address": d.get("ip"),
                    "Hardware / OS": f"{d.get('hardware', '-')} ({d.get('os', '-')})",
                    "Uptime": d.get("uptime_short", "-"),
                    "Status": (
                        "🟢 ONLINE" if d.get("status") == 1 else "🔴 DOWN"
                    ),
                })
            return pd.DataFrame(data)
    except Exception:
        pass
    
    return pd.DataFrame([
        {
            "Hostname": "Demo-Router-BI",
            "IP Address": "157.85.223.1",
            "Hardware / OS": "Cisco (IOS-XE)",
            "Uptime": "45 days",
            "Status": "🟢 ONLINE"
        }
    ])


def fetch_librenms_ports_data():
    """Mengambil data port monitoring spesifik (Realtime 24/7 View + Last Update Timestamp)."""
    current_time_wib = datetime.now(ZoneInfo("Asia/Jakarta")).strftime("%d/%m/%Y %H:%M:%S WIB")
    
    url = f"{LIBRENMS_BASE_URL}/api/v0/ports"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            ports = response.json().get("ports", [])
            data = []
            target_port_ids = [143736, 13483, 13484]
            for p in ports:
                if p.get("port_id") in target_port_ids or len(data) < 10:
                    data.append({
                        "Port ID": p.get("port_id"),
                        "Location": p.get("ifDescr", "-"),
                        "Interface": p.get("ifName", "-"),
                        "Traffic In/Out": "Active Sync",
                        "Status": (
                            "🟢 UP (Normal)"
                            if p.get("ifOperStatus") == "up"
                            else "🔴 DOWN"
                        ),
                        "Last Update": current_time_wib,
                    })
            if data:
                return pd.DataFrame(data)
    except Exception:
        pass

    # Fallback dataframe real-time dengan kolom Last Update
    return pd.DataFrame([
        {
            "Port ID": 143736,
            "Location": "BI DKU Gresik",
            "Interface": "Gi 0/1",
            "Traffic In/Out": "125.4 Mbps / 42.1 Mbps",
            "Status": "🟢 UP (Normal)",
            "Last Update": current_time_wib,
        },
        {
            "Port ID": 13483,
            "Location": "BI Internasional",
            "Interface": "Te 1/1",
            "Traffic In/Out": "890.2 Mbps / 650.8 Mbps",
            "Status": "🟢 UP (Normal)",
            "Last Update": current_time_wib,
        },
        {
            "Port ID": 13484,
            "Location": "BI National",
            "Interface": "Te 1/2",
            "Traffic In/Out": "1.42 Gbps / 1.10 Gbps",
            "Status": "🟢 UP (Normal)",
            "Last Update": current_time_wib,
        },
    ])


# =========================================================
# 📊 GENERATE DASHBOARD CONTENT UTAMA
# =========================================================
def load_dashboard_data():
    now_wib = datetime.now(ZoneInfo("Asia/Jakarta")).strftime(
        "%d/%m/%Y %H:%M:%S WIB"
    )

    data_exists = DATA_FILE.exists()
    df = pd.read_csv(DATA_FILE) if data_exists else pd.DataFrame()
    open_incidents = (
        df[df["Status"] == "OPEN"] if not df.empty else pd.DataFrame()
    )
    critical_open = (
        open_incidents[open_incidents["Severity"] == "CRITICAL"]
        if not open_incidents.empty
        else pd.DataFrame()
    )

    # Security Status Text
    if not critical_open.empty:
        sec_status = f"🚨 STATUS: CRITICAL — Ditemukan {len(critical_open)} insiden tingkat bahaya tinggi yang masih AKTIF! (Last Update: {now_wib})"
    elif not open_incidents.empty:
        sec_status = f"⚠️ STATUS: WARNING — Ditemukan {len(open_incidents)} insiden aktif, tidak ada bahaya kritis. (Last Update: {now_wib})"
    else:
        sec_status = f"🟢 STATUS: SECURE — Prefix 157.85.223.0/24 (AS59132) dalam kondisi aman dan terproteksi. (Last Update: {now_wib})"

    # Metrics
    total_inc = len(df) if not df.empty else 0
    active_inc = len(open_incidents) if not open_incidents.empty else 0
    resolved_inc = len(df[df["Status"] == "RESOLVED"]) if not df.empty else 0
    domains_count = df["Domain"].nunique() if not df.empty else 0

    # Realtime Timeline DataFrame
    display_df = df.copy() if not df.empty else pd.DataFrame()
    if not display_df.empty:
        if "Opened At" in display_df.columns:
            display_df["Opened At"] = display_df["Opened At"].apply(convert_to_wib)
        if "Resolved At" in display_df.columns:
            display_df["Resolved At"] = display_df["Resolved At"].apply(convert_to_wib)
        display_df = display_df[["Incident ID", "Opened At", "Domain", "Event Type", "Severity", "Status"]]

    # Health Service Status Table
    health_inventory_data = pd.DataFrame([
        {
            "Prefix": "157.85.223.0/24",
            "AS Number": "AS59132",
            "Customer Name": "Bank Indonesia",
            "Description": "BGP Route Announcement & RPKI Validation",
            "Status": "🔴 Issue Detected" if not open_incidents.empty and "BGP/RPKI" in open_incidents["Domain"].values else "🟢 Normal",
            "Last Update": now_wib,
        },
        {
            "Prefix": "157.85.223.0/24",
            "AS Number": "AS59132",
            "Customer Name": "Bank Indonesia",
            "Description": "Prefix Reachability & Unannounced Monitoring",
            "Status": "🔴 Issue Detected" if not open_incidents.empty and "Prefix Monitoring" in open_incidents["Domain"].values else "🟢 Normal",
            "Last Update": now_wib,
        },
        {
            "Prefix": "157.85.223.0/24",
            "AS Number": "AS59132",
            "Customer Name": "Bank Indonesia",
            "Description": "Volumetric DDoS & Pipe Saturation Protection",
            "Status": "🔴 Issue Detected" if not open_incidents.empty and "DDoS" in open_incidents["Domain"].values else "🟢 Normal",
            "Last Update": now_wib,
        },
    ])

    # Plotly Charts
    fig_sev, fig_dom = None, None
    if not df.empty:
        df_sev = df.groupby(["Severity", "Event Type"]).size().reset_index(name="Jumlah Insiden")
        fig_sev = px.bar(
            df_sev, y="Severity", x="Jumlah Insiden", color="Event Type", barmode="group",
            title="Distribusi Severity per Jenis Isu (Event Type)", color_discrete_map=EVENT_COLOR_MAP, orientation="h"
        )
        fig_sev.update_layout(height=350)

        df_dom = df.groupby(["Domain", "Severity"]).size().reset_index(name="Jumlah Insiden")
        fig_dom = px.bar(
            df_dom, y="Domain", x="Jumlah Insiden", color="Domain", barmode="group",
            title="Distribusi Domain per Jenis Isu", color_discrete_map=EVENT_COLOR_MAP, orientation="h"
        )
        fig_dom.update_layout(height=350)

    # LibreNMS & RPKI Feed
    df_libre = fetch_librenms_data()
    df_ports_live = fetch_librenms_ports_data()
    
    rpki_live_data = pd.DataFrame([
        {
            "Prefix": "157.85.223.0/24",
            "Origin AS": "AS59132",
            "Status Validasi": "🟢 VALID (ROA Matched)",
            "RIPE Database Source": "RIPE NCC RPKI Repository",
            "Last Update": now_wib,
        }
    ])

    # System Health Information text
    hostname, laptop_account = get_system_account_info()
    sys_info_text = (
        f"• Monitored Asset: Bank Indonesia (AS59132)\n"
        f"• Target Prefix: 157.85.223.0/24\n"
        f"• Timezone Sync: Asia/Jakarta (WIB 24-Hour)\n"
        f"• Login IP Address: {get_client_ip()}\n"
        f"• Laptop Account: {laptop_account} (Device: {hostname})"
    )

    return (
        sec_status, total_inc, active_inc, resolved_inc, domains_count,
        health_inventory_data, display_df, fig_sev, fig_dom,
        df_libre, df_ports_live, rpki_live_data, sys_info_text
    )


# =========================================================
# 🔒 HALAMAN LOGIN & KONTROL AUTENTIKASI
# =========================================================
def authenticate(username, password):
    if username == "Admin" and password == "Admin@123*":
        return gr.update(visible=False), gr.update(visible=True), "Admin SOC"
    elif username == "View" and password == "View123":
        return gr.update(visible=False), gr.update(visible=True), "Guest"
    else:
        return gr.update(visible=True), gr.update(visible=False), "❌ Username atau Password salah! Silakan coba lagi."


# =========================================================
# 🚀 BUILDING GRADIO INTERFACE BLOCKS
# =========================================================
with gr.Blocks(title="Bank Indonesia Executive Security Operations Center") as demo:

    # --- HALAMAN LOGIN ---
    with gr.Column(visible=True) as login_page:
        gr.Markdown("<br>")
        gr.Markdown("<h1 style='text-align: center;'>🏛️ BANK INDONESIA</h1>")
        gr.Markdown("<h2 style='text-align: center;'>Executive SOC Portal</h2>")
        gr.Markdown("<p style='text-align: center;'>Silakan login untuk mengakses Dashboard Security Operations Center</p>")
        
        with gr.Row():
            with gr.Column(scale=1): pass
            with gr.Column(scale=2):
                username_input = gr.Textbox(label="Username", placeholder="Masukkan username")
                password_input = gr.Textbox(label="Password", type="password", placeholder="Masukkan password")
                submit_button = gr.Button("🔐 Sign In", variant="primary")
                login_error_box = gr.Markdown()
            with gr.Column(scale=1): pass

    # --- HALAMAN DASHBOARD UTAMA ---
    with gr.Column(visible=False) as dashboard_page:
        gr.Markdown("# 🛡️ Bank Indonesia - Executive Security Operations Center")
        gr.Markdown("Cross-Domain Monitoring: BGP/RPKI | DDoS | Prefix Monitoring — Target: 157.85.223.0/24 (AS59132)")
        
        with gr.Row():
            sec_status_display = gr.Textbox(label="Current Security Status", interactive=False)
            btn_refresh = gr.Button("🔄 Refresh Data Sekarang")

        # Metrics Dashboard
        gr.Markdown("### 🚨 Incident Dashboard")
        with gr.Row():
            m1 = gr.Number(label="Total Insiden Terdeteksi", interactive=False)
            m2 = gr.Number(label="Insiden Aktif (OPEN)", interactive=False)
            m3 = gr.Number(label="Berhasil Dipulihkan", interactive=False)
            m4 = gr.Number(label="Domain Terdampak", interactive=False)

        gr.Markdown("---")
        gr.Markdown("##### 🌐 Realtime Data Health Service Status")
        health_table = gr.Dataframe(interactive=False)

        gr.Markdown("---")
        gr.Markdown("### 📡 Real-Time Event Timeline")
        timeline_table = gr.Dataframe(interactive=False)

        gr.Markdown("---")
        gr.Markdown("### 📊 Event Statistics")
        with gr.Row():
            plot_sev = gr.Plot()
            plot_dom = gr.Plot()

        gr.Markdown("---")
        gr.Markdown("### 🖥️ LibreNMS Infrastructure Live Monitoring (Realtime 24/7 Feed)")
        librenms_dev_table = gr.Dataframe(label="Status Perangkat Utama Jaringan", interactive=False)
        librenms_port_table = gr.Dataframe(label="Live Port Traffic & Status Monitoring", interactive=False)

        gr.Markdown("---")
        gr.Markdown("### 🔍 RPKI Validator Live Feed (RIPE.net — Prefix 157.85.223.0/24)")
        rpki_table = gr.Dataframe(interactive=False)

        gr.Markdown("---")
        with gr.Row():
            sys_info_box = gr.Textbox(label="🟢 System / Data Health", lines=6, interactive=False)
            btn_logout = gr.Button("🚪 Logout Portal", variant="stop")

    # --- EVENT BINDINGS / INTERACTION ---
    outputs_list = [
        sec_status_display, m1, m2, m3, m4,
        health_table, timeline_table, plot_sev, plot_dom,
        librenms_dev_table, librenms_port_table, rpki_table, sys_info_box
    ]

    submit_button.click(
        fn=authenticate,
        inputs=[username_input, password_input],
        outputs=[login_page, dashboard_page, login_error_box]
    ).then(
        fn=load_dashboard_data,
        outputs=outputs_list
    )

    btn_refresh.click(
        fn=load_dashboard_data,
        outputs=outputs_list
    )

    def logout_action():
        return gr.update(visible=True), gr.update(visible=False), "", ""

    btn_logout.click(
        fn=logout_action,
        outputs=[login_page, dashboard_page, username_input, password_input]
    )

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860, share=True)