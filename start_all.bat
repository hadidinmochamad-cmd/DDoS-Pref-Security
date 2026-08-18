@echo off
echo Memulai layanan Monitoring DDoS...

:: Menjalankan Streamlit (asumsi file ada di folder root)
start cmd /k "echo Menjalankan Streamlit... && streamlit run app_dashboard.py"

:: Pindah ke folder backend dan menjalankan Flask
cd /d "%~dp0\backend"
start cmd /k "echo Menjalankan Flask Backend... && py app.py"

echo Semua layanan telah dimulai.
pause