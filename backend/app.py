from flask import Flask, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import threading
import time
from dotenv import load_dotenv
import os
import logging
from datetime import datetime

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

STREAMLIT_URL = os.getenv('STREAMLIT_URL', 'http://localhost:8501')
UPDATE_INTERVAL = int(os.getenv('UPDATE_INTERVAL', 5))

latest_data = {
    'status': 'SECURE',
    'prefix': '157.85.223.0/24',
    'lastUpdate': datetime.now().isoformat(),
    'services': [],
    'incidents': {'total': 0, 'active': 0, 'resolved': 0, 'domains': 0},
    'connected': False,
    'errorMessage': None
}

clients_connected = 0

def scrape_streamlit_data():
    """Ambil data dari Streamlit"""
    try:
        logger.info(f"Fetching from Streamlit: {STREAMLIT_URL}")
        response = requests.get(STREAMLIT_URL, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        data = {
            'status': 'SECURE',
            'prefix': '157.85.223.0/24',
            'lastUpdate': datetime.now().isoformat(),
            'services': get_default_services(),
            'incidents': {'total': 1, 'active': 0, 'resolved': 1, 'domains': 1},
            'connected': True,
            'errorMessage': None,
            'timestamp': time.time()
        }
        return data
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return None

def get_default_services():
    """Default services jika scraping gagal"""
    return [
        {
            'prefix': '157.85.223.0/24',
            'asNumber': 'AS59132',
            'description': 'BGP Route Announcement & RPKI Validation',
            'status': 'Normal',
            'lastUpdate': datetime.now().strftime('%d/%m/%Y %H:%M:%S WIB')
        },
        {
            'prefix': '157.85.223.0/24',
            'asNumber': 'AS59132',
            'description': 'Prefix Reachability & Unannounced Monitoring',
            'status': 'Normal',
            'lastUpdate': datetime.now().strftime('%d/%m/%Y %H:%M:%S WIB')
        },
        {
            'prefix': '157.85.223.0/24',
            'asNumber': 'AS59132',
            'description': 'Volumetric DDoS & Pipe Saturation Protection',
            'status': 'Normal',
            'lastUpdate': datetime.now().strftime('%d/%m/%Y %H:%M:%S WIB')
        }
    ]

def emit_realtime_updates():
    """Background thread untuk broadcast data"""
    while True:
        try:
            data = scrape_streamlit_data()
            if data:
                latest_data.update(data)
            logger.info(f"Emitting update to all clients")
            # Broadcast ke semua clients
            socketio.emit('dashboard-update', latest_data, skip_sid=None)
            time.sleep(UPDATE_INTERVAL)
        except Exception as e:
            logger.error(f"Error in emit: {str(e)}")
            time.sleep(UPDATE_INTERVAL)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'clients': clients_connected
    }), 200

@app.route('/api/data', methods=['GET'])
def get_data():
    return jsonify(latest_data), 200

@socketio.on('connect')
def handle_connect():
    global clients_connected
    clients_connected += 1
    logger.info(f'Client connected. Total: {clients_connected}')
    # Send initial data ke client yang baru connect
    emit('initial-data', latest_data)
    # Broadcast client count ke semua
    socketio.emit('client-count', {'count': clients_connected}, skip_sid=None)

@socketio.on('disconnect')
def handle_disconnect():
    global clients_connected
    clients_connected -= 1
    logger.info(f'Client disconnected. Total: {clients_connected}')
    socketio.emit('client-count', {'count': clients_connected}, skip_sid=None)

if __name__ == '__main__':
    logger.info("Starting real-time update thread...")
    thread = threading.Thread(target=emit_realtime_updates, daemon=True)
    thread.start()
    
    port = int(os.getenv('PORT', 5000))
    logger.info(f"Starting Flask-SocketIO server on port {port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=False)