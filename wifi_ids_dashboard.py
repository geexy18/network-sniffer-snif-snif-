#!/usr/bin/env python3
"""
Wi-Fi IDS Web Dashboard Server
Provides a real-time web interface to monitor Wi-Fi security alerts
"""

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import threading
import time
import json
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import *

app = Flask(__name__)
app.config['SECRET_KEY'] = 'wifi-ids-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
alerts = deque(maxlen=100)  # Keep last 100 alerts
known_aps = {}
stats = {
    'packets_processed': 0,
    'total_alerts': 0,
    'deauth_attacks': 0,
    'rogue_aps': 0,
    'beacon_floods': 0,
    'start_time': datetime.now().isoformat()
}

MONITOR_INTERFACE = "wlan0mon"
DEAUTH_THRESHOLD = 5

class WiFiIDSMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.deauth_counter = defaultdict(lambda: deque(maxlen=100))
        self.running = False
        
    def emit_alert(self, alert_type, message, details):
        """Emit alert to web dashboard"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'message': message,
            'details': details,
            'severity': self.get_severity(alert_type)
        }
        
        alerts.append(alert)
        stats['total_alerts'] += 1
        stats[f"{alert_type.lower()}s"] = stats.get(f"{alert_type.lower()}s", 0) + 1
        
        # Emit to connected clients
        socketio.emit('new_alert', alert)
        print(f"[ALERT] {alert_type}: {message}")
    
    def get_severity(self, alert_type):
        """Determine alert severity level"""
        severity_map = {
            'DEAUTH_ATTACK': 'critical',
            'ROGUE_AP': 'high',
            'BEACON_FLOOD': 'medium'
        }
        return severity_map.get(alert_type, 'low')
    
    def detect_deauth_attack(self, pkt):
        """Detect deauthentication attacks"""
        if pkt.haslayer(Dot11Deauth):
            bssid = pkt.addr2 or "Unknown"
            current_time = time.time()
            
            self.deauth_counter[bssid].append(current_time)
            recent = [t for t in self.deauth_counter[bssid] if current_time - t < 1.0]
            
            if len(recent) >= DEAUTH_THRESHOLD:
                self.emit_alert(
                    "DEAUTH_ATTACK",
                    f"Deauth attack detected from {bssid}",
                    {"bssid": bssid, "rate": len(recent), "target": pkt.addr1}
                )
    
    def detect_rogue_ap(self, pkt):
        """Detect potential rogue access points"""
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr2
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            
            if bssid in known_aps:
                if known_aps[bssid]['ssid'] != ssid:
                    self.emit_alert(
                        "ROGUE_AP",
                        f"Possible Evil Twin AP detected",
                        {"bssid": bssid, "old_ssid": known_aps[bssid]['ssid'], "new_ssid": ssid}
                    )
            else:
                known_aps[bssid] = {'ssid': ssid, 'first_seen': datetime.now().isoformat()}
                socketio.emit('new_ap', {'bssid': bssid, 'ssid': ssid})
    
    def packet_handler(self, pkt):
        """Process each packet"""
        stats['packets_processed'] += 1
        
        if pkt.haslayer(Dot11):
            self.detect_deauth_attack(pkt)
            self.detect_rogue_ap(pkt)
        
        # Update stats every 50 packets
        if stats['packets_processed'] % 50 == 0:
            socketio.emit('stats_update', stats)
    
    def start(self):
        """Start packet sniffing"""
        self.running = True
        print(f"Starting Wi-Fi monitoring on {self.interface}...")
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            print(f"Error during monitoring: {e}")
    
    def stop(self):
        """Stop monitoring"""
        self.running = False

# Initialize monitor
monitor = WiFiIDSMonitor(MONITOR_INTERFACE)

# Flask routes
@app.route('/')
def index():
    """Serve the dashboard HTML"""
    return render_template('dashboard.html')

@app.route('/api/alerts')
def get_alerts():
    """Get all current alerts"""
    return jsonify(list(alerts))

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    return jsonify(stats)

@app.route('/api/aps')
def get_aps():
    """Get known access points"""
    return jsonify(known_aps)

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    # Send current state to new client
    socketio.emit('initial_data', {
        'alerts': list(alerts),
        'stats': stats,
        'aps': known_aps
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

def start_monitoring_thread():
    """Start the Wi-Fi monitoring in a separate thread"""
    time.sleep(2)  # Wait for Flask to start
    monitor.start()

if __name__ == '__main__':
    # Start monitoring in background thread
    monitor_thread = threading.Thread(target=start_monitoring_thread, daemon=True)
    monitor_thread.start()
    
    print("""
╔══════════════════════════════════════════════════════════════════╗
║           Wi-Fi IDS Dashboard Server                             ║
║           Access at: http://localhost:5000                       ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    # Start Flask server
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
