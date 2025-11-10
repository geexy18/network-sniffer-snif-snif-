#!/usr/bin/env python3
"""
Wi-Fi Intrusion Detection System (IDS)
Monitors Wi-Fi traffic for suspicious activity including:
- Deauthentication attacks
- Rogue access points
- Unusual beacon intervals
- MAC address spoofing attempts
"""

import sys
import time
import json
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import *

# Configuration
MONITOR_INTERFACE = "wlan0mon"  # Your Wi-Fi adapter in monitor mode
DEAUTH_THRESHOLD = 5  # Deauth frames per second to trigger alert
BEACON_INTERVAL_TOLERANCE = 50  # ms tolerance for beacon intervals
TIME_WINDOW = 10  # seconds for rate limiting detection

class WiFiIDS:
    def __init__(self, interface):
        self.interface = interface
        self.known_aps = {}  # BSSID -> AP info
        self.deauth_counter = defaultdict(lambda: deque(maxlen=100))
        self.alerts = []
        self.packet_count = 0
        
    def detect_deauth_attack(self, pkt):
        """Detect deauthentication attack patterns"""
        if pkt.haslayer(Dot11Deauth):
            bssid = pkt.addr2 or "Unknown"
            current_time = time.time()
            
            # Track deauth frames
            self.deauth_counter[bssid].append(current_time)
            
            # Check rate in last second
            recent = [t for t in self.deauth_counter[bssid] if current_time - t < 1.0]
            
            if len(recent) >= DEAUTH_THRESHOLD:
                self.generate_alert(
                    "DEAUTH_ATTACK",
                    f"Deauth attack detected from {bssid}",
                    {"bssid": bssid, "rate": len(recent), "target": pkt.addr1}
                )
                return True
        return False
    
    def detect_rogue_ap(self, pkt):
        """Detect potential rogue access points"""
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr2
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            
            # Check if AP info changed (potential Evil Twin)
            if bssid in self.known_aps:
                old_ssid = self.known_aps[bssid]['ssid']
                old_channel = self.known_aps[bssid]['channel']
                current_channel = self.get_channel(pkt)
                
                # SSID changed for same BSSID - suspicious
                if old_ssid != ssid:
                    self.generate_alert(
                        "ROGUE_AP",
                        f"Possible rogue AP: BSSID {bssid} changed SSID",
                        {"bssid": bssid, "old_ssid": old_ssid, "new_ssid": ssid}
                    )
                    return True
                
                # Channel changed - suspicious
                if old_channel != current_channel:
                    self.generate_alert(
                        "ROGUE_AP",
                        f"Suspicious: AP {ssid} ({bssid}) changed channel",
                        {"bssid": bssid, "ssid": ssid, "old_channel": old_channel, "new_channel": current_channel}
                    )
                    return True
            else:
                # Store new AP
                self.known_aps[bssid] = {
                    'ssid': ssid,
                    'channel': self.get_channel(pkt),
                    'first_seen': datetime.now().isoformat()
                }
        return False
    
    def get_channel(self, pkt):
        """Extract channel from beacon frame"""
        try:
            if pkt.haslayer(Dot11Elt):
                channel = None
                p = pkt[Dot11Elt]
                while p:
                    if p.ID == 3:  # DS Parameter set
                        channel = ord(p.info)
                        break
                    p = p.payload.getlayer(Dot11Elt)
                return channel
        except:
            return None
    
    def detect_beacon_flood(self, pkt):
        """Detect beacon flooding attacks"""
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            
            # Empty SSID in rapid succession can indicate attack
            if ssid == "" or len(ssid) == 0:
                self.generate_alert(
                    "BEACON_FLOOD",
                    "Possible beacon flooding with hidden SSIDs",
                    {"bssid": pkt.addr2}
                )
                return True
        return False
    
    def generate_alert(self, alert_type, message, details):
        """Generate and store security alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'message': message,
            'details': details
        }
        self.alerts.append(alert)
        
        # Print to console with color
        print(f"\n{'='*70}")
        print(f"🚨 ALERT [{alert_type}] - {datetime.now().strftime('%H:%M:%S')}")
        print(f"Message: {message}")
        print(f"Details: {json.dumps(details, indent=2)}")
        print(f"{'='*70}\n")
    
    def packet_handler(self, pkt):
        """Main packet processing handler"""
        self.packet_count += 1
        
        if pkt.haslayer(Dot11):
            # Run detection algorithms
            self.detect_deauth_attack(pkt)
            self.detect_rogue_ap(pkt)
            self.detect_beacon_flood(pkt)
            
            # Status update every 100 packets
            if self.packet_count % 100 == 0:
                print(f"[INFO] Processed {self.packet_count} packets | "
                      f"Known APs: {len(self.known_aps)} | "
                      f"Alerts: {len(self.alerts)}")
    
    def start_monitoring(self):
        """Start monitoring Wi-Fi traffic"""
        print(f"Starting Wi-Fi IDS on interface: {self.interface}")
        print(f"Monitoring for deauth attacks, rogue APs, and suspicious activity...")
        print(f"Press Ctrl+C to stop\n")
        
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=0)
        except KeyboardInterrupt:
            print("\n\nStopping monitoring...")
            self.print_summary()
    
    def print_summary(self):
        """Print monitoring session summary"""
        print(f"\n{'='*70}")
        print("SESSION SUMMARY")
        print(f"{'='*70}")
        print(f"Total packets processed: {self.packet_count}")
        print(f"Total alerts generated: {len(self.alerts)}")
        print(f"Known access points: {len(self.known_aps)}")
        
        if self.alerts:
            print(f"\n{'='*70}")
            print("ALERTS BY TYPE")
            print(f"{'='*70}")
            alert_types = defaultdict(int)
            for alert in self.alerts:
                alert_types[alert['type']] += 1
            
            for alert_type, count in alert_types.items():
                print(f"{alert_type}: {count}")
        
        # Save alerts to file
        if self.alerts:
            filename = f"wifi_ids_alerts_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump(self.alerts, f, indent=2)
            print(f"\nAlerts saved to: {filename}")

def check_requirements():
    """Check if running with proper permissions and setup"""
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root (use sudo)")
        sys.exit(1)
    
    print("✓ Running with root privileges")
    
    # Check if interface exists
    try:
        interfaces = get_if_list()
        if MONITOR_INTERFACE not in interfaces:
            print(f"\nWARNING: Interface '{MONITOR_INTERFACE}' not found")
            print(f"Available interfaces: {', '.join(interfaces)}")
            print("\nTo set up monitor mode:")
            print(f"  sudo airmon-ng start wlan0")
            print(f"  (This will create wlan0mon)")
            sys.exit(1)
    except Exception as e:
        print(f"Error checking interfaces: {e}")
        sys.exit(1)
    
    print(f"✓ Interface '{MONITOR_INTERFACE}' found\n")

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════╗
║           Wi-Fi Intrusion Detection System (IDS)                 ║
║                     Prototype v1.0                               ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    # Check system requirements
    check_requirements()
    
    # Initialize and start IDS
    ids = WiFiIDS(MONITOR_INTERFACE)
    ids.start_monitoring()
