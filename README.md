# 🛡️ Wi-Fi Intrusion Detection System (IDS)

A real-time wireless network security monitoring system built for Raspberry Pi that detects and alerts on suspicious Wi-Fi activity.

![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## 🎯 Features

- **Real-time Detection**
  - ⚠️ Deauthentication attacks (DoS)
  - 🔴 Rogue/Evil Twin access points
  - 📡 Beacon flooding attacks
  - 🔄 MAC address spoofing

- **Live Web Dashboard**
  - 📊 Real-time statistics and metrics
  - 🚨 Color-coded alerts with severity levels
  - 📱 Responsive design (mobile-friendly)
  - 🔔 Audio notifications for critical alerts
  - 📡 Discovered access points panel

- **Production Ready**
  - 🔧 Systemd service integration
  - 📝 Comprehensive logging
  - 💾 JSON alert export
  - ⚙️ Configurable detection thresholds

## 📋 Requirements

### Hardware
- Raspberry Pi (3B+, 4, or 5)
- USB Wi-Fi adapter with **monitor mode support**
  - Recommended: Alfa AWUS036NHA, TP-Link TL-WN722N v1
- MicroSD card (16GB+)
- Power supply

### Software
- Raspberry Pi OS (Lite or Desktop)
- Python 3.7+
- See `requirements.txt` for Python dependencies

## 🚀 Quick Start

### 1. Clone or Download Project

```bash
mkdir ~/wifi-ids
cd ~/wifi-ids
# Copy all project files here
```

### 2. Run Automated Installation

```bash
sudo bash install.sh
```

### 3. Copy Project Files

Place the following files in the project directory:
- `wifi_ids.py` → Main directory
- `wifi_ids_server.py` → Main directory
- `dashboard.html` → `templates/` directory
- `requirements.txt` → Main directory

### 4. Enable Monitor Mode

```bash
sudo airmon-ng start wlan0
# This creates wlan0mon interface
```

### 5. Start the Dashboard

```bash
cd ~/wifi-ids
sudo venv/bin/python wifi_ids_server.py
```

### 6. Access Dashboard

Open browser and navigate to:
```
http://[raspberry-pi-ip]:5000
```

## 📁 Project Structure

```
wifi-ids/
├── wifi_ids.py              # Standalone IDS (console)
├── wifi_ids_server.py       # Dashboard server with IDS
├── requirements.txt         # Python dependencies
├── config.py               # Configuration file
├── install.sh              # Automated installer
├── templates/
│   └── dashboard.html      # Web dashboard
├── logs/                   # Log files
└── data/                   # Alert exports
```

## ⚙️ Configuration

Edit `config.py` to customize:

```python
# Detection sensitivity
DEAUTH_THRESHOLD = 5        # Lower = more sensitive

# Network interface
MONITOR_INTERFACE = "wlan0mon"

# Dashboard settings
DASHBOARD_PORT = 5000
```

## 🔧 Usage

### Console Mode (No Dashboard)

```bash
sudo venv/bin/python wifi_ids.py
```

### Dashboard Mode (Recommended)

```bash
sudo venv/bin/python wifi_ids_server.py
```

### Run as Service

```bash
# Enable service
sudo systemctl enable wifi-ids

# Start service
sudo systemctl start wifi-ids

# Check status
sudo systemctl status wifi-ids

# View logs
sudo journalctl -u wifi-ids -f
```

## 📊 Dashboard Features

### Statistics Panel
- Total packets processed
- Alert counts by type
- Known access points
- Real-time updates

### Alert Panel
- Severity indicators (Critical/High/Medium)
- Detailed attack information
- Timestamps
- Attack metadata (BSSID, targets, etc.)

### Access Points Panel
- All discovered APs
- SSID and MAC address
- First seen timestamp

## 🔒 Security Notes

### ⚠️ Legal Warning

**This tool is for educational and authorized testing only!**

- ✅ Only monitor networks you own
- ✅ Get explicit permission for any security testing
- ❌ Unauthorized network monitoring may be illegal
- ❌ Do not use for malicious purposes

### Best Practices

1. Keep system updated: `sudo apt update && sudo apt upgrade`
2. Use strong passwords for Pi
3. Enable firewall: `sudo ufw enable`
4. Disable password SSH (use keys)
5. Change default configuration

## 🐛 Troubleshooting

### No packets captured

```bash
# Verify monitor mode
iwconfig

# Check interface
sudo airodump-ng wlan0mon
```

### Permission errors

```bash
# Always use sudo for packet capture
sudo venv/bin/python wifi_ids_server.py
```

### Dashboard not loading

```bash
# Check if service is running
sudo netstat -tulpn | grep 5000

# Check firewall
sudo ufw allow 5000/tcp
```

### High CPU usage

```bash
# Reduce processing load in config.py
# Increase DEAUTH_THRESHOLD
# Filter by specific channels
```

## 📈 Extending the Project

### Add Email Alerts

```python
import smtplib
from email.mime.text import MIMEText

def send_alert_email(alert):
    # Implementation here
    pass
```

### Add Database Storage

```python
from sqlalchemy import create_engine

# Store alerts in SQLite/PostgreSQL
```

### Add Channel Hopping

```python
import subprocess

for channel in range(1, 14):
    subprocess.run(['iwconfig', 'wlan0mon', 'channel', str(channel)])
```

## 📚 Documentation

- [Complete Setup Guide](SETUP_GUIDE.md) - Detailed installation
- [Configuration Options](config.py) - All settings
- [API Documentation](#) - REST endpoints

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- [Scapy](https://scapy.net/) - Packet manipulation library
- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Aircrack-ng](https://aircrack-ng.org/) - Wireless tools
- Raspberry Pi Foundation

## 📞 Support

- Issues: Open a GitHub issue
- Documentation: See SETUP_GUIDE.md
- Security: Report responsibly

## 🎓 Learning Resources

- [IEEE 802.11 Standard](https://standards.ieee.org/standard/802_11-2020.html)
- [Wi-Fi Security Guide](https://www.wi-fi.org/discover-wi-fi/security)
- [Wireless Penetration Testing](https://www.offensive-security.com/)

---

**Built with ❤️ for network security education**

⭐ Star this project if you find it helpful!
