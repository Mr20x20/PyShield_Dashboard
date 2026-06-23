# 🛡️ PyShield Dashboard

A real-time security operations dashboard built with Flask and WebSockets, sitting on top of a custom Mini SIEM pipeline. Aggregates live data from four independent sensors, calculates a weighted risk score, detects correlation events, and pushes updates to the browser without polling.

---

## 📸 Dashboard Preview

> Dark SOC-style UI with live risk gauge, trend chart, event breakdown, and live event feed.
> <img width="1915" height="858" alt="image" src="https://github.com/user-attachments/assets/e91cd9ce-8379-4478-876c-9073861521db" />


---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        PyShield Dashboard                       │
│                                                                 │
│  ┌─────────────┐   ┌──────────────┐   ┌────────────────────┐  │
│  │ scheduler.py│   │ ingestion.py │   │    database.py     │  │
│  │             │   │              │   │                    │  │
│  │ port_scanner│──▶│ mini_siem_v2 │──▶│  SQLite history    │  │
│  │ log_analyzer│   │ analyze_     │   │  risk_snapshots    │  │
│  │ fim_monitor │   │ security_    │   │  events            │  │
│  │             │   │ state()      │   │  summary_lines     │  │
│  └─────────────┘   └──────┬───────┘   └────────┬───────────┘  │
│                           │                    │               │
│                    ┌──────▼────────────────────▼───────────┐  │
│                    │              app.py                    │  │
│                    │   Flask + Flask-SocketIO               │  │
│                    │   REST API + WebSocket push            │  │
│                    └──────────────────┬────────────────────┘  │
│                                       │ WebSocket              │
│                    ┌──────────────────▼────────────────────┐  │
│                    │         dashboard.html/js/css          │  │
│                    │  Gauge | Trend | Donut | Feed          │  │
│                    │  Sensor trigger buttons                │  │
│                    └───────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘

Sniffer (pyshield_sniffer_v4.py) runs as a separate admin process
and writes sniffer_report.json — ingested automatically each cycle.
```

---

## 🔍 Sensors

| Sensor | File | Interval | Output |
|---|---|---|---|
| Port Scanner | `port_scanner.py` | 180s / on-demand | `port_scan_report.json` |
| Log Analyzer | `log_analyzer.py` | 60s / on-demand | `log_analysis_report.json` |
| File Integrity Monitor | `secure_monitor.py` | 90s / on-demand | `fim_report.json` |
| IDS Sniffer | `pyshield_sniffer_v4.py` | standalone (admin) | `sniffer_report.json` |
| Mini SIEM | `mini_siem2.py` | 30s aggregation | `siem_final_report.json` |

---

## ⚙️ Risk Scoring

The SIEM engine applies weighted scoring rules across all sensor outputs:

| Event | Score |
|---|---|
| Failed login (per attempt) | +1 |
| Brute force — MEDIUM severity | +5 |
| Brute force — HIGH/CRITICAL severity | +10 |
| File modified (per file) | +7 |
| Untracked file created (per file) | +4 |
| Open port — critical (22, 21, 23, 80, 443) | +5 |
| Open port — other | +2 |
| Live port scan alert (per alert) | +8 |
| Live SYN flood alert (per alert) | +12 |
| Correlation: brute force + open ports | +15 |
| Correlation: live scan + brute force | +20 |
| Correlation: live SYN flood active | +10 |

**Risk Levels:** `CLEAN (0)` → `LOW (<5)` → `MEDIUM (<12)` → `HIGH (<20)` → `CRITICAL (20+)`

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Mr20x20/pyshield-dashboard.git
cd pyshield-dashboard
```

### 2. Create virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set up File Integrity Monitor keys (first time only)

```bash
python secure_monitor.py generate-keys
```

Then place files you want to monitor inside the `monitored\` folder and sign them:

```bash
python secure_monitor.py save monitored\yourfile.txt
```

### 5. (Optional) Run the IDS sniffer in a separate terminal as admin

```bash
# Windows — run as Administrator
python pyshield_sniffer_v4.py
```

### 6. Start the dashboard

```bash
python app.py
```

Open your browser at **http://127.0.0.1:5000**

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Dashboard UI |
| GET | `/api/latest` | Latest SIEM snapshot |
| GET | `/api/history` | Last 60 risk score snapshots |
| GET | `/api/event-counts` | Event type frequencies |
| GET | `/api/sensor-status` | Last run time per sensor |
| POST | `/api/run/port_scanner` | Trigger port scan immediately |
| POST | `/api/run/log_analyzer` | Trigger log analysis immediately |
| POST | `/api/run/secure_monitor` | Trigger FIM scan immediately |
| POST | `/api/run/siem` | Force SIEM re-evaluation + push |

---

## 📁 Project Structure

```
pyshield-dashboard/
├── app.py                    # Flask + SocketIO server, REST API
├── ingestion.py              # Calls mini_siem2 and returns report dict
├── scheduler.py              # Background sensor threads + manual triggers
├── database.py               # SQLite persistence layer
├── mini_siem2.py             # SIEM aggregation + correlation engine
├── port_scanner.py           # Multithreaded TCP port scanner
├── log_analyzer.py           # SSH auth log parser and brute-force detector
├── secure_monitor.py         # RSA-signed file integrity monitor
├── pyshield_sniffer_v4.py    # Scapy-based IDS (port scan + SYN flood)
├── real_auth.log             # Sample auth log for testing
├── requirements.txt
├── templates/
│   └── dashboard.html
├── static/
│   ├── dashboard.js          # WebSocket client + Chart.js logic
│   └── style.css             # SOC dark theme
├── monitored/                # Directory watched by FIM sensor
└── data/
    └── pyshield.db           # SQLite database (auto-created)
```

---

## 🛠️ Tech Stack

- **Backend:** Python 3.11+, Flask, Flask-SocketIO
- **Real-time:** WebSockets (Socket.IO)
- **Database:** SQLite with WAL mode
- **Network:** Scapy (IDS sniffer)
- **Crypto:** cryptography (RSA-signed FIM)
- **Frontend:** Vanilla JS, Chart.js 4, Socket.IO client
- **Styling:** Custom CSS — SOC dark terminal theme

---

## 🔐 Security Notes

- The IDS sniffer requires **administrator / root privileges** to capture raw packets
- This tool is designed for **authorized lab environments only**
- Port scanning targets are set to `127.0.0.1` (localhost) by default

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Yasin.m** — Security Engineering Enthusiast  
GitHub: [github.com/Mr20x20](https://github.com/Mr20x20)
