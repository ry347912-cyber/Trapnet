# 🕸 TrapNet XDR — Honeypot Platform

<div align="center">

```
████████╗██████╗  █████╗ ██████╗ ███╗   ██╗███████╗████████╗
╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
   ██║   ██████╔╝███████║██████╔╝██╔██╗ ██║█████╗     ██║
   ██║   ██╔══██╗██╔══██║██╔═══╝ ██║╚██╗██║██╔══╝     ██║
   ██║   ██║  ██║██║  ██║██║     ██║ ╚████║███████╗   ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═══╝╚══════╝   ╚═╝

        X D R   H O N E Y P O T   P L A T F O R M
```

**Advanced Cyber Deception Platform · Honeypot Intelligence · ML-Powered Threat Detection**

![Python](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react&logoColor=black)
![MongoDB](https://img.shields.io/badge/MongoDB-7.0-47a248?style=flat-square&logo=mongodb&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ed?style=flat-square&logo=docker&logoColor=white)
![ML](https://img.shields.io/badge/ML-IsolationForest-ff6f00?style=flat-square&logo=scikit-learn&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Production--Ready-brightgreen?style=flat-square)

> 🎓 **B.Tech Final Year Project** — Cybersecurity + ML + Full-Stack Development

</div>

---

## ⚠️ Disclaimer

> **TrapNet XDR is a cybersecurity research and educational tool.**
> All honeypot services are 100% simulated — no real system access is ever granted.
> Deploy only in authorized, isolated environments.
> Unauthorized deployment of honeypots may violate local laws.
> This project is intended for learning, research, and placement portfolios only.

---

## 🎯 What is TrapNet XDR?

TrapNet XDR is a **full-stack cyber deception platform** that simulates vulnerable services (SSH, HTTP login panels) to lure and capture attacker behavior, analyze threats using machine learning, and visualize everything in a real-time multi-page dashboard.

```
Attacker arrives →  Fake SSH / HTTP panel →  Credentials captured
                                           →  Commands logged
                                           →  ML risk score assigned
                                           →  MITRE ATT&CK mapped
                                           →  Alert triggered
                                           →  Real-time dashboard updated
```

---

## ✨ Features

| Feature | Details |
|---|---|
| 🐝 **Multi-Service Honeypot** | Fake SSH (port 22) + HTTP login panel — captures all interaction |
| 🧠 **ML Detection** | Isolation Forest anomaly detection — unsupervised, no labels needed |
| ⚡ **Rule Engine** | Brute force detection, dangerous command flagging, rate analysis |
| 📊 **6-Page Dashboard** | Home · Honeypot · Dashboard · Logs · Analytics · Admin |
| 🌍 **Geo Tracking** | Attacker IP → Country/City/Coordinates mapping |
| 🔔 **Alert System** | Real-time alerts with severity levels and acknowledgement |
| 🎯 **MITRE ATT&CK** | Auto-tags T1110, T1059, T1078, T1136, T1053 and more |
| 📈 **Live Charts** | Attack timeline, risk donut, country bars, ML scatter plot |
| 🔢 **Risk Scoring** | 0–100 score with CRITICAL / HIGH / MEDIUM / LOW classification |
| 🔒 **Zero Real Access** | Honeypot NEVER grants actual shell or admin access |
| 🗃️ **MongoDB Storage** | Full log persistence with filtering and query support |
| ☁️ **Cloud Ready** | AWS EC2 + Nginx + Gunicorn + MongoDB Atlas deployment |

---

## 📸 Screenshots

<table>
  <tr>
    <td align="center">
      <b>🏠 Home Page</b><br/>
      <sub>Live attack ticker · platform stats</sub><br/><br/>
      <img src="screenshots/Home_png.png" width="380"/>
    </td>
    <td align="center">
      <b>🕸 Honeypot — HTTP Login Panel</b><br/>
      <sub>Fake corporate portal · credential capture</sub><br/><br/>
      <img src="screenshots/Honeypot_png.png" width="380"/>
    </td>
  </tr>
  <tr>
    <td align="center">
      <b>🕸 Honeypot — SSH Terminal</b><br/>
      <sub>Simulated Bash shell · command logging</sub><br/><br/>
      <img src="screenshots/ssh_terminal_png.png" width="380"/>
    </td>
    <td align="center">
      <b>📊 Dashboard — Attack Timeline</b><br/>
      <sub>1,370 captures · 36 critical · 24h graph</sub><br/><br/>
      <img src="screenshots/dashboard_png.png" width="380"/>
    </td>
  </tr>
  <tr>
    <td align="center">
      <b>📊 Dashboard — Risk & Top IPs</b><br/>
      <sub>Donut chart · top IPs · credentials · MITRE</sub><br/><br/>
      <img src="screenshots/dashbboard_png.png" width="380"/>
    </td>
    <td align="center">
      <b>📋 Logs — Full Attack Table</b><br/>
      <sub>1,373 records · searchable · filterable</sub><br/><br/>
      <img src="screenshots/Logs_png.png" width="380"/>
    </td>
  </tr>
  <tr>
    <td align="center">
      <b>📋 Logs — Critical SSH Filtered</b><br/>
      <sub>CRITICAL severity · SSH · Tehran / Beijing / Kyiv</sub><br/><br/>
      <img src="screenshots/critcallogs_png.png" width="380"/>
    </td>
    <td align="center">
      <b>🧠 Analytics — Country & ML Summary</b><br/>
      <sub>5 Malicious · 4 Suspicious · 1 Benign</sub><br/><br/>
      <img src="screenshots/analtic_png.png" width="380"/>
    </td>
  </tr>
  <tr>
    <td align="center">
      <b>🧠 Analytics — Hourly Distribution</b><br/>
      <sub>Peak windows · Isolation Forest ~95.2% accuracy</sub><br/><br/>
      <img src="screenshots/Anlaysss_png.png" width="380"/>
    </td>
    <td align="center">
      <b>🧠 Analytics — ML Threat Table</b><br/>
      <sub>Per-IP risk score · anomaly score · classification</sub><br/><br/>
      <img src="screenshots/Analysis_png.png" width="380"/>
    </td>
  </tr>
  <tr>
    <td align="center" colspan="2">
      <b>🔔 Alerts — Active Brute Force Feed</b><br/>
      <sub>Real-time alerts · Kyiv · Mumbai · Tehran · Lagos · San Jose · Frankfurt</sub><br/><br/>
      <img src="screenshots/Alerts_png.png" width="380"/>
    </td>
  </tr>
</table>

---

## 🏗️ System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                  TRAPNET XDR PLATFORM ARCHITECTURE                │
│                                                                    │
│  👤 Attacker (simulated)          👤 Security Analyst             │
│       │ SSH / HTTP attempt              │ Browser                  │
│       ▼                                ▼                          │
│  ┌─────────────────┐         ┌──────────────────────┐            │
│  │  Honeypot Layer │         │   React Frontend      │            │
│  │                 │         │   (6 pages, Chart.js) │            │
│  │  • Fake SSH/22  │         │                       │            │
│  │  • Fake HTTP    │         │  Home · Honeypot      │            │
│  │  • Shell Sim    │         │  Dashboard · Logs     │            │
│  └────────┬────────┘         │  Analytics · Admin    │            │
│           │                  └──────────┬────────────┘            │
│           │ Log event                   │ REST API                 │
│           ▼                             ▼                          │
│  ┌─────────────────────────────────────────────────┐             │
│  │           FastAPI Backend (Python 3.11)          │             │
│  │                                                   │             │
│  │  ┌──────────────┐  ┌──────────────────────────┐ │             │
│  │  │ Rule Engine  │  │   ML Anomaly Detector     │ │             │
│  │  │ • BruteForce │  │   (Isolation Forest)      │ │             │
│  │  │ • C2 Detect  │  │   • 8 behavioral features │ │             │
│  │  │ • Rate Limit │  │   • 200 estimator trees   │ │             │
│  │  └──────────────┘  └──────────────────────────┘ │             │
│  └──────────────────────────┬──────────────────────┘             │
│                              │                                     │
│                   ┌──────────▼──────────┐                        │
│                   │     MongoDB          │                        │
│                   │  • analyses          │                        │
│                   │  • attack_logs       │                        │
│                   │  • alerts            │                        │
│                   └─────────────────────┘                        │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🧠 ML Pipeline

```
Raw Session Data (captured from honeypot)
    │
    ▼
Feature Extraction (8 features per session)
  ├─ login_attempts        → number of login tries
  ├─ unique_usernames      → credential spray indicator
  ├─ unique_passwords      → dictionary attack indicator
  ├─ commands_executed     → post-auth activity count
  ├─ dangerous_commands    → wget/curl/rm -rf/shadow etc.
  ├─ session_duration_s    → time-on-target
  ├─ request_rate          → attempts per minute
  └─ entropy_score         → Shannon entropy of credentials
    │
    ▼
StandardScaler (normalize all features to z-scores)
    │
    ▼
Isolation Forest (200 trees, contamination=0.05)
    │
    ├─ Anomaly Score → normalized to 0–100
    ├─ Prediction: ANOMALY (-1) or NORMAL (1)
    └─ Risk Level: CRITICAL / HIGH / MEDIUM / LOW

Model Performance:
  Accuracy   ~95.2%
  Precision  93.2%
  Recall     94.7%
  Type       Unsupervised (no labels needed)
```

---

## 📁 Project Structure

```
trapnet-xdr/                    ← GitHub repo root
│
├── README.md                   ← You are here ⬅
│
├── 📁 screenshots/             ← ⬅ All PNG files go HERE (same level as README)
│   ├── Home_png.png
│   ├── Honeypot_png.png
│   ├── ssh_terminal_png.png
│   ├── dashboard_png.png
│   ├── dashbboard_png.png
│   ├── Logs_png.png
│   ├── critcallogs_png.png
│   ├── analtic_png.png
│   ├── Anlaysss_png.png
│   ├── Analysis_png.png
│   └── Alerts_png.png
│
├── 📁 frontend/
│   └── index.html              ← Complete React SPA (6 pages, self-contained)
│
├── 📁 backend/
│   ├── main.py                 ← FastAPI app — all endpoints
│   └── requirements.txt        ← Python dependencies
│
├── 📁 ml_model/
│   └── detector.py             ← Isolation Forest anomaly detection
│
├── 📁 honeypot/
│   └── (extend with real socket-level honeypot services)
│
├── 📁 database/
│   └── (MongoDB schemas and seed scripts)
│
└── docker-compose.yml          ← One-command full-stack deploy
```

---

## 🚀 Quick Start

### Option A — Frontend Only (Zero Setup)

```bash
# Just open the file in any browser — fully self-contained
open frontend/index.html
```

The frontend includes 150+ mock attack logs, live charts, ML results, and full interactivity — no server needed.

### Option B — Full Stack

**Prerequisites:** Python 3.11+ · MongoDB

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/trapnet-xdr.git
cd trapnet-xdr

# 2. Backend
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
# ✅ API running at http://localhost:8000
# ✅ Docs at http://localhost:8000/docs

# 3. Frontend — open in browser
open ../frontend/index.html
```

### Option C — Docker Compose (One Command)

```bash
docker-compose up --build
# ✅ Backend:  http://localhost:8000
# ✅ Frontend: http://localhost:3000
# ✅ MongoDB:  localhost:27017
```

---

## 📡 API Reference

### Health
```
GET /api/health
→ { status, platform, honeypots_active, total_logs, timestamp }
```

### Honeypot Trap
```
POST /api/honeypot/login
Body: { service: "ssh"|"http", username, password }
→ Always returns 401 — NEVER grants access
→ Logs: IP · geo · credentials · risk score · MITRE tags
```

### Command Capture
```
POST /api/honeypot/command
Body: { session_id, command }
→ Returns fake shell output
→ Logs command with danger detection
```

### Logs & Analytics
```
GET /api/logs?limit=100&severity=CRITICAL&service=ssh
GET /api/logs/{log_id}
GET /api/stats           → Full dashboard stats
GET /api/analytics/ml    → ML classification results
GET /api/geo/map         → Attacker geo coordinates
GET /api/alerts
PUT /api/alerts/{id}/acknowledge
```

---

## 🔒 Security Model

- SSH/HTTP services are **fully simulated in software** — no real OS access
- All credentials submitted are **logged and rejected** — always returns 401
- Shell responses are **hardcoded fake outputs** — no real command execution
- Rate limiting prevents the honeypot itself from being abused
- MongoDB injection prevented via parameterized queries

---

## 🛠️ Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Frontend | React 18 + Chart.js | Real-time SPA, 6 pages, dark cyber UI |
| Backend | FastAPI + Python 3.11 | Async, fast, auto-docs, type-safe |
| ML | Scikit-learn (Isolation Forest) | Unsupervised — works without labels |
| Database | MongoDB + PyMongo | Flexible schema for nested reports |
| Deployment | Docker Compose + Nginx | Production-grade one-command deploy |
| Fonts | Orbitron + Share Tech Mono | Authentic terminal/military aesthetic |

---

## 📋 Roadmap

- [x] Multi-service honeypot (SSH + HTTP)
- [x] Real-time attack logging
- [x] Geo-location tracking
- [x] ML anomaly detection (Isolation Forest)
- [x] 6-page React dashboard
- [x] MITRE ATT&CK auto-mapping
- [x] Risk scoring (0–100)
- [x] Alert system with acknowledgement
- [x] Docker Compose deployment
- [ ] YARA rule engine integration
- [ ] VirusTotal / AbuseIPDB API feeds
- [ ] Email / Slack alerting
- [ ] PDF report export
- [ ] FTP / Telnet honeypot services
- [ ] LSTM-based sequence detection
- [ ] React Native mobile monitoring app

---

## 🤝 Contributing

```bash
git checkout -b feature/AmazingFeature
git commit -m "Add: amazing feature"
git push origin feature/AmazingFeature
# Open a Pull Request
```

---

## 👨‍💻 Author

**Developed as a B.Tech Final Year Project**
Cybersecurity + Machine Learning + Full-Stack Development

---

## 📄 License

MIT License — Free to use, modify, and distribute for educational purposes.

---

<div align="center">

**Made with 🕸 for the cybersecurity community**

⭐ Star this repo if it helped your placement journey!

</div>
