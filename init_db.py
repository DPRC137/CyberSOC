import sqlite3
import random
import time
from datetime import datetime, timedelta, timezone
import os
import sys

DB_FILE = 'cyber_soc.db'

ATTACK_TYPES = [
    "DDoS Flood", "SQL Injection", "Brute Force", "Man-in-the-Middle",
    "Ransomware", "Phishing Payload", "Zero-Day Exploit", "DNS Tunneling",
    "ARP Spoofing", "Buffer Overflow", "XSS Attack", "Port Scanning",
    "Credential Stuffing", "Firmware Exploit", "Botnet C2 Communication",
    "Privilege Escalation", "Data Exfiltration", "Cryptojacking",
    "Session Hijacking", "API Abuse"
]

DEVICE_NAMES = [
    "Lobby-Cam-01", "Lobby-Cam-02", "Server-Room-Therm", "Main-Entry-Lock",
    "Warehouse-Motion-01", "Office-Light-A1", "Edge-Gateway-01", "Edge-Gateway-02",
    "Kitchen-Plug-01", "Floor3-Smoke-01", "Basement-Water-01", "Hub-Central",
    "Reception-Phone", "Conf-Speaker-01", "AQ-Monitor-Lab", "Energy-Meter-Main",
]

SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_WEIGHTS = [0.1, 0.25, 0.35, 0.3]

def _random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _time_ago(minutes):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

def init_db(force_reset=False):
    if force_reset and os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print(f"Force reset requested: Removed {DB_FILE}.")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            timestamp TEXT,
            severity TEXT,
            source_ip TEXT,
            device TEXT,
            attack_type TEXT,
            description TEXT,
            status TEXT,
            bayesian_prob REAL,
            markov_prob REAL,
            hybrid_risk REAL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            timestamp TEXT,
            source_ip TEXT,
            device TEXT,
            protocol_type TEXT,
            network_packet_size INTEGER,
            session_duration REAL,
            login_attempts INTEGER,
            failed_logins INTEGER,
            browser_type TEXT,
            encryption_used TEXT,
            ip_reputation_score REAL,
            unusual_time_access INTEGER,
            markov_state TEXT,
            bayesian_prob REAL,
            markov_prob REAL,
            hybrid_risk REAL,
            severity TEXT,
            alert_id TEXT
        )
    ''')

    # Ensure schema migration for alerts table
    cursor.execute("PRAGMA table_info(alerts)")
    existing_cols = [r[1] for r in cursor.fetchall()]
    for col in ['bayesian_prob', 'markov_prob', 'hybrid_risk']:
        if col not in existing_cols:
            cursor.execute(f"ALTER TABLE alerts ADD COLUMN {col} REAL")

    cursor.execute("SELECT COUNT(*) FROM alerts")
    count = cursor.fetchone()[0]

    if count > 0:
        print(f"Database {DB_FILE} already initialized with {count} alerts. Preserving existing records.")
        conn.commit()
        conn.close()
        return

    seed = int(time.time() // 15)
    rng = random.Random(seed)
    seed_count = rng.randint(45, 60)

    alerts_data = []
    for i in range(seed_count):
        r = random.Random(seed + i)
        severity = r.choices(SEVERITIES, weights=SEVERITY_WEIGHTS)[0]
        
        alert_id = f"ALR-{seed % 10000:04d}-{i:03d}"
        timestamp = _time_ago(r.randint(0, 1440))
        source_ip = _random_ip()
        device = r.choice(DEVICE_NAMES)
        attack_type = r.choice(ATTACK_TYPES)
        description = r.choice([
            "Multiple failed authentication attempts detected",
            "Suspicious outbound connection to known C2 server",
            "Firmware integrity check failed",
            "Unusual data transfer volume detected",
            "Port scan detected from internal network",
            "Privilege escalation attempt blocked",
            "Malware signature match in network traffic",
            "Unauthorized API access attempt",
            "Certificate validation failure",
            "Anomalous DNS resolution pattern",
        ])
        status = r.choices(["new", "investigating", "resolved", "dismissed"], weights=[0.6, 0.2, 0.1, 0.1])[0]

        if severity == 'critical':
            b_prob, m_prob, h_risk = 0.92, 0.88, 0.91
        elif severity == 'high':
            b_prob, m_prob, h_risk = 0.78, 0.74, 0.76
        elif severity == 'medium':
            b_prob, m_prob, h_risk = 0.52, 0.48, 0.50
        else:
            b_prob, m_prob, h_risk = 0.25, 0.20, 0.22

        alerts_data.append((
            alert_id, timestamp, severity, source_ip, device, attack_type,
            description, status, b_prob, m_prob, h_risk
        ))

    cursor.executemany('''
        INSERT INTO alerts (id, timestamp, severity, source_ip, device, attack_type, description, status, bayesian_prob, markov_prob, hybrid_risk)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', alerts_data)

    conn.commit()
    conn.close()
    print(f"Successfully initialized {DB_FILE} with {seed_count} initial security alerts.")

if __name__ == '__main__':
    force = '--force-reset' in sys.argv
    init_db(force_reset=force)
