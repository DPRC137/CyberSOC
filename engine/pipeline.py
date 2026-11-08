"""
Detection Pipeline: Ingestion, Bayesian-Markov Processing & Alert Persistence
=============================================================================
Orchestrates the entire detection flow:
Raw Event -> Standardize -> Bayesian Classification -> Markov Sequence Tracking
-> Hybrid Risk Fusion -> SQLite Storage -> Alert Generation (if R >= threshold).
"""

import json
import sqlite3
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import pandas as pd

from models.bayesian_classifier import BayesianClassifier
from models.markov_analyzer import MarkovSequenceAnalyzer
from models.hybrid_engine import HybridRiskEngine

DB_FILE = 'cyber_soc.db'


class DetectionPipeline:
    """End-to-end pipeline processing events through Bayesian, Markov, and Hybrid models."""

    def __init__(
        self,
        db_path: str = DB_FILE,
        data_path: str = 'intrusion_data.csv',
        alert_threshold: float = 0.60,
    ):
        self.db_path = db_path
        self.bayesian = BayesianClassifier()
        self.markov = MarkovSequenceAnalyzer()
        self.hybrid = HybridRiskEngine(alert_threshold=alert_threshold)

        # Train Bayesian model on dataset if available
        if os.path.exists(data_path):
            df = pd.read_csv(data_path)
            self.bayesian.fit(df)
            self.bayesian.evaluate(df.sample(min(1000, len(df)), random_state=42))

        self._ensure_database()

    def _ensure_database(self):
        """Ensure all required database tables exist without dropping existing data."""
        conn = sqlite3.connect(self.db_path)
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

        conn.commit()
        conn.close()

    def process_event(self, raw_event: dict) -> dict:
        """
        Process a single event through Bayesian, Markov, and Hybrid models.
        Persists event and conditionally generates an alert.
        """
        # 1. Bayesian Classification
        bayes_res = self.bayesian.predict_sample(raw_event)

        # 2. Markov Sequence Analysis
        entity_id = raw_event.get('device') or raw_event.get('source_ip') or 'default-node'
        markov_res = self.markov.record_and_evaluate(entity_id, raw_event)

        # 3. Hybrid Risk Calculation
        hybrid_res = self.hybrid.calculate_risk(bayes_res, markov_res, raw_event)

        event_id = raw_event.get('session_id') or f"EVT-{int(datetime.now(timezone.utc).timestamp()*1000)}"
        timestamp = raw_event.get('timestamp') or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        device = raw_event.get('device', 'Unknown-Device')
        source_ip = raw_event.get('source_ip', '0.0.0.0')

        alert_id = None
        alert_record = None

        # 4. Conditionally Generate & Persist Alert
        if hybrid_res['should_alert']:
            alert_id = f"ALR-HYB-{int(datetime.now(timezone.utc).timestamp()*1000)%1000000:06d}"
            description = (
                f"Hybrid risk {hybrid_res['hybrid_risk']*100:.1f}% detected "
                f"(Bayesian: {hybrid_res['bayesian_prob']*100:.1f}%, "
                f"Markov: {hybrid_res['markov_prob']*100:.1f}%). "
                f"State: {hybrid_res['current_state']}."
            )
            alert_record = {
                'id': alert_id,
                'timestamp': timestamp,
                'severity': hybrid_res['severity'],
                'source_ip': source_ip,
                'device': device,
                'attack_type': hybrid_res['attack_type'],
                'description': description,
                'status': 'new',
                'bayesian_prob': hybrid_res['bayesian_prob'],
                'markov_prob': hybrid_res['markov_prob'],
                'hybrid_risk': hybrid_res['hybrid_risk'],
            }
            self._save_alert(alert_record)

        # 5. Persist Event
        self._save_event({
            'id': event_id,
            'timestamp': timestamp,
            'source_ip': source_ip,
            'device': device,
            'protocol_type': raw_event.get('protocol_type', 'TCP'),
            'network_packet_size': int(raw_event.get('network_packet_size', 500)),
            'session_duration': float(raw_event.get('session_duration', 500)),
            'login_attempts': int(raw_event.get('login_attempts', 1)),
            'failed_logins': int(raw_event.get('failed_logins', 0)),
            'browser_type': str(raw_event.get('browser_type', 'Chrome')),
            'encryption_used': str(raw_event.get('encryption_used', 'AES')),
            'ip_reputation_score': float(raw_event.get('ip_reputation_score', 0.5)),
            'unusual_time_access': int(raw_event.get('unusual_time_access', 0)),
            'markov_state': markov_res['current_state'],
            'bayesian_prob': hybrid_res['bayesian_prob'],
            'markov_prob': hybrid_res['markov_prob'],
            'hybrid_risk': hybrid_res['hybrid_risk'],
            'severity': hybrid_res['severity'],
            'alert_id': alert_id,
        })

        return {
            'event_id': event_id,
            'timestamp': timestamp,
            'device': device,
            'source_ip': source_ip,
            'bayesian': bayes_res,
            'markov': markov_res,
            'hybrid': hybrid_res,
            'alert_generated': alert_id is not None,
            'alert_id': alert_id,
            'alert_record': alert_record,
        }

    def process_batch(self, events: List[dict]) -> List[dict]:
        """Process multiple events sequentially."""
        return [self.process_event(ev) for ev in events]

    def _save_alert(self, a: dict):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute('''
            INSERT OR REPLACE INTO alerts 
            (id, timestamp, severity, source_ip, device, attack_type, description, status, bayesian_prob, markov_prob, hybrid_risk)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            a['id'], a['timestamp'], a['severity'], a['source_ip'], a['device'],
            a['attack_type'], a['description'], a['status'],
            a['bayesian_prob'], a['markov_prob'], a['hybrid_risk']
        ))
        conn.commit()
        conn.close()

    def _save_event(self, e: dict):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute('''
            INSERT OR REPLACE INTO events
            (id, timestamp, source_ip, device, protocol_type, network_packet_size,
             session_duration, login_attempts, failed_logins, browser_type,
             encryption_used, ip_reputation_score, unusual_time_access,
             markov_state, bayesian_prob, markov_prob, hybrid_risk, severity, alert_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            e['id'], e['timestamp'], e['source_ip'], e['device'], e['protocol_type'],
            e['network_packet_size'], e['session_duration'], e['login_attempts'],
            e['failed_logins'], e['browser_type'], e['encryption_used'],
            e['ip_reputation_score'], e['unusual_time_access'], e['markov_state'],
            e['bayesian_prob'], e['markov_prob'], e['hybrid_risk'], e['severity'],
            e['alert_id']
        ))
        conn.commit()
        conn.close()
