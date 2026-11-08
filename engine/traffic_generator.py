"""
Network Traffic Generator for Normal & Malicious IoT Telemetry
==============================================================
Generates mathematically parameterized synthetic traffic events matching
the empirical distribution of IoT intrusion datasets (e.g., intrusion_data.csv).
Capable of generating:
1. Normal routine operational traffic.
2. Multi-stage malicious attack sequences (Recon -> Auth Burst -> Exploit -> Exfiltration).
"""

import random
import time
from datetime import datetime, timezone
from typing import List, Dict

DEVICE_NAMES = [
    "Lobby-Cam-01", "Lobby-Cam-02", "Server-Room-Therm", "Main-Entry-Lock",
    "Warehouse-Motion-01", "Office-Light-A1", "Edge-Gateway-01", "Edge-Gateway-02",
    "Kitchen-Plug-01", "Floor3-Smoke-01", "Basement-Water-01", "Hub-Central",
    "Reception-Phone", "Conf-Speaker-01", "AQ-Monitor-Lab", "Energy-Meter-Main",
]

NORMAL_BROWSERS = ["Chrome", "Firefox", "Edge", "Safari"]


class TrafficGenerator:
    """Generates synthetic normal and malicious IoT network traffic."""

    def __init__(self, seed: int = None):
        self.rng = random.Random(seed)
        self.seq_counter = 1

    def generate_normal_event(self, device: str = None, source_ip: str = None) -> dict:
        """Generate a realistic benign IoT network event matching intrusion_data.csv distribution."""
        if not device:
            device = self.rng.choice(DEVICE_NAMES)
        if not source_ip:
            source_ip = f"192.168.{self.rng.randint(1, 10)}.{self.rng.randint(2, 250)}"

        event_id = f"EVT-NORM-{int(time.time())}-{self.seq_counter:04d}"
        self.seq_counter += 1

        return {
            'session_id': event_id,
            'timestamp': datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            'source_ip': source_ip,
            'device': device,
            'protocol_type': self.rng.choices(["TCP", "UDP"], weights=[0.8, 0.2])[0],
            'network_packet_size': int(self.rng.gauss(490, 70)),
            'login_attempts': self.rng.choice([1, 2, 3]),
            'failed_logins': 0,
            'session_duration': round(max(50.0, self.rng.gauss(500, 150)), 2),
            'encryption_used': self.rng.choices(["AES", "DES"], weights=[0.85, 0.15])[0],
            # In intrusion_data.csv, normal IP threat score has mean 0.297, max 0.599
            'ip_reputation_score': round(self.rng.uniform(0.20, 0.35), 4),
            'browser_type': self.rng.choice(NORMAL_BROWSERS),
            'unusual_time_access': 0,
            'traffic_type': 'normal',
        }

    def generate_malicious_event(
        self,
        attack_phase: str = "brute_force",
        device: str = None,
        source_ip: str = None,
    ) -> dict:
        """Generate a realistic malicious IoT network event corresponding to an attack phase."""
        if not device:
            device = self.rng.choice(DEVICE_NAMES)
        if not source_ip:
            source_ip = f"{self.rng.randint(100, 220)}.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}"

        event_id = f"EVT-ATK-{int(time.time())}-{self.seq_counter:04d}"
        self.seq_counter += 1

        if attack_phase == "recon":
            # Reconnaissance port scan
            return {
                'session_id': event_id,
                'timestamp': datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                'source_ip': source_ip,
                'device': device,
                'protocol_type': self.rng.choice(["ICMP", "TCP"]),
                'network_packet_size': int(self.rng.gauss(150, 40)),
                'login_attempts': 1,
                'failed_logins': 1,
                'session_duration': round(max(2.0, self.rng.gauss(30, 10)), 2),
                'encryption_used': 'None',
                'ip_reputation_score': round(self.rng.uniform(0.55, 0.75), 4),
                'browser_type': "Unknown",
                'unusual_time_access': 1,
                'traffic_type': 'malicious',
                'attack_phase': 'recon',
            }
        elif attack_phase == "brute_force":
            # Password brute force (failed_logins >= 3 has 100% attack correlation)
            return {
                'session_id': event_id,
                'timestamp': datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                'source_ip': source_ip,
                'device': device,
                'protocol_type': "TCP",
                'network_packet_size': int(self.rng.gauss(520, 60)),
                'login_attempts': self.rng.randint(6, 10),
                'failed_logins': self.rng.randint(3, 5),
                'session_duration': round(max(60.0, self.rng.gauss(800, 120)), 2),
                'encryption_used': self.rng.choice(["DES", "None"]),
                'ip_reputation_score': round(self.rng.uniform(0.65, 0.90), 4),
                'browser_type': "Unknown",
                'unusual_time_access': 1,
                'traffic_type': 'malicious',
                'attack_phase': 'brute_force',
            }
        elif attack_phase == "exploit":
            # Buffer overflow / payload exploitation
            return {
                'session_id': event_id,
                'timestamp': datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                'source_ip': source_ip,
                'device': device,
                'protocol_type': "TCP",
                'network_packet_size': int(self.rng.gauss(1150, 80)),
                'login_attempts': self.rng.randint(3, 6),
                'failed_logins': self.rng.randint(3, 4),
                'session_duration': round(max(500.0, self.rng.gauss(1800, 300)), 2),
                'encryption_used': "None",
                'ip_reputation_score': round(self.rng.uniform(0.70, 0.92), 4),
                'browser_type': "Unknown",
                'unusual_time_access': 1,
                'traffic_type': 'malicious',
                'attack_phase': 'exploit',
            }
        else:  # exfiltration
            return {
                'session_id': event_id,
                'timestamp': datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                'source_ip': source_ip,
                'device': device,
                'protocol_type': "UDP",
                'network_packet_size': int(self.rng.gauss(1250, 40)),
                'login_attempts': 2,
                'failed_logins': 3,
                'session_duration': round(max(1000.0, self.rng.gauss(4200, 500)), 2),
                'encryption_used': "DES",
                'ip_reputation_score': round(self.rng.uniform(0.75, 0.92), 4),
                'browser_type': "Unknown",
                'unusual_time_access': 1,
                'traffic_type': 'malicious',
                'attack_phase': 'exfiltration',
            }

    def generate_batch(self, count: int, normal_ratio: float = 0.7) -> List[dict]:
        """Generate a mixed batch of normal and malicious events."""
        events = []
        for _ in range(count):
            if self.rng.random() < normal_ratio:
                events.append(self.generate_normal_event())
            else:
                phase = self.rng.choice(["recon", "brute_force", "exploit", "exfiltration"])
                events.append(self.generate_malicious_event(attack_phase=phase))
        return events
