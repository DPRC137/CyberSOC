"""
Hybrid Threat Detection & Risk Engine
====================================
Fuses point-in-time Bayesian classification with temporal Markov sequence analysis
into a mathematically calibrated hybrid risk score.

Mathematical Formulation:
-------------------------
1. Linear Convex Fusion with Contextual Correction:
   R_raw = w_B * P_Bayes + w_M * P_Markov + Delta_context
   where:
   - w_B = 0.50 (Bayesian spatial weight)
   - w_M = 0.40 (Markov temporal weight)
   - Delta_context = 0.10 * (1.0 - IP_reputation) + 0.05 * Unusual_Time

2. Clamping:
   R_Hybrid = clip(R_raw, 0.0, 1.0)

3. Severity Mapping:
   - R_Hybrid >= 0.80: "critical"
   - 0.60 <= R_Hybrid < 0.80: "high"
   - 0.35 <= R_Hybrid < 0.60: "medium"
   - R_Hybrid < 0.35: "low"

4. Alert Rule:
   Trigger security alert if R_Hybrid >= alert_threshold (default: 0.60).
"""

from typing import Dict, Any, Optional
import uuid
from datetime import datetime


class HybridRiskEngine:
    """Fuses Bayesian point-in-time and Markov sequence probabilities into hybrid risk."""

    def __init__(
        self,
        weight_bayesian: float = 0.50,
        weight_markov: float = 0.40,
        alert_threshold: float = 0.60,
    ):
        self.weight_bayesian = weight_bayesian
        self.weight_markov = weight_markov
        self.alert_threshold = alert_threshold

    def calculate_risk(
        self,
        bayesian_result: dict,
        markov_result: dict,
        raw_event: dict,
    ) -> dict:
        """
        Calculate mathematical hybrid risk score and determine if an alert should fire.
        """
        p_bayes = float(bayesian_result.get('probability_attack', 0.0))
        p_markov = float(markov_result.get('markov_probability', 0.5))

        # Contextual penalty
        ip_rep = float(raw_event.get('ip_reputation_score', 0.5))
        unusual_time = int(raw_event.get('unusual_time_access', 0))
        failed_logins = int(raw_event.get('failed_logins', 0))

        context_penalty = 0.10 * (1.0 - ip_rep)
        if unusual_time == 1:
            context_penalty += 0.05
        if failed_logins >= 3:
            context_penalty += 0.05

        # Raw risk calculation
        raw_score = (
            self.weight_bayesian * p_bayes
            + self.weight_markov * p_markov
            + context_penalty
        )
        hybrid_risk = max(0.0, min(1.0, raw_score))

        # Severity categorization
        if hybrid_risk >= 0.80:
            severity = "critical"
        elif hybrid_risk >= 0.60:
            severity = "high"
        elif hybrid_risk >= 0.35:
            severity = "medium"
        else:
            severity = "low"

        should_alert = hybrid_risk >= self.alert_threshold

        # Determine inferred attack type based on Markov state & Bayesian contributions
        current_state = markov_result.get('current_state', 'BENIGN_TELEMETRY')
        attack_type = self._infer_attack_type(current_state, raw_event, bayesian_result)

        return {
            'hybrid_risk': round(float(hybrid_risk), 4),
            'bayesian_prob': round(float(p_bayes), 4),
            'markov_prob': round(float(p_markov), 4),
            'context_penalty': round(float(context_penalty), 4),
            'severity': severity,
            'should_alert': should_alert,
            'current_state': current_state,
            'attack_type': attack_type,
            'weights': {
                'bayesian': self.weight_bayesian,
                'markov': self.weight_markov,
            },
        }

    def _infer_attack_type(self, state: str, event: dict, bayes_res: dict) -> str:
        failed_logins = int(event.get('failed_logins', 0))
        packet_size = float(event.get('network_packet_size', 500))
        protocol = str(event.get('protocol_type', 'TCP'))

        if failed_logins >= 3:
            return "Brute Force Authentication"
        elif state == "EXFIL_IMPACT":
            return "Data Exfiltration" if packet_size > 800 else "Botnet C2 Beaconing"
        elif state == "RECON_PROBE":
            return "Port Scanning & Reconnaissance"
        elif state == "EXPLOITATION":
            return f"Zero-Day / Buffer Overflow ({protocol})"
        elif protocol == "ICMP":
            return "ICMP Flood Anomaly"
        elif bayes_res.get('probability_attack', 0) > 0.7:
            return "Multi-Stage Network Intrusion"
        else:
            return "Benign Operational Traffic"
