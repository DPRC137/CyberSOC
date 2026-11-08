"""
Markov Sequence Analyzer for IoT Cyber Threat Tracking
======================================================
Implements a First-Order Discrete-Time Markov Chain (DTMC) sequence analysis
engine to model multi-stage cyber attack kill chains and distinguish benign IoT
temporal patterns from malicious attack progressions.

Mathematical Formulation:
-------------------------
1. State Space S = {s_0, s_1, s_2, s_3, s_4}:
   - s_0: BENIGN_TELEMETRY   (Routine operational telemetry)
   - s_1: RECON_PROBE        (Reconnaissance, port scans, probe packets)
   - s_2: CREDENTIAL_STRESS  (Failed auth bursts, unusual access attempts)
   - s_3: EXPLOITATION       (Active payload exploitation, buffer overflow)
   - s_4: EXFIL_IMPACT       (Data exfiltration, C2 beacon, DoS impact)

2. Transition Probability Matrix T_{i,j} = P(S_t = j | S_{t-1} = i):
   - T_benign: Dominant self-loops on s_0; low transition probabilities to s_3, s_4.
   - T_attack: High forward transition probabilities following MITRE kill chains:
     s_0 -> s_1 -> s_2 -> s_3 -> s_4.

3. Sequence Log-Likelihood Ratio:
   L(S) = sum_{t=2}^L ln( T_attack(s_{t-1}, s_t) / T_benign(s_{t-1}, s_t) )

4. Sigmoidal Sequence Attack Probability:
   P_markov(Attack | S) = 1 / (1 + exp(-L(S)))
"""

import math
import numpy as np
from typing import List, Dict, Optional, Tuple


class MarkovSequenceAnalyzer:
    """Discrete-Time Markov Chain (DTMC) sequence analyzer for temporal attack detection."""

    STATES = [
        "BENIGN_TELEMETRY",
        "RECON_PROBE",
        "CREDENTIAL_STRESS",
        "EXPLOITATION",
        "EXFIL_IMPACT",
    ]
    STATE_INDEX = {s: i for i, s in enumerate(STATES)}

    def __init__(self, window_size: int = 10, laplace_alpha: float = 0.05):
        self.window_size = window_size
        self.laplace_alpha = laplace_alpha

        # Pre-calibrated empirical baseline transition matrices
        # Rows = source state (i), Columns = target state (j)
        self.T_benign = np.array([
            [0.82, 0.08, 0.07, 0.02, 0.01],  # from BENIGN
            [0.65, 0.22, 0.10, 0.02, 0.01],  # from RECON
            [0.60, 0.08, 0.28, 0.03, 0.01],  # from CRED_STRESS
            [0.55, 0.05, 0.08, 0.25, 0.07],  # from EXPLOIT
            [0.70, 0.05, 0.05, 0.08, 0.12],  # from EXFIL
        ], dtype=float)

        self.T_attack = np.array([
            [0.15, 0.45, 0.25, 0.12, 0.03],  # from BENIGN
            [0.05, 0.20, 0.48, 0.22, 0.05],  # from RECON
            [0.02, 0.05, 0.25, 0.55, 0.13],  # from CRED_STRESS
            [0.01, 0.02, 0.05, 0.32, 0.60],  # from EXPLOIT
            [0.02, 0.03, 0.05, 0.25, 0.65],  # from EXFIL
        ], dtype=float)

        # Ensure normalized rows
        self._normalize_matrices()

        # Sliding window sequence history per device or IP: {entity_id: [state_indices]}
        self.entity_history: Dict[str, List[int]] = {}

    def _normalize_matrices(self):
        """Ensure stochastic matrix property: sum_j T_{i,j} = 1."""
        self.T_benign = self.T_benign / self.T_benign.sum(axis=1, keepdims=True)
        self.T_attack = self.T_attack / self.T_attack.sum(axis=1, keepdims=True)

    def classify_state(self, event: dict) -> str:
        """Map an event dictionary into one of the 5 discrete Markov states."""
        failed_logins = int(event.get('failed_logins', 0))
        login_attempts = int(event.get('login_attempts', 1))
        packet_size = float(event.get('network_packet_size', 500))
        browser = str(event.get('browser_type', ''))
        unusual_time = int(event.get('unusual_time_access', 0))
        attack_detected = event.get('attack_detected', None)
        session_duration = float(event.get('session_duration', 500))
        ip_rep = float(event.get('ip_reputation_score', 0.5))

        if failed_logins >= 3 or attack_detected == 1:
            if packet_size > 900 or session_duration > 3500:
                return "EXFIL_IMPACT"
            return "EXPLOITATION"
        elif failed_logins >= 1 or login_attempts >= 4:
            return "CREDENTIAL_STRESS"
        elif browser == 'Unknown' or unusual_time == 1 or packet_size > 800 or ip_rep < 0.2:
            return "RECON_PROBE"
        elif session_duration > 3000:
            return "EXFIL_IMPACT"
        else:
            return "BENIGN_TELEMETRY"

    def record_and_evaluate(self, entity_id: str, event: dict) -> dict:
        """
        Record the next event for entity_id, update Markov sequence, and compute risk.
        Returns detailed transition statistics and Markov probability.
        """
        state_name = self.classify_state(event)
        state_idx = self.STATE_INDEX[state_name]

        if entity_id not in self.entity_history:
            self.entity_history[entity_id] = []

        history = self.entity_history[entity_id]
        prev_idx = history[-1] if history else None
        history.append(state_idx)

        # Enforce sliding window
        if len(history) > self.window_size:
            history.pop(0)

        # Compute sequence metrics
        log_odds, p_markov, step_transitions = self.evaluate_sequence(history)

        last_trans_anomaly = 0.0
        transition_desc = "Initial observation"
        if prev_idx is not None:
            p_b = self.T_benign[prev_idx, state_idx]
            p_a = self.T_attack[prev_idx, state_idx]
            last_trans_anomaly = -math.log(max(p_b, 1e-6))
            transition_desc = f"{self.STATES[prev_idx]} -> {self.STATES[state_idx]}"

        return {
            'entity_id': entity_id,
            'current_state': state_name,
            'current_state_idx': state_idx,
            'previous_state_idx': prev_idx,
            'sequence_length': len(history),
            'log_odds': round(float(log_odds), 4),
            'markov_probability': round(float(p_markov), 4),
            'transition_anomaly_score': round(float(last_trans_anomaly), 4),
            'transition_description': transition_desc,
            'recent_states': [self.STATES[idx] for idx in history],
            'step_transitions': step_transitions,
        }

    def evaluate_sequence(self, state_indices: List[int]) -> Tuple[float, float, List[dict]]:
        """
        Compute sequence log-odds ratio and sigmoidal attack probability.
        """
        if len(state_indices) < 2:
            # Single observation: neutral base prior (p=0.5, log_odds=0.0)
            return 0.0, 0.5, []

        log_odds = 0.0
        step_transitions = []

        for t in range(1, len(state_indices)):
            i = state_indices[t - 1]
            j = state_indices[t]
            p_b = self.T_benign[i, j]
            p_a = self.T_attack[i, j]
            step_lr = math.log(max(p_a, 1e-7) / max(p_b, 1e-7))
            log_odds += step_lr

            step_transitions.append({
                'from_state': self.STATES[i],
                'to_state': self.STATES[j],
                'p_attack_trans': round(float(p_a), 4),
                'p_benign_trans': round(float(p_b), 4),
                'log_ratio': round(float(step_lr), 4),
            })

        # Logistic sigmoid bounded to [0.0, 1.0]
        p_markov = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, log_odds))))
        return log_odds, p_markov, step_transitions

    def get_transition_matrix_data(self) -> dict:
        """Export transition matrices for frontend visualization."""
        return {
            'states': self.STATES,
            'benign_matrix': self.T_benign.round(4).tolist(),
            'attack_matrix': self.T_attack.round(4).tolist(),
        }
