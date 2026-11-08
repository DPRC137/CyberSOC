import pytest
import numpy as np
from models.markov_analyzer import MarkovSequenceAnalyzer


@pytest.fixture
def markov_analyzer():
    return MarkovSequenceAnalyzer(window_size=10)


def test_transition_matrix_stochastic(markov_analyzer):
    # Each row in transition matrices must sum to 1.0 (stochastic matrix property)
    for i in range(len(markov_analyzer.STATES)):
        assert pytest.approx(markov_analyzer.T_benign[i].sum(), abs=1e-5) == 1.0
        assert pytest.approx(markov_analyzer.T_attack[i].sum(), abs=1e-5) == 1.0


def test_state_classification(markov_analyzer):
    normal_event = {'failed_logins': 0, 'login_attempts': 1, 'network_packet_size': 450, 'browser_type': 'Chrome'}
    assert markov_analyzer.classify_state(normal_event) == "BENIGN_TELEMETRY"

    recon_event = {'browser_type': 'Unknown', 'network_packet_size': 850, 'failed_logins': 0}
    assert markov_analyzer.classify_state(recon_event) == "RECON_PROBE"

    cred_event = {'failed_logins': 2, 'login_attempts': 4}
    assert markov_analyzer.classify_state(cred_event) == "CREDENTIAL_STRESS"

    exploit_event = {'failed_logins': 4, 'network_packet_size': 600}
    assert markov_analyzer.classify_state(exploit_event) == "EXPLOITATION"

    exfil_event = {'failed_logins': 3, 'network_packet_size': 1200}
    assert markov_analyzer.classify_state(exfil_event) == "EXFIL_IMPACT"


def test_benign_vs_attack_sequence_probabilities(markov_analyzer):
    # Benign sequence: repeated BENIGN states
    benign_seq = [0, 0, 0, 0, 0]  # BENIGN -> BENIGN -> ...
    log_odds_b, p_b, _ = markov_analyzer.evaluate_sequence(benign_seq)
    assert p_b < 0.15
    assert log_odds_b < 0.0

    # Malicious kill chain sequence: BENIGN -> RECON -> CRED_STRESS -> EXPLOIT -> EXFIL
    attack_seq = [0, 1, 2, 3, 4]
    log_odds_a, p_a, steps = markov_analyzer.evaluate_sequence(attack_seq)
    assert p_a > 0.85
    assert log_odds_a > 0.0
    assert len(steps) == 4


def test_sliding_window_memory(markov_analyzer):
    entity = "Camera-DMZ"
    for _ in range(15):
        markov_analyzer.record_and_evaluate(entity, {'failed_logins': 0, 'browser_type': 'Chrome'})

    assert len(markov_analyzer.entity_history[entity]) == 10
