import pytest
from models.hybrid_engine import HybridRiskEngine


@pytest.fixture
def hybrid_engine():
    return HybridRiskEngine(weight_bayesian=0.50, weight_markov=0.40, alert_threshold=0.60)


def test_hybrid_risk_normal_calculation(hybrid_engine):
    bayes_res = {'probability_attack': 0.08}
    markov_res = {'markov_probability': 0.05, 'current_state': 'BENIGN_TELEMETRY'}
    raw_event = {'ip_reputation_score': 0.95, 'unusual_time_access': 0, 'failed_logins': 0}

    res = hybrid_engine.calculate_risk(bayes_res, markov_res, raw_event)

    # 0.50 * 0.08 + 0.40 * 0.05 + 0.10 * 0.05 = 0.04 + 0.02 + 0.005 = 0.065
    assert 0.0 <= res['hybrid_risk'] <= 0.20
    assert res['severity'] == "low"
    assert res['should_alert'] is False


def test_hybrid_risk_attack_calculation(hybrid_engine):
    bayes_res = {'probability_attack': 0.92}
    markov_res = {'markov_probability': 0.90, 'current_state': 'EXPLOITATION'}
    raw_event = {'ip_reputation_score': 0.10, 'unusual_time_access': 1, 'failed_logins': 4}

    res = hybrid_engine.calculate_risk(bayes_res, markov_res, raw_event)

    assert res['hybrid_risk'] >= 0.80
    assert res['severity'] == "critical"
    assert res['should_alert'] is True
    assert res['attack_type'] == "Brute Force Authentication"


def test_hybrid_risk_bounds_clamping(hybrid_engine):
    # Extreme inputs cannot exceed [0.0, 1.0]
    bayes_res = {'probability_attack': 1.0}
    markov_res = {'markov_probability': 1.0, 'current_state': 'EXFIL_IMPACT'}
    raw_event = {'ip_reputation_score': 0.0, 'unusual_time_access': 1, 'failed_logins': 10}

    res = hybrid_engine.calculate_risk(bayes_res, markov_res, raw_event)
    assert res['hybrid_risk'] <= 1.0
