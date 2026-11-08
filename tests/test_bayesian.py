import pytest
import pandas as pd
import numpy as np
import os
from models.bayesian_classifier import BayesianClassifier

DATASET_PATH = 'intrusion_data.csv'


@pytest.fixture
def trained_bayesian():
    clf = BayesianClassifier()
    assert os.path.exists(DATASET_PATH), f"{DATASET_PATH} must exist"
    df = pd.read_csv(DATASET_PATH)
    clf.fit(df)
    return clf


def test_bayesian_training_and_priors(trained_bayesian):
    assert trained_bayesian.is_trained is True
    p0 = trained_bayesian.priors[0]
    p1 = trained_bayesian.priors[1]
    assert 0.0 < p0 < 1.0
    assert 0.0 < p1 < 1.0
    assert pytest.approx(p0 + p1, abs=1e-3) == 1.0


def test_bayesian_normal_event_prediction(trained_bayesian):
    normal_sample = {
        'protocol_type': 'TCP',
        'network_packet_size': 480,
        'login_attempts': 2,
        'session_duration': 400.0,
        'encryption_used': 'AES',
        'ip_reputation_score': 0.28,
        'failed_logins': 0,
        'browser_type': 'Chrome',
        'unusual_time_access': 0,
    }
    res = trained_bayesian.predict_sample(normal_sample)
    assert 0.0 <= res['probability_normal'] <= 1.0
    assert 0.0 <= res['probability_attack'] <= 1.0
    assert pytest.approx(res['probability_normal'] + res['probability_attack'], abs=1e-5) == 1.0
    # Normal event should have high normal probability
    assert res['probability_normal'] > res['probability_attack']
    assert res['predicted_class'] == 0


def test_bayesian_malicious_event_prediction(trained_bayesian):
    # Brute force attack: 4 failed logins, unknown browser, elevated threat IP reputation
    malicious_sample = {
        'protocol_type': 'TCP',
        'network_packet_size': 550,
        'login_attempts': 6,
        'session_duration': 800.0,
        'encryption_used': 'None',
        'ip_reputation_score': 0.75,
        'failed_logins': 4,
        'browser_type': 'Unknown',
        'unusual_time_access': 1,
    }
    res = trained_bayesian.predict_sample(malicious_sample)
    assert res['probability_attack'] > 0.70
    assert res['predicted_class'] == 1
    # Evidence for failed_logins should be positive
    assert 'failed_logins' in res['feature_contributions']
    assert res['feature_contributions']['failed_logins'] > 0


def test_bayesian_evaluation_metrics(trained_bayesian):
    df = pd.read_csv(DATASET_PATH)
    test_subset = df.sample(500, random_state=42)
    metrics = trained_bayesian.evaluate(test_subset)

    assert metrics['accuracy'] >= 0.80
    assert metrics['precision'] >= 0.80
    assert metrics['recall'] >= 0.65
    assert metrics['f1_score'] >= 0.75
    assert metrics['roc_auc'] >= 0.80
    cm = metrics['confusion_matrix']
    assert cm['tp'] + cm['tn'] + cm['fp'] + cm['fn'] == 500
