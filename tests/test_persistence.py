import pytest
import sqlite3
import os
import uuid
from engine.pipeline import DetectionPipeline

TEST_DB = 'test_persistence.db'


@pytest.fixture
def clean_test_db():
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    yield TEST_DB
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


def test_database_persistence_across_restarts(clean_test_db):
    # Phase 1: Initialize pipeline with test database
    pipe1 = DetectionPipeline(db_path=clean_test_db, data_path='intrusion_data.csv')

    # Process a normal event and a malicious attack event
    norm_ev = {
        'session_id': 'TEST-PERSIST-001',
        'device': 'Server-Room-Therm',
        'source_ip': '192.168.1.150',
        'protocol_type': 'TCP',
        'network_packet_size': 450,
        'login_attempts': 1,
        'failed_logins': 0,
        'session_duration': 300.0,
        'encryption_used': 'AES',
        'ip_reputation_score': 0.95,
        'browser_type': 'Chrome',
        'unusual_time_access': 0,
    }
    atk_ev = {
        'session_id': 'TEST-PERSIST-002',
        'device': 'Edge-Gateway-01',
        'source_ip': '198.51.100.44',
        'protocol_type': 'TCP',
        'network_packet_size': 600,
        'login_attempts': 8,
        'failed_logins': 5,
        'session_duration': 800.0,
        'encryption_used': 'None',
        'ip_reputation_score': 0.05,
        'browser_type': 'Unknown',
        'unusual_time_access': 1,
    }

    res1 = pipe1.process_event(norm_ev)
    res2 = pipe1.process_event(atk_ev)

    assert res2['alert_generated'] is True
    generated_alert_id = res2['alert_id']

    # Phase 2: Simulate application shutdown / restart
    del pipe1

    # Reconnect and inspect SQLite directly
    conn = sqlite3.connect(clean_test_db)
    cur = conn.cursor()

    cur.execute("SELECT id, device, severity, status FROM alerts WHERE id = ?", (generated_alert_id,))
    alert_row = cur.fetchone()
    assert alert_row is not None
    assert alert_row[0] == generated_alert_id
    assert alert_row[1] == 'Edge-Gateway-01'
    assert alert_row[2] in ['critical', 'high']

    cur.execute("SELECT COUNT(*) FROM events")
    event_count = cur.fetchone()[0]
    assert event_count >= 2

    conn.close()

    # Phase 3: Spin up a new DetectionPipeline instance on the same DB
    pipe2 = DetectionPipeline(db_path=clean_test_db, data_path='intrusion_data.csv')
    conn2 = sqlite3.connect(clean_test_db)
    cur2 = conn2.cursor()
    cur2.execute("SELECT COUNT(*) FROM alerts")
    reloaded_alerts = cur2.fetchone()[0]
    assert reloaded_alerts >= 1
    conn2.close()
