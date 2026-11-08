import pytest
import io
import json
import app

@pytest.fixture
def client():
    app.app.config['TESTING'] = True
    return app.app.test_client()


def test_dashboard_live_endpoint(client):
    res = client.get('/api/dashboard/live')
    assert res.status_code == 200
    data = res.json
    assert 'activeThreats' in data
    assert 'devicesOnline' in data
    assert 'trend' in data
    assert len(data['trend']) == 24
    assert 'topIPs' in data


def test_threats_feed_endpoint(client):
    res = client.get('/api/threats/feed')
    assert res.status_code == 200
    data = res.json
    assert 'events' in data
    assert isinstance(data['events'], list)


def test_devices_endpoint(client):
    res = client.get('/api/devices')
    assert res.status_code == 200
    data = res.json
    assert 'devices' in data
    assert data['summary']['total'] == 50


def test_alerts_endpoint_and_status_update(client):
    res = client.get('/api/alerts')
    assert res.status_code == 200
    data = res.json
    assert 'alerts' in data
    assert len(data['alerts']) > 0

    first_id = data['alerts'][0]['id']
    put_res = client.put(f'/api/alerts/{first_id}/status', json={'status': 'investigating'})
    assert put_res.status_code == 200
    assert put_res.json['success'] is True


def test_model_metrics_endpoint(client):
    res = client.get('/api/model/metrics')
    assert res.status_code == 200
    data = res.json
    assert 'bayesian_metrics' in data
    assert 'markov_matrices' in data
    assert data['bayesian_metrics']['accuracy'] >= 0.80


def test_traffic_generate_endpoint(client):
    # Test generating normal traffic
    res_norm = client.post('/api/traffic/generate', json={'traffic_type': 'normal', 'count': 2})
    assert res_norm.status_code == 200
    assert len(res_norm.json['results']) == 2

    # Test generating malicious traffic
    res_atk = client.post('/api/traffic/generate', json={'traffic_type': 'malicious', 'count': 2, 'attack_phase': 'brute_force'})
    assert res_atk.status_code == 200
    results = res_atk.json['results']
    assert len(results) == 2
    # At least one malicious event should trigger an alert
    assert any(r['alert_generated'] for r in results)


def test_upload_endpoint(client):
    with open('intrusion_data.csv', 'rb') as f:
        data = {'file': (io.BytesIO(f.read()), 'intrusion_data.csv')}

    res = client.post('/upload', data=data, content_type='multipart/form-data')
    assert res.status_code == 200
    j = res.json
    assert j['rows'] == 9537
    assert 'modelMetrics' in j
    assert j['modelMetrics']['accuracy'] >= 0.80
