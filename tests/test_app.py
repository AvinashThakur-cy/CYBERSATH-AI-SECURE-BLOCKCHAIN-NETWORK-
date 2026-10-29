from fastapi.testclient import TestClient

from app.main import app


def test_root_page_renders():
    client = TestClient(app)
    response = client.get('/')
    assert response.status_code == 200
    assert 'CYBERSATHI' in response.text
    assert 'Security observatory' in response.text
    assert 'does not connect to a live blockchain' in response.text
    assert 'not a reputation lookup or a guarantee of safety' in response.text


def test_telemetry_payload():
    client = TestClient(app)
    response = client.get('/api/telemetry')
    assert response.status_code == 200
    payload = response.json()
    assert payload['threat_level'] in {'Critical', 'High', 'Elevated'}
    assert payload['live_nodes'] >= 0
    assert payload['data_mode'] == 'illustrative_demo'
    assert 'executive_brief' in payload
    assert 'attack_investigation' in payload
    assert 'wallet_intelligence' in payload


def test_security_actions_and_report():
    client = TestClient(app)
    action = client.post('/api/actions/isolate-wallet')
    report = client.get('/api/report')
    assert action.status_code == 200
    assert action.json()['status'] == 'accepted'
    assert 'no wallet activity is changed' in action.json()['detail']
    assert report.status_code == 200
    assert report.json()['report_name'] == 'CYBERSATHI Blockchain Security Report'
    assert report.json()['data_mode'] == 'illustrative_demo'


def test_dashboard_modules_are_actionable():
    client = TestClient(app)
    dashboard = client.get('/api/dashboard')
    module = client.get('/api/modules/wallet-intelligence')
    invalid_module = client.get('/api/modules/not-a-module')
    invalid_action = client.post('/api/actions', json={'action': 'not-an-action'})
    assert dashboard.status_code == 200
    assert dashboard.json()['summary']['security_score'] == 88
    assert dashboard.json()['data_mode'] == 'illustrative_demo'
    assert module.status_code == 200
    assert module.json()['module']['label'] == 'Wallet Intelligence'
    assert invalid_module.status_code == 404
    assert invalid_action.status_code == 422


def test_integrity_scan_returns_findings():
    client = TestClient(app)
    response = client.post('/api/actions', json={'action': 'run-scan', 'target': 'Bridge-04'})
    payload = response.json()
    assert response.status_code == 200
    assert payload['scan']['status'] == 'completed'
    assert payload['scan']['security_score'] == 88
    assert payload['scan']['nodes_checked'] == 4
    assert payload['scan']['findings'] == 2
    assert payload['scan']['wallets_in_snapshot'] == 284
    assert 'no live systems were scanned' in payload['detail']
    assert 'Gateway-03 (86%) requires review' in payload['scan']['finding_summary']
    assert 'Bridge-04 (61%) requires review' in payload['scan']['finding_summary']
    assert 'all other monitored nodes' not in payload['scan']['finding_summary']


def test_legacy_get_integrity_scan_is_compatible():
    client = TestClient(app)
    response = client.get('/api/actions/run-scan')
    assert response.status_code == 200
    assert response.json()['scan']['status'] == 'completed'


def test_live_server_origin_has_cors_access():
    client = TestClient(app)
    response = client.options(
        '/api/dashboard',
        headers={
            'Origin': 'http://127.0.0.1:5501',
            'Access-Control-Request-Method': 'GET',
        },
    )
    assert response.status_code == 200
    assert response.headers['access-control-allow-origin'] == 'http://127.0.0.1:5501'


def test_pdf_report_and_shravi_assistant():
    client = TestClient(app)
    pdf = client.get('/api/report.pdf')
    chat = client.post('/api/chat', json={'message': 'What is the attacker IP?'})
    assert pdf.status_code == 200
    assert pdf.headers['content-type'] == 'application/pdf'
    assert pdf.content.startswith(b'%PDF')
    assert chat.status_code == 200
    assert chat.json()['assistant'] == 'Shravi.ai'
    assert 'cannot confirm' in chat.json()['answer'].lower()
    assert chat.json()['intent'] == 'Attribution guidance'
    assert chat.json()['confidence'] == 'High'
    assert len(chat.json()['evidence']) >= 2
    assert len(chat.json()['next_steps']) >= 2


def test_shravi_returns_actionable_posture_guidance():
    client = TestClient(app)
    response = client.post('/api/chat', json={'message': 'What should I fix first?'})
    payload = response.json()
    assert response.status_code == 200
    assert payload['intent'] == 'Containment recommendation'
    assert payload['suggested_action'] == 'isolate-wallet'
