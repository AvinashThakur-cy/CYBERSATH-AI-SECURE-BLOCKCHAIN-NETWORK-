from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.analysis import AUDIT_LOG_PATH
from app.main import app


client = TestClient(app)


def assert_analysis_shape(payload: dict, analysis_type: str) -> None:
    assert set(
        ["status", "analysis_type", "risk_level", "score", "summary", "findings", "recommendations", "metadata", "analyzed_at"]
    ).issubset(payload)
    assert payload["status"] == "ok"
    assert payload["analysis_type"] == analysis_type
    assert payload["risk_level"] in {"low", "medium", "high"}
    assert 0 <= payload["score"] <= 100
    assert isinstance(payload["findings"], list)
    assert isinstance(payload["recommendations"], list)


def test_health_endpoint() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["backend"] == "running"
    assert response.json()["analysis_engine"] == "ready"


@pytest.mark.parametrize(
    ("url", "expected_risk"),
    [("https://example.com/account", "low"), ("http://login.example.test:8080/verify", "high")],
)
def test_url_analysis_is_deterministic(url: str, expected_risk: str) -> None:
    first = client.post("/api/analyze/url", json={"url": url})
    second = client.post("/api/analyze/url", json={"url": url})
    assert first.status_code == second.status_code == 200
    assert first.json()["risk_level"] == second.json()["risk_level"] == expected_risk
    assert_analysis_shape(first.json(), "url")


@pytest.mark.parametrize("payload", [{}, {"url": ""}, {"url": "not a URL"}, {"url": "ftp://example.com"}])
def test_url_analysis_rejects_empty_or_malformed_requests(payload: dict) -> None:
    assert client.post("/api/analyze/url", json=payload).status_code == 422


def test_email_analysis_and_validation() -> None:
    response = client.post("/api/analyze/email", json={"email": "person@example.com"})
    assert response.status_code == 200
    assert_analysis_shape(response.json(), "email")
    assert response.json()["metadata"]["domain"] == "example.com"
    assert client.post("/api/analyze/email", json={"email": "not-an-email"}).status_code == 422
    assert client.post("/api/analyze/email", json={}).status_code == 422


def test_password_analysis_never_exposes_plaintext() -> None:
    password = "Unique-Local-Password-2026!"
    response = client.post("/api/analyze/password", json={"password": password})
    assert response.status_code == 200
    payload = response.json()
    assert_analysis_shape(payload, "password")
    assert "password" not in payload
    assert password not in response.text
    assert client.post("/api/analyze/password", json={"password": ""}).status_code == 422
    assert client.post("/api/analyze/password", json={}).status_code == 422
    assert AUDIT_LOG_PATH.exists()
    assert password not in AUDIT_LOG_PATH.read_text(encoding="utf-8")


def test_malformed_json_returns_validation_error() -> None:
    response = client.post("/api/analyze/email", content=b'{"email":')
    assert response.status_code == 422


def test_frontend_uses_local_analysis_endpoint_names() -> None:
    app_js = Path(__file__).parents[1].joinpath("static", "app.js").read_text(encoding="utf-8")
    assert "/api/analyze/url" in app_js
    assert "/api/analyze/email" in app_js
    assert "/api/analyze/password" in app_js
