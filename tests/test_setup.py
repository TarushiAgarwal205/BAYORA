from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from backend.main import create_app


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(audit_db_path=tmp_path / "stage1-audit.sqlite3")) as test_client:
        yield test_client


def test_health_returns_expected_body(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_home_returns_success(client):
    assert client.get("/").status_code == 200


def test_test_route_accepts_valid_request_and_rejects_malformed_request(client):
    response = client.post(
        "/test",
        json={
            "session_id": "setup-test",
            "role": "red",
            "resource": "test_endpoint",
            "action": "run_test",
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "session_id": "setup-test",
        "decision": "ALLOWED",
        "reason": "Policy permits this test",
    }
    assert client.post("/test", json={"session_id": "setup-test"}).status_code == 422


def test_dashboard_serves_relocated_frontend(client):
    response = client.get("/dashboard/")
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text
    assert 'fetch("/health")' in response.text


def test_application_files_are_outside_venv():
    assert (PROJECT_ROOT / "backend" / "main.py").is_file()
    assert (PROJECT_ROOT / "frontend" / "index.html").is_file()
    assert not (PROJECT_ROOT / "venv" / "main.py").exists()
    assert not (PROJECT_ROOT / "venv" / "frontend" / "index.html").exists()
