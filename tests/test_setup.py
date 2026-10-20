from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_health_returns_expected_body():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_home_returns_success():
    assert client.get("/").status_code == 200


def test_test_route_accepts_valid_request_and_rejects_malformed_request():
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


def test_dashboard_serves_relocated_frontend():
    response = client.get("/dashboard/")
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text
    assert 'fetch("/health")' in response.text


def test_application_files_are_outside_venv():
    assert (PROJECT_ROOT / "backend" / "main.py").is_file()
    assert (PROJECT_ROOT / "frontend" / "index.html").is_file()
    assert not (PROJECT_ROOT / "venv" / "main.py").exists()
    assert not (PROJECT_ROOT / "venv" / "frontend" / "index.html").exists()
