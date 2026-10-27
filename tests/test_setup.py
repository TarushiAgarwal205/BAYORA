from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from backend.main import create_app


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_RED_TOKEN = "setup-only-red-token"


@pytest.fixture
def client(tmp_path):
    app = create_app(
        audit_db_path=tmp_path / "stage1-audit.sqlite3",
        gateway_caller_tokens={"red": TEST_RED_TOKEN, "blue": "setup-only-blue-token"},
    )
    with TestClient(app) as test_client:
        test_client.headers["Authorization"] = f"Bearer {TEST_RED_TOKEN}"
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


def test_demo_test_route_rejects_an_unauthenticated_role_claim(client):
    response = client.post(
        "/test",
        json={
            "session_id": "setup-unauthenticated",
            "role": "red",
            "resource": "test_endpoint",
            "action": "run_test",
        },
        headers={"Authorization": ""},
    )
    assert response.status_code == 401


def test_dashboard_serves_relocated_frontend(client):
    response = client.get("/dashboard/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<!DOCTYPE html>" in response.text
    assert 'id="gatewayToken"' in response.text

    # The dashboard builds the health URL from window.location.origin, so
    # exercise the same endpoint through its mounted application instead of
    # requiring one particular JavaScript spelling.
    health_response = client.get("/health")
    assert health_response.status_code == 200
    assert health_response.json() == {"status": "healthy"}


def test_application_files_are_outside_venv():
    assert (PROJECT_ROOT / "backend" / "main.py").is_file()
    assert (PROJECT_ROOT / "frontend" / "index.html").is_file()
    assert not (PROJECT_ROOT / "venv" / "main.py").exists()
    assert not (PROJECT_ROOT / "venv" / "frontend" / "index.html").exists()


def test_root_uvicorn_entrypoint_uses_the_secured_gateway_app():
    import main as root_main
    from backend.main import app as secured_app

    assert root_main.app is secured_app
