from pathlib import Path
import re

from fastapi.testclient import TestClient
import pytest

from backend.main import create_app


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_RED_TOKEN = "setup-only-red-token"


def compose_services(text):
    service_section = re.split(r"(?m)^services:\r?$", text, maxsplit=1)[1]
    service_section = re.split(r"(?m)^networks:\r?$", service_section, maxsplit=1)[0]
    matches = list(re.finditer(r"(?m)^  ([a-z0-9-]+):\r?$", service_section))
    services = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(service_section)
        services[match.group(1)] = service_section[match.end():end]
    return services


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


def test_compose_gateway_host_bridge_and_required_paths():
    compose = (PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8")
    services = compose_services(compose)
    gateway = services["gateway"]
    blue = services["blue"]
    llm = services["llm"]
    egress_proxy = services["egress-proxy"]
    red = services["red"]

    assert '"127.0.0.1:8000:8000"' in gateway
    assert "- red-gateway" in gateway
    assert "- blue-gateway" in gateway
    assert "- llm-gateway" in gateway
    assert "- gateway-host" in gateway
    gateway_host = re.search(
        r"(?m)^  gateway-host:\r?\n(?P<body>(?:^    .*\r?\n|^\r?\n)*)",
        compose,
    )
    assert gateway_host is not None
    assert "internal: true" not in gateway_host.group("body")
    assert "- blue-gateway" in blue
    assert "- llm-proxy" in llm
    assert "- llm-egress" not in llm
    assert "BAYORA_LLM_EGRESS_PROXY: http://egress-proxy:8080" in llm
    assert "- llm-proxy" in egress_proxy
    assert "- llm-egress" in egress_proxy
    assert "- red-gateway" in red
    assert "llm-egress" not in gateway + blue + llm + red
    assert 'llm-proxy:\n    internal: true' in compose


def test_compose_red_and_blue_have_no_shared_network_and_keep_gateway_routes():
    compose = (PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8")
    services = compose_services(compose)
    gateway = services["gateway"]
    blue = services["blue"]
    red = services["red"]

    assert "- red-gateway" in gateway and "- blue-gateway" in gateway
    assert "- blue-gateway" in blue and "red-gateway" not in blue
    assert "- red-gateway" in red and "blue-gateway" not in red
