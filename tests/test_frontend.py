from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import create_app


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_TOKEN = "frontend-test-red-token"


def test_dashboard_matches_authenticated_audit_api_contract(tmp_path):
    app = create_app(
        audit_db_path=tmp_path / "frontend-audit.sqlite3",
        gateway_caller_tokens={"red": TEST_TOKEN, "blue": "frontend-test-blue-token"},
    )
    with TestClient(app) as client:
        response = client.get("/dashboard/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["content-security-policy"]
    assert 'id="gatewayToken"' in response.text
    assert 'id="generateReportButton"' in response.text
    assert 'id="evidenceReport"' in response.text
    assert "Authorization" in response.text
    assert "/audit/verify" in response.text
    assert "/audit/anomalies" in response.text
    assert "/audit/events?limit=15" in response.text
    assert "/audit/report" in response.text
    assert "/llm/generate" in response.text
    assert "/admin/policies" in response.text
    assert "/admin/config" in response.text
    assert "/admin/scenarios/run" in response.text
    assert "/admin/incidents" in response.text
    assert 'id="promptInput"' in response.text
    assert "innerHTML" not in response.text


def test_dashboard_file_is_served_from_frontend_directory():
    assert (PROJECT_ROOT / "frontend" / "index.html").is_file()
