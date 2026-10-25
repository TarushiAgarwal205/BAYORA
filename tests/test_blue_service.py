from fastapi.testclient import TestClient

from blue.service import RESOURCE_ID, create_blue_app


def test_blue_service_rejects_direct_requests_without_service_token():
    with TestClient(create_blue_app("test-only-token")) as client:
        response = client.get(f"/internal/resources/{RESOURCE_ID}", headers={"X-Role": "blue"})
    assert response.status_code == 401
    assert "content" not in response.json()


def test_blue_service_returns_only_the_synthetic_fixture_to_authenticated_gateway():
    with TestClient(create_blue_app("test-only-token")) as client:
        response = client.get(
            f"/internal/resources/{RESOURCE_ID}",
            headers={"Authorization": "Bearer test-only-token"},
        )
    assert response.status_code == 200
    assert response.json()["content"].startswith("SYNTHETIC DUMMY CONFIDENTIAL TEST DATA:")
    assert "No real personal information" in response.json()["content"]


def test_blue_service_rejects_unknown_resource():
    with TestClient(create_blue_app("test-only-token")) as client:
        response = client.get(
            "/internal/resources/blue:other",
            headers={"Authorization": "Bearer test-only-token"},
        )
    assert response.status_code == 404
