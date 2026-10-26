import httpx
import pytest
from fastapi.testclient import TestClient

from backend.blue_client import BlueServiceClient
from backend.main import create_app
from blue.service import RESOURCE_ID, create_blue_app

TEST_CALLER_TOKENS = {
    "red": "test-red-gateway-token",
    "blue": "test-blue-gateway-token",
}


def request(role="blue", resource=RESOURCE_ID, action="read_artifact"):
    return {"session_id": "blue-test", "role": role, "action": action, "resource": resource}


def gateway_headers(role):
    return {"Authorization": f"Bearer {TEST_CALLER_TOKENS[role]}"}


def make_client(tmp_path, transport=None):
    selected_transport = transport or httpx.ASGITransport(app=create_blue_app("test-only-token"))
    resource_client = BlueServiceClient("http://blue.test", "test-only-token", selected_transport)
    app = create_app(
        audit_db_path=tmp_path / "resource-audit.sqlite3",
        blue_client=resource_client,
        gateway_caller_tokens=TEST_CALLER_TOKENS,
    )
    return TestClient(app)


def audit_events(client):
    return client.get("/audit/events").json()["events"]


def test_allowed_gateway_read_executes_and_audits_accurate_outcome(tmp_path):
    with make_client(tmp_path) as client:
        response = client.post(
            "/resource/read", json=request(role="red"), headers=gateway_headers("blue")
        )
        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "ALLOW"
        assert body["operation_executed"] is True
        assert body["observed_outcome"] == "SUCCEEDED"
        assert body["verification_result"] == "VERIFIED"
        assert body["content"].startswith("SYNTHETIC DUMMY CONFIDENTIAL TEST DATA:")
        event = client.get(f"/audit/events/{body['event_id']}").json()
        assert event["role"] == "blue"
        assert (event["decision"], event["operation_executed"], event["observed_outcome"],
                event["verification_result"]) == ("ALLOW", 1, "SUCCEEDED", "VERIFIED")


def test_policy_denial_never_calls_blue_or_exposes_fixture(tmp_path):
    calls = []

    def count_call(request):
        calls.append(request)
        return httpx.Response(200, json={"content": "unexpected"})

    with make_client(tmp_path, httpx.MockTransport(count_call)) as client:
        response = client.post(
            "/resource/read", json=request(role="red"), headers=gateway_headers("red")
        )
        assert response.status_code == 403
        assert "SYNTHETIC DUMMY CONFIDENTIAL TEST DATA" not in response.text
        assert calls == []
        event = audit_events(client)[0]
        assert (event["decision"], event["operation_executed"], event["observed_outcome"],
                event["verification_result"]) == ("DENY", 0, "NOT_EXECUTED", "NOT_VERIFIED")


def test_unauthenticated_blue_role_claim_is_rejected_before_policy_or_blue_call(tmp_path):
    calls = []

    def count_call(request):
        calls.append(request)
        return httpx.Response(200, json={"content": "unexpected"})

    with make_client(tmp_path, httpx.MockTransport(count_call)) as client:
        response = client.post("/resource/read", json=request(role="blue"))
        assert response.status_code == 401
        assert calls == []
        assert audit_events(client) == []


def test_red_credential_overrides_spoofed_blue_body_role(tmp_path):
    calls = []

    def count_call(request):
        calls.append(request)
        return httpx.Response(200, json={"content": "unexpected"})

    with make_client(tmp_path, httpx.MockTransport(count_call)) as client:
        response = client.post(
            "/resource/read", json=request(role="blue"), headers=gateway_headers("red")
        )
        assert response.status_code == 403
        assert calls == []
        event = audit_events(client)[0]
        assert event["role"] == "red"
        assert event["decision"] == "DENY"


def test_direct_resource_call_with_role_claim_but_without_token_is_denied():
    with TestClient(create_blue_app("test-only-token")) as blue_client:
        response = blue_client.get(f"/internal/resources/{RESOURCE_ID}", headers={"X-Role": "blue"})
    assert response.status_code == 401
    assert "content" not in response.json()


@pytest.mark.parametrize("payload", [
    {"role": "blue", "action": "read_artifact", "resource": "blue:bad!"},
    {"role": "blue", "action": "read_artifact"},
    {"role": "blue", "action": "read_artifact", "resource": RESOURCE_ID, "unexpected": True},
])
def test_invalid_resource_requests_do_not_audit_or_return_data(tmp_path, payload):
    with make_client(tmp_path) as client:
        response = client.post(
            "/resource/read", json=payload, headers=gateway_headers("blue")
        )
        assert response.status_code == 422
        assert "content" not in response.text
        assert audit_events(client) == []


def test_resource_service_failure_fails_closed_and_audits_unknown_outcome(tmp_path):
    transport = httpx.MockTransport(lambda request: httpx.Response(503))
    with make_client(tmp_path, transport) as client:
        response = client.post("/resource/read", json=request(), headers=gateway_headers("blue"))
        assert response.status_code == 503
        assert "content" not in response.text
        event = audit_events(client)[0]
        assert (event["decision"], event["operation_executed"], event["observed_outcome"],
                event["verification_result"]) == ("ALLOW", None, "UNKNOWN", "NOT_VERIFIED")


def test_connect_failure_is_audited_as_not_executed(tmp_path):
    def fail_connect(request):
        raise httpx.ConnectError("simulated unavailable service", request=request)

    with make_client(tmp_path, httpx.MockTransport(fail_connect)) as client:
        response = client.post("/resource/read", json=request(), headers=gateway_headers("blue"))
        assert response.status_code == 503
        event = audit_events(client)[0]
        assert (event["operation_executed"], event["observed_outcome"], event["verification_result"]) == (
            0, "NOT_EXECUTED", "NOT_VERIFIED"
        )


def test_unexpected_resource_content_is_withheld_and_verification_fails(tmp_path):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={
        "resource_id": RESOURCE_ID,
        "classification": "dummy",
        "content": "unexpected content",
        "sha256": "0" * 64,
    }))
    with make_client(tmp_path, transport) as client:
        response = client.post("/resource/read", json=request(), headers=gateway_headers("blue"))
        assert response.status_code == 502
        assert "unexpected content" not in response.text
        event = audit_events(client)[0]
        assert (event["operation_executed"], event["observed_outcome"], event["verification_result"]) == (
            1, "SUCCEEDED", "FAILED"
        )
