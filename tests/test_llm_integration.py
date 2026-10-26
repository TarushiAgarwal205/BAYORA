import json

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.llm_client import OPENROUTER_CHAT_COMPLETIONS_URL, OpenRouterClient
from backend.main import create_app


def payload(**overrides):
    value = {
        "session_id": "llm-test",
        "role": "red",
        "action": "generate_client_response",
        "resource": "test:authorized_access",
        "prompt": "Respond with a short synthetic test message.",
    }
    value.update(overrides)
    return value


def make_client(tmp_path, handler, *, api_key="test-only-key", model="mock/provider-model"):
    transport = httpx.MockTransport(handler)
    llm_client = OpenRouterClient(api_key, model, transport=transport, timeout=1.0)
    app = create_app(audit_db_path=tmp_path / "llm-audit.sqlite3", llm_client=llm_client)
    return TestClient(app)


def get_events(client):
    return client.get("/audit/events").json()["events"]


def test_authorized_request_calls_openrouter_and_keeps_output_unverified(tmp_path):
    captured = []

    def respond(request):
        captured.append(request)
        return httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": "Synthetic model response."}}]
        })

    with make_client(tmp_path, respond) as client:
        response = client.post("/llm/generate", json=payload())

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW"
    assert body["model"] == "mock/provider-model"
    assert body["model_output"] == "Synthetic model response."
    assert body["operation_executed"] is True
    assert body["observed_outcome"] == "SUCCEEDED"
    assert body["verification_result"] == "NOT_VERIFIED"
    assert body["security_outcome"] == "NOT_EVALUATED"
    assert len(captured) == 1
    assert str(captured[0].url) == OPENROUTER_CHAT_COMPLETIONS_URL
    assert captured[0].headers["Authorization"] == "Bearer test-only-key"
    request_body = json.loads(captured[0].content)
    assert request_body["model"] == "mock/provider-model"
    assert request_body["messages"] == [{"role": "user", "content": payload()["prompt"]}]

    event = client.get(f"/audit/events/{body['event_id']}").json()
    assert (event["decision"], event["operation_executed"], event["observed_outcome"],
            event["verification_result"]) == ("ALLOW", 1, "SUCCEEDED", "NOT_VERIFIED")


def test_policy_denial_does_not_call_provider(tmp_path):
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json={"choices": []})

    with make_client(tmp_path, respond) as client:
        response = client.post("/llm/generate", json=payload(role="blue"))
        assert response.status_code == 403
        assert calls == []
        assert "model_output" not in response.text
        event = get_events(client)[0]
        assert (event["decision"], event["operation_executed"], event["observed_outcome"],
                event["verification_result"]) == ("DENY", 0, "NOT_EXECUTED", "NOT_VERIFIED")


def test_provider_failure_is_sanitized_and_audited_unknown(tmp_path):
    def provider_error(request):
        return httpx.Response(429, text="provider secret detail should not reach the caller")

    with make_client(tmp_path, provider_error) as client:
        response = client.post("/llm/generate", json=payload())
        assert response.status_code == 502
        assert "provider secret detail" not in response.text
        event = get_events(client)[0]
        assert (event["operation_executed"], event["observed_outcome"], event["verification_result"]) == (
            None, "UNKNOWN", "NOT_VERIFIED"
        )


def test_malformed_provider_response_is_not_exposed(tmp_path):
    def malformed(request):
        return httpx.Response(200, json={"choices": [{"message": {"content": None}}]})

    with make_client(tmp_path, malformed) as client:
        response = client.post("/llm/generate", json=payload())
        assert response.status_code == 502
        assert "choices" not in response.text
        event = get_events(client)[0]
        assert (event["operation_executed"], event["observed_outcome"], event["verification_result"]) == (
            None, "UNKNOWN", "NOT_VERIFIED"
        )


def test_missing_key_fails_closed_without_provider_call(tmp_path):
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json={})

    with make_client(tmp_path, respond, api_key="") as client:
        response = client.post("/llm/generate", json=payload())
        assert response.status_code == 503
        assert calls == []
        assert "test-only-key" not in response.text
        event = get_events(client)[0]
        assert (event["operation_executed"], event["observed_outcome"], event["verification_result"]) == (
            0, "NOT_EXECUTED", "NOT_VERIFIED"
        )


def test_connection_failure_is_audited_not_executed(tmp_path):
    def fail_connect(request):
        raise httpx.ConnectError("simulated unavailable provider", request=request)

    with make_client(tmp_path, fail_connect) as client:
        response = client.post("/llm/generate", json=payload())
        assert response.status_code == 502
        event = get_events(client)[0]
        assert (event["operation_executed"], event["observed_outcome"], event["verification_result"]) == (
            0, "NOT_EXECUTED", "NOT_VERIFIED"
        )


@pytest.mark.parametrize("overrides", [
    {"resource": "test:unapproved"},
    {"resource": "test:authorized_access", "action": "read_artifact"},
])
def test_unapproved_test_or_action_is_denied(tmp_path, overrides):
    calls = []
    with make_client(tmp_path, lambda request: calls.append(request) or httpx.Response(200)) as client:
        response = client.post("/llm/generate", json=payload(**overrides))
        assert response.status_code == 403
        assert calls == []


def test_invalid_prompt_is_rejected_before_audit_or_provider_call(tmp_path):
    calls = []
    with make_client(tmp_path, lambda request: calls.append(request) or httpx.Response(200)) as client:
        response = client.post("/llm/generate", json=payload(prompt=""))
        assert response.status_code == 422
        assert calls == []
        assert get_events(client) == []


def test_openrouter_client_defaults_model_and_requires_no_network_for_missing_key():
    client = OpenRouterClient("")
    assert client.model == "openrouter/free"


def test_local_env_reader_parses_only_selected_variables(tmp_path):
    from backend.config import _read_local_env

    env_file = tmp_path / "test.env"
    env_file.write_text(
        'BAYORA_OPENROUTER_API_KEY="dummy-key-value"\n'
        "BAYORA_LLM_MODEL=openrouter/free # comment\n"
        "UNRELATED_VALUE=ignored\n",
        encoding="utf-8",
    )
    values = _read_local_env({"BAYORA_OPENROUTER_API_KEY", "BAYORA_LLM_MODEL"}, env_file)
    assert values == {
        "BAYORA_OPENROUTER_API_KEY": "dummy-key-value",
        "BAYORA_LLM_MODEL": "openrouter/free",
    }
