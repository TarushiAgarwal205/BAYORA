import re

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app


@pytest.fixture
def make_client(tmp_path):
    def factory(rules_path=None, audit_store=None):
        selected_rules = rules_path or "policies/rules.json"
        app = create_app(
            rules_path=selected_rules,
            audit_db_path=tmp_path / "api-audit.sqlite3",
            audit_store=audit_store,
        )
        return TestClient(app)
    return factory


def test_allow_decision_is_recorded_with_separate_outcome_fields(make_client):
    with make_client() as client:
        response = client.post("/policy/decide", json={
            "role": " RED ",
            "action": " RUN_APPROVED_TEST ",
            "resource": " test:authorized_access ",
        })
        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "ALLOW"
        assert body["matched_rule_id"] == "red-approved-tests"
        assert re.fullmatch(r"[A-Za-z0-9_-]{1,64}", body["session_id"])
        assert body["observed_outcome"] == "NOT_EXECUTED"
        assert body["verification_result"] == "NOT_VERIFIED"

        event = client.get(f"/audit/events/{body['event_id']}").json()
        assert event["decision"] == "ALLOW"
        assert event["resource"] == "test:authorized_access"


def test_explicit_deny_and_default_deny_are_audited(make_client):
    with make_client() as client:
        denied = client.post("/policy/decide", json={
            "session_id": "session-deny",
            "role": "red",
            "action": "read_artifact",
            "resource": "blue:report",
        }).json()
        assert (denied["decision"], denied["matched_rule_id"]) == (
            "DENY", "red-deny-blue-artifacts"
        )

        default = client.post("/policy/decide", json={
            "session_id": "session-default",
            "role": "red",
            "action": "unknown_action",
            "resource": "test:authorized_access",
        }).json()
        assert default["decision"] == "DENY"
        assert default["reason"] == "no matching allow rule (default deny)"
        assert default["matched_rule_id"] == "default-deny"
        audited_events = client.get("/audit/events").json()["events"]
        assert len(audited_events) == 2
        assert all(event["observed_outcome"] == "NOT_EXECUTED" for event in audited_events)
        assert all(event["verification_result"] == "NOT_VERIFIED" for event in audited_events)


@pytest.mark.parametrize("payload", [
    {"role": "red!", "action": "run_approved_test", "resource": "test:authorized_access"},
    {"role": "r" * 65, "action": "run_approved_test", "resource": "test:authorized_access"},
    {"role": "red", "action": "run_approved_test"},
    {"role": 7, "action": "run_approved_test", "resource": "test:authorized_access"},
    {"role": "red", "action": "run_approved_test", "resource": "test:authorized_access", "extra": "field"},
    {"role": "red", "action": "run_approved_test", "resource": "test:%2e%2e"},
    {"session_id": "bad session", "role": "red", "action": "run_approved_test", "resource": "test:authorized_access"},
])
def test_invalid_requests_return_422_without_audit_row(make_client, payload):
    with make_client() as client:
        assert client.post("/policy/decide", json=payload).status_code == 422
        assert client.get("/audit/events").json()["events"] == []


def test_traversal_like_resource_is_denied_and_audited(make_client):
    with make_client() as client:
        response = client.post("/policy/decide", json={
            "role": "red",
            "action": "run_approved_test",
            "resource": "..",
        })
        assert response.status_code == 200
        assert response.json()["decision"] == "DENY"
        assert response.json()["matched_rule_id"] == "default-deny"
        assert len(client.get("/audit/events").json()["events"]) == 1


@pytest.mark.parametrize("rules_content,expected_reason", [
    (None, "policy configuration error: rules file is missing"),
    ("not json", "policy configuration error: rules file is invalid"),
])
def test_rule_configuration_error_denies_and_attempts_audit(
    make_client, tmp_path, rules_content, expected_reason
):
    rules_path = tmp_path / "rules.json"
    if rules_content is not None:
        rules_path.write_text(rules_content, encoding="utf-8")
    else:
        rules_path = tmp_path / "missing.json"

    with make_client(rules_path=rules_path) as client:
        response = client.post("/policy/decide", json={
            "role": "red",
            "action": "run_approved_test",
            "resource": "test:authorized_access",
        })
        assert response.status_code == 200
        assert response.json()["decision"] == "DENY"
        assert response.json()["reason"] == expected_reason
        assert response.json()["matched_rule_id"] == "configuration-error"
        events = client.get("/audit/events").json()["events"]
        assert len(events) == 1
        assert events[0]["decision"] == "DENY"


def test_rules_endpoint_returns_loaded_rules(make_client):
    with make_client() as client:
        response = client.get("/policy/rules")
        assert response.status_code == 200
        assert response.json()["rules"][0]["resource_match"]["type"] == "exact"


def test_audit_pagination_filters_and_validation(make_client):
    with make_client() as client:
        for session_id, action in (("alpha", "run_approved_test"), ("beta", "unknown"), ("gamma", "unknown")):
            client.post("/policy/decide", json={
                "session_id": session_id,
                "role": "red",
                "action": action,
                "resource": "test:authorized_access",
            })
        page = client.get("/audit/events?limit=1&offset=1")
        assert page.status_code == 200
        assert len(page.json()["events"]) == 1
        assert client.get("/audit/events?decision=ALLOW").json()["events"][0]["session_id"] == "alpha"
        assert len(client.get("/audit/events?session_id=beta").json()["events"]) == 1
        assert client.get("/audit/events?limit=201").status_code == 422
        assert client.get("/audit/events?offset=-1").status_code == 422
        assert client.get("/audit/events?decision=BLOCKED").status_code == 422
        assert client.get("/audit/events/not-a-uuid").status_code == 404


class FailingAuditStore:
    def initialize(self):
        pass

    def record(self, event):
        raise OSError("simulated disk write failure")


def test_audit_failure_returns_503_without_allow(make_client):
    with make_client(audit_store=FailingAuditStore()) as client:
        response = client.post("/policy/decide", json={
            "role": "red",
            "action": "run_approved_test",
            "resource": "test:authorized_access",
        })
        assert response.status_code == 503
        assert "ALLOW" not in response.text


def test_sql_metacharacters_are_rejected_by_request_validation(make_client):
    with make_client() as client:
        marker = "test:authorized_access'; DROP TABLE audit_events; --"
        response = client.post("/policy/decide", json={
            "role": "red",
            "action": "run_approved_test",
            "resource": marker,
        })
        assert response.status_code == 422
        assert client.get("/audit/events").json()["events"] == []
