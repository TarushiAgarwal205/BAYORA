import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app


TEST_CALLER_TOKENS = {"red": "api-test-red-token", "blue": "api-test-blue-token"}


@pytest.fixture
def make_client(tmp_path):
    def factory(rules_path=None, audit_store=None):
        selected_rules = rules_path or "policies/rules.json"
        app = create_app(
            rules_path=selected_rules,
            audit_db_path=tmp_path / "api-audit.sqlite3",
            audit_store=audit_store,
            gateway_caller_tokens=TEST_CALLER_TOKENS,
        )
        test_client = TestClient(app)
        test_client.headers["Authorization"] = f"Bearer {TEST_CALLER_TOKENS['red']}"
        return test_client
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
        assert body["role"] == "red"
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


def test_authenticated_red_cannot_spoof_blue_role_for_policy_or_audit(make_client):
    with make_client() as client:
        response = client.post("/policy/decide", json={
            "role": "blue",
            "action": "read_artifact",
            "resource": "blue:report",
        })
        assert response.status_code == 200
        assert response.json()["decision"] == "DENY"
        assert response.json()["role"] == "red"
        event = client.get(f"/audit/events/{response.json()['event_id']}").json()
        assert event["role"] == "red"


def test_audit_events_are_scoped_to_authenticated_role(make_client):
    with make_client() as client:
        response = client.post(
            "/policy/decide",
            json={
                "role": "red",
                "action": "read_artifact",
                "resource": "blue:synthetic-confidential",
            },
            headers={"Authorization": f"Bearer {TEST_CALLER_TOKENS['blue']}"},
        )
        assert response.status_code == 200
        assert response.json()["role"] == "blue"
        assert response.json()["decision"] == "ALLOW"
        event_id = response.json()["event_id"]

        assert all(event["event_id"] != event_id for event in client.get("/audit/events").json()["events"])
        assert client.get(f"/audit/events/{event_id}").status_code == 404
        blue_headers = {"Authorization": f"Bearer {TEST_CALLER_TOKENS['blue']}"}
        blue_events = client.get("/audit/events", headers=blue_headers).json()["events"]
        assert any(event["event_id"] == event_id for event in blue_events)
        assert client.get(f"/audit/events/{event_id}", headers=blue_headers).json()["role"] == "blue"


def test_session_role_switch_is_denied_and_audited(make_client):
    with make_client() as client:
        first = client.post("/policy/decide", json={
            "session_id": "role-bound-session",
            "role": "blue",
            "action": "run_approved_test",
            "resource": "test:authorized_access",
        })
        assert first.status_code == 200
        assert first.json()["decision"] == "ALLOW"
        blue_headers = {"Authorization": f"Bearer {TEST_CALLER_TOKENS['blue']}"}
        switched = client.post("/policy/decide", json={
            "session_id": "role-bound-session",
            "role": "red",
            "action": "read_artifact",
            "resource": "blue:synthetic-confidential",
        }, headers=blue_headers)
        assert switched.status_code == 200
        assert switched.json()["decision"] == "DENY"
        assert switched.json()["role"] == "blue"
        assert switched.json()["matched_rule_id"] == "session-isolation-violation"
        event = client.get(
            f"/audit/events/{switched.json()['event_id']}", headers=blue_headers
        ).json()
        assert event["decision"] == "DENY"
        assert "session isolation violation" in event["reason"]


def test_protected_gateway_routes_and_audit_reads_reject_missing_credentials(make_client):
    with make_client() as client:
        headers = {"Authorization": ""}
        policy = client.post("/policy/decide", json={
            "role": "blue",
            "action": "read_artifact",
            "resource": "blue:report",
        }, headers=headers)
        assert policy.status_code == 401
        assert client.get("/policy/rules", headers=headers).status_code == 401
        assert client.get("/audit/events", headers=headers).status_code == 401
        assert client.get("/audit/integrity", headers=headers).status_code == 401
        assert client.get("/audit/events").json()["events"] == []


def test_audit_api_reports_tampering_and_withholds_unverified_events(make_client, tmp_path):
    with make_client() as client:
        response = client.post("/policy/decide", json={
            "role": "red",
            "action": "run_approved_test",
            "resource": "test:authorized_access",
        })
        event_id = response.json()["event_id"]
        assert client.get("/audit/integrity").json()["valid"] is True

        with sqlite3.connect(tmp_path / "api-audit.sqlite3") as connection:
            connection.execute(
                "UPDATE audit_events SET reason = 'unauthorized edit' WHERE event_id = ?",
                (event_id,),
            )

        integrity = client.get("/audit/integrity")
        assert integrity.status_code == 200
        assert integrity.json()["valid"] is False
        assert client.get("/audit/events").status_code == 503
        assert client.get(f"/audit/events/{event_id}").status_code == 503


def test_audit_feature_routes_are_authenticated_and_role_scoped(make_client):
    with make_client() as client:
        for _ in range(3):
            client.post("/policy/decide", json={
                "session_id": "anomaly-scan",
                "role": "blue",
                "action": "unknown_action",
                "resource": "test:unapproved",
            })
        blue_headers = {"Authorization": f"Bearer {TEST_CALLER_TOKENS['blue']}"}
        for path in ("/audit/verify", "/audit/anomalies", "/audit/report"):
            assert client.get(path, headers={"Authorization": ""}).status_code == 401

        verification = client.get("/audit/verify")
        assert verification.status_code == 200
        assert verification.json()["valid"] is True
        assert verification.json()["verified_events"] >= 3

        anomalies = client.get("/audit/anomalies")
        assert anomalies.status_code == 200
        assert any(item["type"] == "REPEATED_POLICY_DENIALS" for item in anomalies.json()["anomalies"])

        report = client.get("/audit/report")
        assert report.status_code == 200
        assert report.json()["scope_role"] == "red"
        assert report.json()["audit"]["total_events"] == 3
        assert "anomaly-scan" in report.text
        assert "blue" not in report.json()["scope_role"]

        blue_report = client.get("/audit/report", headers=blue_headers)
        assert blue_report.status_code == 200
        assert blue_report.json()["scope_role"] == "blue"
        assert blue_report.json()["audit"]["total_events"] == 0


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
