import json
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.blue_client import BlueServiceClient
from backend.main import create_app
from blue.service import create_blue_app
from red.runner import RunnerError, load_run, load_run_bytes, main, run_suite

TEST_AUTH_TOKENS = {
    "red": "runner-red-test-token",
    "blue": "runner-blue-test-token",
}


def run_mock_suite(gateway, tmp_path):
    return run_suite(
        "http://127.0.0.1:8000",
        transport=httpx.MockTransport(gateway),
        results_dir=tmp_path,
        auth_tokens=TEST_AUTH_TOKENS,
    )


class GatewayStub:
    def __init__(self, *, allowed_llm_preflight=False, missing_audit_for=None,
                 unknown_allowed_audit=False, leak_denied_resource=False):
        self.events = {}
        self.calls = []
        self.resource_auth_roles = []
        self.policy_auth_roles = []
        self.llm_auth_roles = []
        self.allowed_llm_preflight = allowed_llm_preflight
        self.missing_audit_for = missing_audit_for
        self.unknown_allowed_audit = unknown_allowed_audit
        self.leak_denied_resource = leak_denied_resource

    def __call__(self, request):
        self.calls.append((request.method, request.url.host, request.url.path))
        path = request.url.path
        if path == "/policy/decide":
            caller_role = self._authenticated_role(request)
            self.policy_auth_roles.append(caller_role)
            if caller_role is None:
                return httpx.Response(401, json={"detail": "authentication required"})
            payload = json.loads(request.content)
            evidence_payload = {**payload, "role": caller_role}
            if payload["action"] == "generate_client_response" and self.allowed_llm_preflight:
                return self._event_response(evidence_payload, "ALLOW", 200, 0, "NOT_EXECUTED", "NOT_VERIFIED")
            return self._event_response(evidence_payload, "DENY", 200, 0, "NOT_EXECUTED", "NOT_VERIFIED")
        if path == "/resource/read":
            payload = json.loads(request.content)
            caller_role = self._authenticated_role(request)
            self.resource_auth_roles.append(caller_role)
            if caller_role is None:
                return httpx.Response(401, json={"detail": "authentication required"})
            evidence_payload = {**payload, "role": caller_role}
            if caller_role == "blue":
                return self._event_response(
                    evidence_payload, "ALLOW", 200, 1, "SUCCEEDED", "VERIFIED", body={
                        "resource_id": "blue:synthetic-confidential",
                        "classification": "SYNTHETIC DUMMY CONFIDENTIAL TEST DATA",
                        "content": "SYNTHETIC DUMMY CONFIDENTIAL TEST DATA: fake fixture",
                    }
                )
            return self._event_response(
                evidence_payload, "DENY", 403, 0, "NOT_EXECUTED", "NOT_VERIFIED", nested=True,
                body={"content": "leaked synthetic content"} if self.leak_denied_resource else None,
            )
        if path == "/llm/generate":
            payload = json.loads(request.content)
            caller_role = self._authenticated_role(request)
            self.llm_auth_roles.append(caller_role)
            if caller_role is None:
                return httpx.Response(401, json={"detail": "authentication required"})
            evidence_payload = {**payload, "role": caller_role}
            return self._event_response(
                evidence_payload, "DENY", 403, 0, "NOT_EXECUTED", "NOT_VERIFIED", nested=True
            )
        if path.startswith("/audit/events/"):
            if self._authenticated_role(request) is None:
                return httpx.Response(401, json={"detail": "authentication required"})
            event_id = path.rsplit("/", 1)[-1]
            if self.missing_audit_for in ("all", event_id) or event_id not in self.events:
                return httpx.Response(404, json={"detail": "audit event not found"})
            event = dict(self.events[event_id])
            if self.unknown_allowed_audit and event["resource"] == "blue:synthetic-confidential":
                event.update({
                    "operation_executed": None,
                    "observed_outcome": "UNKNOWN",
                    "verification_result": "NOT_VERIFIED",
                })
            return httpx.Response(200, json=event)
        return httpx.Response(404)

    @staticmethod
    def _authenticated_role(request):
        caller_token = request.headers.get("Authorization", "")
        return {
            f"Bearer {TEST_AUTH_TOKENS['red']}": "red",
            f"Bearer {TEST_AUTH_TOKENS['blue']}": "blue",
        }.get(caller_token)

    def _event_response(self, payload, decision, status, executed, outcome, verification,
                        *, body=None, nested=False):
        event_id = str(uuid4())
        event = {
            "event_id": event_id,
            "session_id": payload.get("session_id", "runner-test"),
            "role": payload["role"],
            "action": payload["action"],
            "resource": payload["resource"],
            "decision": decision,
            "reason": "mocked gateway evidence",
            "matched_rule_id": "mock-rule",
            "operation_executed": executed,
            "observed_outcome": outcome,
            "verification_result": verification,
        }
        self.events[event_id] = event
        response_body = {"event_id": event_id, **body} if body else {
            "event_id": event_id,
            "decision": decision,
            "operation_executed": bool(executed),
            "observed_outcome": outcome,
            "verification_result": verification,
        }
        if nested:
            response_body = {"detail": response_body}
        return httpx.Response(status, json=response_body)


def test_fixed_runner_scenarios_capture_inputs_http_and_audit(tmp_path):
    gateway = GatewayStub()
    report = run_mock_suite(gateway, tmp_path)

    assert report["summary"] == {"PASS": 4, "FAIL": 0, "INCONCLUSIVE": 0}
    cases = {case["case_id"]: case for case in report["cases"]}
    assert set(cases) == {
        "allowed-protected-resource", "denied-red-resource-read",
        "invalid-test-identifier", "policy-denied-llm-generation",
    }
    for case in cases.values():
        assert case["input"]
        assert case["observed"]["http_status"] == case["expected"]["http_status"]
        assert case["audit_evidence"] is not None
        assert case["input"]["session_id"] == (
            f"run-{UUID(report['run_id']).hex}-{case['authenticated_role']}"
        )
    assert cases["allowed-protected-resource"]["observed"]["resource_content_received"] is True
    assert cases["allowed-protected-resource"]["input"]["role"] == "red"
    assert cases["allowed-protected-resource"]["authenticated_role"] == "blue"
    assert cases["denied-red-resource-read"]["input"]["role"] == "blue"
    assert cases["denied-red-resource-read"]["authenticated_role"] == "red"
    assert gateway.resource_auth_roles == ["blue", "red"]
    assert gateway.policy_auth_roles == ["red", "red", "red"]
    assert gateway.llm_auth_roles == ["red"]
    assert cases["invalid-test-identifier"]["input"]["resource"] == "test:not-approved"
    assert cases["policy-denied-llm-generation"]["result"] == "PASS"
    assert all(host == "127.0.0.1" for _, host, _ in gateway.calls)

    stored = load_run(report["run_id"], results_dir=tmp_path)
    assert stored["summary"] == report["summary"]
    report_text = (tmp_path / f"{report['run_id']}.json").read_text(encoding="utf-8")
    assert "SYNTHETIC DUMMY CONFIDENTIAL TEST DATA: fake fixture" not in report_text


def test_synthetic_gateway_request_to_verified_json_report_workflow(tmp_path):
    blue_transport = httpx.ASGITransport(app=create_blue_app("blue-test-token"))
    blue_client = BlueServiceClient(
        "http://blue.test",
        "blue-test-token",
        blue_transport,
    )
    gateway_app = create_app(
        audit_db_path=tmp_path / "workflow-audit.sqlite3",
        blue_client=blue_client,
        gateway_caller_tokens=TEST_AUTH_TOKENS,
    )

    with TestClient(gateway_app) as gateway:
        def in_process_gateway(request):
            response = gateway.request(
                request.method,
                request.url.path,
                content=request.content,
                headers=dict(request.headers),
            )
            return httpx.Response(
                response.status_code,
                headers=dict(response.headers),
                content=response.content,
            )

        report = run_suite(
            "http://127.0.0.1:8000",
            transport=httpx.MockTransport(in_process_gateway),
            results_dir=tmp_path / "workflow-runs",
            auth_tokens=TEST_AUTH_TOKENS,
            selected_cases=["denied-red-resource-read"],
        )

        case = report["cases"][0]
        assert report["summary"] == {"PASS": 1, "FAIL": 0, "INCONCLUSIVE": 0}
        assert case["observed"]["http_status"] == 403
        assert case["audit_evidence"]["event_id"] == case["observed"]["event_id"]
        assert case["audit_evidence"]["decision"] == "DENY"
        assert case["audit_evidence"]["observed_outcome"] == "NOT_EXECUTED"
        assert case["result"] == "PASS"
        persisted = load_run(report["run_id"], tmp_path / "workflow-runs")
        assert persisted == report
        report_bytes = (tmp_path / "workflow-runs" / f"{report['run_id']}.json").read_bytes()
        assert TEST_AUTH_TOKENS["red"].encode() not in report_bytes


def test_runner_cli_passes_custom_results_directory(monkeypatch, tmp_path, capsys):
    observed = {}
    report = {
        "run_id": str(uuid4()),
        "summary": {"PASS": 1, "FAIL": 0, "INCONCLUSIVE": 0},
    }

    def fake_run_suite(gateway_url, *, results_dir, selected_cases):
        observed.update({
            "gateway_url": gateway_url,
            "results_dir": results_dir,
            "selected_cases": selected_cases,
        })
        return report

    monkeypatch.setattr("red.runner.run_suite", fake_run_suite)

    assert main([
        "run",
        "--results-dir",
        str(tmp_path),
        "--case",
        "invalid-test-identifier",
    ]) == 0

    assert observed == {
        "gateway_url": "http://127.0.0.1:8000",
        "results_dir": str(tmp_path),
        "selected_cases": ["invalid-test-identifier"],
    }
    output = json.loads(capsys.readouterr().out)
    assert output["results_file"] == str(tmp_path / f"{report['run_id']}.json")


def test_missing_audit_evidence_is_inconclusive_not_pass(tmp_path):
    gateway = GatewayStub(missing_audit_for="all")
    report = run_mock_suite(gateway, tmp_path)
    assert report["summary"]["PASS"] == 0
    assert report["summary"]["INCONCLUSIVE"] == 4


def test_success_response_without_audit_execution_evidence_is_inconclusive(tmp_path):
    gateway = GatewayStub(unknown_allowed_audit=True)
    report = run_mock_suite(gateway, tmp_path)
    allowed = next(case for case in report["cases"] if case["case_id"] == "allowed-protected-resource")
    assert allowed["observed"]["http_status"] == 200
    assert allowed["observed"]["resource_content_received"] is True
    assert allowed["result"] == "INCONCLUSIVE"


def test_unrelated_audit_event_is_not_accepted_as_evidence(tmp_path):
    gateway = GatewayStub()
    original = gateway.__call__

    def mismatch_allowed_audit(request):
        response = original(request)
        if request.url.path.startswith("/audit/events/"):
            event_id = request.url.path.rsplit("/", 1)[-1]
            event = gateway.events.get(event_id)
            if event and event["resource"] == "blue:synthetic-confidential":
                altered = dict(event, resource="test:unrelated")
                return httpx.Response(200, json=altered)
        return response

    report = run_suite(
        "http://127.0.0.1:8000", transport=httpx.MockTransport(mismatch_allowed_audit),
        results_dir=tmp_path, auth_tokens=TEST_AUTH_TOKENS,
    )
    allowed = next(case for case in report["cases"] if case["case_id"] == "allowed-protected-resource")
    assert allowed["result"] == "INCONCLUSIVE"


def test_denied_response_that_contains_resource_data_is_a_failure(tmp_path):
    gateway = GatewayStub(leak_denied_resource=True)
    report = run_mock_suite(gateway, tmp_path)
    denied = next(case for case in report["cases"] if case["case_id"] == "denied-red-resource-read")
    assert denied["observed"]["resource_content_received"] is True
    assert denied["result"] == "FAIL"


def test_allowed_preflight_skips_policy_denied_llm_case(tmp_path):
    gateway = GatewayStub(allowed_llm_preflight=True)
    report = run_mock_suite(gateway, tmp_path)
    llm_case = next(case for case in report["cases"] if case["case_id"] == "policy-denied-llm-generation")
    assert llm_case["result"] == "INCONCLUSIVE"
    assert "was skipped" in llm_case["reason"]
    assert not any(path == "/llm/generate" for _, _, path in gateway.calls)


def test_runner_rejects_non_loopback_gateway_without_requests(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200)

    with pytest.raises(RunnerError, match="loopback"):
        run_suite("https://example.com", transport=httpx.MockTransport(handler), results_dir=tmp_path)
    assert calls == []


def test_load_run_rejects_path_like_identifier(tmp_path):
    with pytest.raises(RunnerError, match="invalid"):
        load_run("..", results_dir=tmp_path)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda report: report.pop("cases"),
        lambda report: report.update(summary={"PASS": 99, "FAIL": 0, "INCONCLUSIVE": 0}),
        lambda report: report["cases"][0].update(result="UNVERIFIED"),
        lambda report: report["cases"][0].update(case_id=[]),
        lambda report: report["cases"][0].update(result=[]),
        lambda report: report["cases"][0]["input"].update(session_id=[]),
        lambda report: report["cases"][0]["audit_evidence"].update(
            observed_outcome=[]
        ),
        lambda report: report["cases"][1]["observed"].update(http_status=200),
    ],
)
def test_load_run_rejects_incomplete_or_inconsistent_report(tmp_path, mutate):
    report = run_mock_suite(GatewayStub(), tmp_path)
    malformed = json.loads(json.dumps(report))
    mutate(malformed)

    with pytest.raises(RunnerError, match="invalid"):
        load_run_bytes(
            report["run_id"],
            json.dumps(malformed).encode("utf-8"),
        )


def test_runner_does_not_overwrite_an_existing_run_report(tmp_path):
    run_id = str(uuid4())
    first = run_suite(
        "http://127.0.0.1:8000",
        transport=httpx.MockTransport(GatewayStub()),
        results_dir=tmp_path,
        auth_tokens=TEST_AUTH_TOKENS,
        selected_cases=["invalid-test-identifier"],
        run_id=run_id,
    )
    saved_path = tmp_path / f"{run_id}.json"
    saved_bytes = saved_path.read_bytes()

    duplicate_gateway = GatewayStub()
    with pytest.raises(RunnerError, match="already has a saved report"):
        run_suite(
            "http://127.0.0.1:8000",
            transport=httpx.MockTransport(duplicate_gateway),
            results_dir=tmp_path,
            auth_tokens=TEST_AUTH_TOKENS,
            selected_cases=["invalid-test-identifier"],
            run_id=run_id,
        )

    assert saved_path.read_bytes() == saved_bytes
    assert duplicate_gateway.calls == []
    assert first["run_id"] == run_id


def test_runner_rejects_empty_case_selection(tmp_path):
    with pytest.raises(RunnerError, match="at least one"):
        run_suite(
            "http://127.0.0.1:8000",
            transport=httpx.MockTransport(GatewayStub()),
            results_dir=tmp_path,
            auth_tokens=TEST_AUTH_TOKENS,
            selected_cases=[],
        )

    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "summary,expected_exit",
    [
        ({"PASS": 4, "FAIL": 0, "INCONCLUSIVE": 0}, 0),
        ({"PASS": 3, "FAIL": 1, "INCONCLUSIVE": 0}, 1),
        ({"PASS": 3, "FAIL": 0, "INCONCLUSIVE": 1}, 1),
    ],
)
def test_runner_cli_exit_code_reflects_evidence(monkeypatch, capsys, summary, expected_exit):
    monkeypatch.setattr(
        "red.runner.run_suite",
        lambda *args, **kwargs: {"run_id": str(uuid4()), "summary": summary},
    )

    assert main(["run"]) == expected_exit
    assert capsys.readouterr().out
