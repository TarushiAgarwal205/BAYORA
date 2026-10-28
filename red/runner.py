"""Run a fixed, bounded set of local checks through Bayora's gateway API."""

import argparse
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import httpx

from backend.config import GATEWAY_CALLER_TOKENS


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "reports" / "red-runs"
REQUEST_TIMEOUT_SECONDS = 3.0

TEST_CASES = (
    {
        "case_id": "allowed-protected-resource",
        "description": "A policy-allowed Blue role can read the synthetic fixture through the gateway.",
        "endpoint": "/resource/read",
        "caller_role": "blue",
        "input": {
            "session_id": "red-run-allowed",
            "role": "red",
            "action": "read_artifact",
            "resource": "blue:synthetic-confidential",
        },
        "expected": {
            "http_status": 200,
            "decision": "ALLOW",
            "operation_executed": 1,
            "observed_outcome": "SUCCEEDED",
            "verification_result": "VERIFIED",
        },
    },
    {
        "case_id": "denied-red-resource-read",
        "description": "A Red caller is denied even when the request body claims the Blue role.",
        "endpoint": "/resource/read",
        "caller_role": "red",
        "preflight": True,
        "preflight_input": {
            "session_id": "red-run-denied",
            "role": "red",
            "action": "read_artifact",
            "resource": "blue:synthetic-confidential",
        },
        "input": {
            "session_id": "red-run-denied",
            "role": "blue",
            "action": "read_artifact",
            "resource": "blue:synthetic-confidential",
        },
        "expected": {
            "http_status": 403,
            "decision": "DENY",
            "operation_executed": 0,
            "observed_outcome": "NOT_EXECUTED",
            "verification_result": "NOT_VERIFIED",
        },
    },
    {
        "case_id": "invalid-test-identifier",
        "description": "An unknown test identifier receives a policy DENY.",
        "endpoint": "/policy/decide",
        "caller_role": "red",
        "input": {
            "session_id": "red-run-invalid-id",
            "role": "blue",
            "action": "run_approved_test",
            "resource": "test:not-approved",
        },
        "expected": {
            "http_status": 200,
            "decision": "DENY",
            "operation_executed": 0,
            "observed_outcome": "NOT_EXECUTED",
            "verification_result": "NOT_VERIFIED",
        },
    },
    {
        "case_id": "policy-denied-llm-generation",
        "description": "An unapproved LLM resource is denied; the body role cannot override the Red credential.",
        "endpoint": "/llm/generate",
        "caller_role": "red",
        "preflight": True,
        "input": {
            "session_id": "red-run-denied-llm",
            "role": "blue",
            "action": "generate_client_response",
            "resource": "test:not-approved",
            "prompt": "Return a short synthetic test response.",
        },
        "expected": {
            "http_status": 403,
            "decision": "DENY",
            "operation_executed": 0,
            "observed_outcome": "NOT_EXECUTED",
            "verification_result": "NOT_VERIFIED",
        },
    },
)

_AUDIT_FIELDS = (
    "event_id", "session_id", "role", "action", "resource", "decision", "reason",
    "matched_rule_id", "operation_executed", "observed_outcome", "verification_result",
)


class RunnerError(Exception):
    """Raised when the local test runner cannot safely complete a run."""


def _local_gateway_url(value):
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError as error:
        raise RunnerError("gateway URL is invalid") from error

    try:
        is_loopback_ip = bool(host and ipaddress.ip_address(host).is_loopback)
    except ValueError:
        is_loopback_ip = False

    # Allow loopback addresses for local development and the exact
    # Docker Compose hostname used by containers on the Bayora network.
    is_docker_gateway = host == "gateway"

    if (
        parts.scheme != "http"
        or not (is_loopback_ip or is_docker_gateway)
        or parts.username is not None
        or parts.password is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or (port is not None and not 1 <= port <= 65535)
        or (is_docker_gateway and port != 8000)
    ):
        raise RunnerError(
            "gateway URL must be a plain HTTP loopback address "
            "or http://gateway:8000 inside Docker"
        )

    host_label = f"[{host}]" if host and ":" in host else host
    netloc = f"{host_label}:{port}" if port is not None else host_label
    return urlunsplit((parts.scheme, netloc, "", "", ""))


def _json_body(response):
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _response_summary(response):
    body = _json_body(response)
    detail = body.get("detail") if isinstance(body.get("detail"), dict) else {}
    values = {**body, **detail}
    content = values.get("content")
    model_output = values.get("model_output")

    return {
        "http_status": response.status_code,
        "event_id": values.get("event_id"),
        "decision": values.get("decision"),
        "operation_executed": values.get("operation_executed"),
        "observed_outcome": values.get("observed_outcome"),
        "verification_result": values.get("verification_result"),
        "resource_id": values.get("resource_id"),
        "resource_content_received": isinstance(content, str) and bool(content),
        "model_output_received": isinstance(model_output, str) and bool(model_output),
        "security_outcome": values.get("security_outcome"),
    }


def _audit_evidence(client, event_id, headers):
    if not isinstance(event_id, str):
        return None
    try:
        UUID(event_id)
    except (ValueError, TypeError, AttributeError):
        return None
    try:
        response = client.get(f"/audit/events/{event_id}", headers=headers)
    except httpx.RequestError:
        return None
    if response.status_code != 200:
        return None
    body = _json_body(response)
    if body.get("event_id") != event_id:
        return None
    return {field: body.get(field) for field in _AUDIT_FIELDS}


def _policy_preflight(client, case, headers):
    preflight_input = case.get("preflight_input", case["input"])
    payload = {key: value for key, value in preflight_input.items() if key != "prompt"}
    try:
        response = client.post("/policy/decide", json=payload, headers=headers)
    except httpx.RequestError:
        return {"http_status": None, "decision": None, "audit_evidence": None}
    summary = _response_summary(response)
    evidence = _audit_evidence(client, summary["event_id"], headers)
    return {**summary, "audit_evidence": evidence}


def _evidence_matches_input(evidence, payload, expected_role=None):
    role = payload.get("role") if expected_role is None else expected_role
    return (
        evidence is not None
        and all(
            evidence.get(field) == payload.get(field)
            for field in ("session_id", "action", "resource")
        )
        and evidence.get("role") == role
    )


def _evaluate(case, observed, audit_evidence):
    if not _evidence_matches_input(
        audit_evidence, case["input"], expected_role=case.get("caller_role")
    ):
        return "INCONCLUSIVE"

    if (
        audit_evidence.get("operation_executed") is None
        or audit_evidence.get("observed_outcome") in {"PENDING", "UNKNOWN"}
    ):
        return "INCONCLUSIVE"

    expected = case["expected"]
    if any(
        audit_evidence.get(key) != expected[key]
        for key in (
            "decision", "operation_executed", "observed_outcome",
            "verification_result",
        )
    ):
        return "FAIL"

    if observed.get("http_status") != expected["http_status"]:
        return "FAIL"

    if case["case_id"] == "allowed-protected-resource":
        if observed.get("resource_id") != case["input"]["resource"]:
            return "FAIL"
        if not observed.get("resource_content_received"):
            return "FAIL"

    if (
        case["case_id"] == "denied-red-resource-read"
        and observed.get("resource_content_received")
    ):
        return "FAIL"

    if (
        case["case_id"] == "policy-denied-llm-generation"
        and observed.get("model_output_received")
    ):
        return "FAIL"

    return "PASS"


def _run_case(client, case, auth_tokens):
    result = {
        "case_id": case["case_id"],
        "description": case["description"],
        "endpoint": case["endpoint"],
        "authenticated_role": case.get("caller_role"),
        "input": case["input"],
        "expected": case["expected"],
        "preflight": None,
        "observed": None,
        "audit_evidence": None,
        "result": "INCONCLUSIVE",
    }

    caller_role = case.get("caller_role")
    token = auth_tokens.get(caller_role, "")
    if not token:
        result["reason"] = (
            "required Gateway caller credential is not configured; operation was skipped"
        )
        return result
    headers = {"Authorization": f"Bearer {token}"}

    if case.get("preflight"):
        preflight = _policy_preflight(client, case, headers)
        result["preflight"] = preflight
        preflight_audit = preflight.get("audit_evidence") or {}
        preflight_input = case.get("preflight_input", case["input"])
        if (
            not _evidence_matches_input(
                preflight_audit, preflight_input, expected_role=caller_role
            )
            or preflight.get("http_status") != 200
            or preflight.get("decision") != "DENY"
            or preflight_audit.get("decision") != "DENY"
            or preflight_audit.get("operation_executed") != 0
            or preflight_audit.get("observed_outcome") != "NOT_EXECUTED"
        ):
            result["reason"] = (
                "audited policy preflight did not establish DENY; operation was skipped"
            )
            return result

    try:
        response = client.post(case["endpoint"], json=case["input"], headers=headers)
    except httpx.RequestError:
        result["reason"] = "gateway request failed; no reliable HTTP or audit evidence"
        return result

    observed = _response_summary(response)
    audit_evidence = _audit_evidence(client, observed.get("event_id"), headers)
    result["observed"] = observed
    result["audit_evidence"] = audit_evidence
    result["result"] = _evaluate(case, observed, audit_evidence)

    if result["result"] == "INCONCLUSIVE":
        result["reason"] = "audit evidence does not establish the operation outcome"
    elif result["result"] == "FAIL":
        result["reason"] = "observed HTTP result or audit evidence differed from expectation"

    return result


def run_suite(
    gateway_url="http://127.0.0.1:8000",
    *,
    transport=None,
    results_dir=None,
    auth_tokens=None,
    selected_cases=None,
    run_id=None,
):
    base_url = _local_gateway_url(gateway_url)
    selected_auth_tokens = (
        GATEWAY_CALLER_TOKENS if auth_tokens is None else auth_tokens
    )

    if selected_cases is None:
        cases_to_run = TEST_CASES
    else:
        selected_ids = set(selected_cases)
        known_ids = {case["case_id"] for case in TEST_CASES}
        if selected_ids - known_ids:
            raise RunnerError("one or more selected test case IDs are invalid")
        cases_to_run = tuple(
            case for case in TEST_CASES if case["case_id"] in selected_ids
        )

    if run_id is not None:
        try:
            run_id = str(UUID(run_id))
        except (ValueError, TypeError, AttributeError) as error:
            raise RunnerError("run ID is invalid") from error
    else:
        run_id = str(uuid4())
    client = httpx.Client(
        base_url=base_url,
        transport=transport,
        timeout=REQUEST_TIMEOUT_SECONDS,
        follow_redirects=False,
    )

    try:
        with client:
            cases = [
                _run_case(client, case, selected_auth_tokens)
                for case in cases_to_run
            ]
    except httpx.RequestError as error:
        raise RunnerError("could not contact the local Bayora gateway") from error

    report = {
        "run_id": run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "gateway": base_url,
        "cases": cases,
        "summary": {
            result: sum(case["result"] == result for case in cases)
            for result in ("PASS", "FAIL", "INCONCLUSIVE")
        },
    }

    directory = Path(results_dir) if results_dir is not None else RESULTS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{run_id}.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    return report


def load_run(run_id, results_dir=None):
    try:
        normalized_id = str(UUID(run_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise RunnerError("run ID is invalid") from error

    directory = Path(results_dir) if results_dir is not None else RESULTS_DIR
    result_path = directory / f"{normalized_id}.json"
    try:
        raw_report = result_path.read_bytes()
    except FileNotFoundError as error:
        raise RunnerError("run result not found") from error
    except OSError as error:
        raise RunnerError("run result could not be read") from error
    return load_run_bytes(normalized_id, raw_report)


def load_run_bytes(run_id, raw_report):
    try:
        normalized_id = str(UUID(run_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise RunnerError("run ID is invalid") from error

    try:
        report = json.loads(raw_report.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RunnerError("run result could not be read") from error

    if not isinstance(report, dict) or report.get("run_id") != normalized_id:
        raise RunnerError("run result is invalid")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run Bayora's fixed local Red Team checks."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    run_parser = commands.add_parser(
        "run", help="run all test cases or selected test cases"
    )
    run_parser.add_argument("--gateway-url", default="http://127.0.0.1:8000")
    run_parser.add_argument(
        "--case",
        action="append",
        dest="selected_cases",
        choices=[case["case_id"] for case in TEST_CASES],
        help="run a specific test case; repeat this option to select multiple cases",
    )
    run_parser.add_argument("--results-dir")

    show_parser = commands.add_parser("show", help="retrieve a saved run report")
    show_parser.add_argument("run_id")
    args = parser.parse_args(argv)

    try:
        if args.command == "run":
            report = run_suite(
                args.gateway_url,
                results_dir=args.results_dir,
                selected_cases=args.selected_cases,
            )
            result_directory = (
                Path(args.results_dir) if args.results_dir is not None else RESULTS_DIR
            )
            output = {
                "run_id": report["run_id"],
                "results_file": str(result_directory / f"{report['run_id']}.json"),
                "summary": report["summary"],
            }
        else:
            output = load_run(args.run_id)
    except RunnerError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2

    print(json.dumps(output, indent=2, sort_keys=True))
    if args.command == "run" and (
        output["summary"]["FAIL"] or output["summary"]["INCONCLUSIVE"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
