from backend.anomaly_detector import analyze_audit_events
from backend.audit_store import AuditStore, utc_timestamp
from backend.evidence_report import generate_evidence_report


def _event(event_id, *, session_id="audit-test-session", role="red", decision="DENY", resource="test:unknown"):
    return {
        "event_id": event_id,
        "timestamp_utc": utc_timestamp(),
        "session_id": session_id,
        "role": role,
        "action": "unknown_action",
        "resource": resource,
        "decision": decision,
        "reason": "default deny",
        "matched_rule_id": "default-deny",
    }


def test_anomaly_indicators_detect_traversal_and_repeated_denials():
    events = [
        _event("denial-1", resource="../etc/passwd"),
        _event("denial-2"),
        _event("denial-3"),
    ]

    findings = analyze_audit_events(events)

    assert {item["type"] for item in findings} == {
        "PATH_TRAVERSAL_PROBE",
        "REPEATED_POLICY_DENIALS",
    }
    assert all("../etc/passwd" not in item["details"] for item in findings)


def test_evidence_report_is_role_scoped_and_uses_verified_integrity(tmp_path):
    store = AuditStore(tmp_path / "report-audit.sqlite3")
    store.initialize()
    store.record(_event("red-denial"))
    store.record(_event("blue-allow", session_id="blue-session", role="blue", decision="ALLOW"))

    report = generate_evidence_report(
        audit_store=store,
        rules_path=tmp_path / "missing-rules.json",
        role="red",
        red_runs_dir=tmp_path / "no-red-runs",
    )

    assert report["scope_role"] == "red"
    assert report["audit"]["total_events"] == 1
    assert report["audit"]["decisions"] == {"DENY": 1}
    assert report["audit"]["cryptographic_integrity"]["valid"] is True
    assert report["policy"]["configuration_error"]
    assert report["overall_status"] == "ATTENTION_REQUIRED"
    assert report["recent_red_runs"] == []
