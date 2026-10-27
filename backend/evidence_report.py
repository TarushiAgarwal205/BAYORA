"""Generate role-scoped summaries from Bayora's verified audit evidence."""

import json
from datetime import datetime, timezone
from pathlib import Path

from backend.anomaly_detector import analyze_audit_events
from backend.audit_store import AuditStore
from backend.config import AUDIT_DB_PATH, PROJECT_ROOT
from backend.policy import PolicyEngine


DEFAULT_RULES_PATH = PROJECT_ROOT / "policies" / "rules.json"
DEFAULT_RED_RUNS_DIR = PROJECT_ROOT / "reports" / "red-runs"


def generate_evidence_report(
    audit_store=None,
    rules_path=None,
    *,
    role=None,
    red_runs_dir=None,
    repeated_denial_threshold=3,
):
    """Build a summary; when a role is supplied, audit data is role-scoped."""
    store = audit_store or AuditStore(AUDIT_DB_PATH)
    if audit_store is None:
        store.initialize()

    selected_rules = Path(rules_path or DEFAULT_RULES_PATH)
    policy = PolicyEngine(selected_rules)
    events = store.list_events(limit=200, role=role)
    integrity = store.verify_integrity()
    total_events = integrity.get("checked_events", len(events))
    integrity_summary = {
        **integrity,
        "total_events": total_events,
        "verified_events": total_events if integrity.get("valid") else 0,
        "broken_at": None if integrity.get("valid") else integrity.get("reason"),
    }

    decisions = _count(events, "decision")
    outcomes = _count(events, "observed_outcome")
    verifications = _count(events, "verification_result")
    anomalies = analyze_audit_events(
        events, repeated_denial_threshold=repeated_denial_threshold
    )
    report = {
        "project": "Bayora Security Gateway",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scope_role": role,
        "policy": {
            "rules_file": selected_rules.name,
            "configuration_error": policy.configuration_error,
            "rules_count": len(policy.rules) if not policy.configuration_error else 0,
        },
        "audit": {
            "total_events": len(events),
            "decisions": decisions,
            "observed_outcomes": outcomes,
            "verification_results": verifications,
            "cryptographic_integrity": integrity_summary,
        },
        "anomalies": {"count": len(anomalies), "findings": anomalies},
        # Red-run reports have no authenticated role ownership metadata yet.
        # Keep them out of role-scoped API reports until that mapping exists.
        "recent_red_runs": (
            _recent_red_runs(Path(red_runs_dir or DEFAULT_RED_RUNS_DIR))
            if role is None
            else []
        ),
    }
    report["overall_status"] = (
        "HEALTHY"
        if integrity.get("valid") and not policy.configuration_error and not anomalies
        else "ATTENTION_REQUIRED"
    )
    return report


def render_markdown_report(report):
    audit = report["audit"]
    integrity = audit["cryptographic_integrity"]
    anomalies = report["anomalies"]["findings"]
    lines = [
        "# Bayora Evidence Summary",
        "",
        f"Generated at (UTC): {report['generated_at_utc']}",
        f"Status: {report['overall_status']}",
        f"Audit scope role: {report.get('scope_role') or 'all (local report only)'}",
        "",
        "## Audit integrity",
        "",
        f"- Valid: {integrity.get('valid')}",
        f"- Events checked: {integrity.get('verified_events', 0)} / {integrity.get('total_events', 0)}",
        f"- Details: {integrity.get('reason', 'unknown')}",
        "",
        "## Policy",
        "",
        f"- Rules file: {report['policy']['rules_file']}",
        f"- Loaded rules: {report['policy']['rules_count']}",
        f"- Configuration error: {report['policy']['configuration_error'] or 'none'}",
        "",
        "## Audit activity",
        "",
        f"- Events in report scope: {audit['total_events']}",
        f"- Decisions: {audit['decisions']}",
        f"- Outcomes: {audit['observed_outcomes']}",
        f"- Verification states: {audit['verification_results']}",
        "",
        "## Anomalies",
        "",
    ]
    if anomalies:
        lines.extend(
            f"- [{finding['severity']}] {finding['type']}: {finding['details']}"
            for finding in anomalies
        )
    else:
        lines.append("- No configured indicators were detected in the scanned event window.")
    return "\n".join(lines) + "\n"


def save_evidence_report(report, output_dir):
    """Write a previously generated report to an explicit caller-selected directory."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "evidence-report.json"
    markdown_path = destination / "EVIDENCE.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown_report(report), encoding="utf-8")
    return json_path, markdown_path


def _count(events, key):
    counts = {}
    for event in events:
        value = event.get(key, "UNKNOWN")
        counts[value] = counts.get(value, 0) + 1
    return counts


def _recent_red_runs(directory):
    summaries = []
    if not directory.is_dir():
        return summaries
    for run_file in sorted(directory.glob("*.json"), reverse=True)[:5]:
        try:
            run_data = json.loads(run_file.read_text(encoding="utf-8"))
            cases = run_data.get("cases", [])
            if not isinstance(cases, list):
                continue
            summaries.append({
                "run_id": run_data.get("run_id"),
                "created_at_utc": run_data.get("created_at_utc"),
                "passed_cases": sum(case.get("result") == "PASS" for case in cases if isinstance(case, dict)),
                "total_cases": len(cases),
            })
        except (OSError, json.JSONDecodeError, TypeError):
            continue
    return summaries
