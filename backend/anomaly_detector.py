"""Small, explainable anomaly checks over role-scoped audit events."""

from collections import defaultdict


def analyze_audit_events(events, repeated_denial_threshold=3):
    """Return indicators from supplied audit events; this is not a classifier."""
    findings = []
    denials_by_session = defaultdict(list)

    for event in events:
        session_id = str(event.get("session_id", "unknown"))
        if event.get("decision") == "DENY":
            denials_by_session[session_id].append(event)

        resource = str(event.get("resource", ""))
        reason = str(event.get("reason", ""))
        if "session isolation" in reason.lower() or event.get("matched_rule_id") == "session-isolation-violation":
            findings.append({
                "type": "SESSION_ISOLATION_VIOLATION",
                "severity": "HIGH",
                "session_id": session_id,
                "event_id": event.get("event_id"),
                "details": "A request attempted to reuse a session under a different authenticated role.",
            })

        lower_resource = resource.lower()
        if (
            ".." in resource
            or "%2e%2e" in lower_resource
            or "/etc/" in lower_resource
            or "\\" in resource
        ):
            findings.append({
                "type": "PATH_TRAVERSAL_PROBE",
                "severity": "HIGH",
                "session_id": session_id,
                "event_id": event.get("event_id"),
                "details": "A resource identifier contained traversal-like syntax.",
            })

    for session_id, denials in denials_by_session.items():
        if len(denials) >= repeated_denial_threshold:
            findings.append({
                "type": "REPEATED_POLICY_DENIALS",
                "severity": "MEDIUM",
                "session_id": session_id,
                "count": len(denials),
                "details": f"Session generated {len(denials)} policy denials in the scanned event window.",
            })

    return findings
