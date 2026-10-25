import sqlite3
from datetime import datetime

from backend.audit_store import AuditStore, utc_timestamp


def event(event_id="event-1", **overrides):
    value = {
        "event_id": event_id,
        "timestamp_utc": utc_timestamp(),
        "session_id": "session-1",
        "role": "red",
        "action": "run_approved_test",
        "resource": "test:authorized_access",
        "decision": "ALLOW",
        "reason": "matched explicit allow rule",
        "matched_rule_id": "red-approved-tests",
    }
    value.update(overrides)
    return value


def test_records_complete_events_with_utc_separation_fields(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.initialize()
    store.record(event())
    stored = store.get_event("event-1")

    assert stored["decision"] == "ALLOW"
    assert stored["observed_outcome"] == "NOT_EXECUTED"
    assert stored["verification_result"] == "NOT_VERIFIED"
    assert datetime.fromisoformat(stored["timestamp_utc"].replace("Z", "+00:00")).utcoffset().total_seconds() == 0


def test_record_ignores_caller_outcome_and_verification_values(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.initialize()
    store.record(event(
        "fixed-outcomes",
        observed_outcome="EXECUTED",
        verification_result="VERIFIED",
    ))

    stored = store.get_event("fixed-outcomes")
    assert stored["observed_outcome"] == "NOT_EXECUTED"
    assert stored["verification_result"] == "NOT_VERIFIED"


def test_records_unique_ids_and_filters_with_pagination(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.initialize()
    store.record(event("a", decision="ALLOW"))
    store.record(event("b", decision="DENY", session_id="session-2"))
    store.record(event("c", decision="DENY", session_id="session-2"))

    assert len(store.list_events()) == 3
    assert [item["event_id"] for item in store.list_events(limit=1, offset=1)] == ["b"]
    assert len(store.list_events(session_id="session-2", decision="DENY")) == 2
    assert store.get_event("missing") is None
    try:
        store.record(event("a"))
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError("duplicate event ID should fail")


def test_sql_metacharacters_are_stored_as_data(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.initialize()
    marker = "x'; DROP TABLE audit_events; --"
    store.record(event("sql-safe", resource=marker))

    assert store.get_event("sql-safe")["resource"] == marker
    assert len(store.list_events()) == 1


def test_pending_resource_operation_is_completed_with_evidence(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.initialize()
    store.record_pending_operation(event("resource-read"))
    pending = store.get_event("resource-read")
    assert pending["operation_executed"] is None
    assert pending["observed_outcome"] == "PENDING"
    assert pending["verification_result"] == "NOT_VERIFIED"

    store.complete_operation("resource-read", True, "SUCCEEDED", "VERIFIED")
    completed = store.get_event("resource-read")
    assert completed["operation_executed"] == 1
    assert completed["observed_outcome"] == "SUCCEEDED"
    assert completed["verification_result"] == "VERIFIED"


def test_existing_database_is_migrated_additively(tmp_path):
    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("""CREATE TABLE audit_events (
            event_id TEXT PRIMARY KEY, timestamp_utc TEXT NOT NULL,
            session_id TEXT NOT NULL, role TEXT NOT NULL, action TEXT NOT NULL,
            resource TEXT NOT NULL, decision TEXT NOT NULL,
            reason TEXT NOT NULL, matched_rule_id TEXT NOT NULL,
            observed_outcome TEXT NOT NULL DEFAULT 'NOT_EXECUTED',
            verification_result TEXT NOT NULL DEFAULT 'NOT_VERIFIED'
        )""")
        connection.execute(
            """INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("legacy", utc_timestamp(), "session-1", "red", "run_approved_test",
             "test:authorized_access", "ALLOW", "legacy row", "rule-1",
             "NOT_EXECUTED", "NOT_VERIFIED"),
        )
    store = AuditStore(database)
    store.initialize()

    stored = store.get_event("legacy")
    assert stored["reason"] == "legacy row"
    assert stored["operation_executed"] == 0
    store.record_pending_operation(event("new"))
    assert store.get_event("new")["observed_outcome"] == "PENDING"


def test_operation_audit_rejects_inconsistent_status(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.initialize()
    store.record_pending_operation(event("invalid-transition"))
    try:
        store.complete_operation("invalid-transition", False, "SUCCEEDED", "VERIFIED")
    except ValueError:
        pass
    else:
        raise AssertionError("inconsistent operation state should fail")
    assert store.get_event("invalid-transition")["observed_outcome"] == "PENDING"
