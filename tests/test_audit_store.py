import sqlite3
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

from backend.audit_checkpoint import CheckpointError
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


def sqlite_backup(source_path, destination_path):
    source = sqlite3.connect(source_path)
    destination = sqlite3.connect(destination_path)
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()


def _record_from_process(database_path, event_id):
    store = AuditStore(Path(database_path))
    store.record(event(event_id))


def test_records_complete_events_with_utc_separation_fields(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.initialize()
    store.record(event())
    stored = store.get_event("event-1")

    assert stored["decision"] == "ALLOW"
    assert stored["observed_outcome"] == "NOT_EXECUTED"
    assert stored["verification_result"] == "NOT_VERIFIED"
    assert datetime.fromisoformat(stored["timestamp_utc"].replace("Z", "+00:00")).utcoffset().total_seconds() == 0
    assert store.verify_integrity()["valid"] is True


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


def test_same_client_session_id_is_isolated_by_authenticated_role(tmp_path):
    store = AuditStore(tmp_path / "role-scoped-sessions.sqlite3")
    store.initialize()
    store.record(event("red-session-event", session_id="shared-id", role="red"))
    store.record(event("blue-session-event", session_id="shared-id", role="blue"))

    assert store.get_session_role("shared-id") is None
    assert [row["event_id"] for row in store.list_events(session_id="shared-id", role="red")] == [
        "red-session-event"
    ]
    assert [row["event_id"] for row in store.list_events(session_id="shared-id", role="blue")] == [
        "blue-session-event"
    ]


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


def test_empty_existing_database_is_migrated_additively(tmp_path):
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
    store = AuditStore(database)
    store.initialize(allow_checkpoint_bootstrap=True)

    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_events)")}
    assert "operation_executed" in columns
    assert store.verify_integrity()["valid"] is True
    store.record_pending_operation(event("new"))
    assert store.get_event("new")["observed_outcome"] == "PENDING"


def test_populated_database_without_integrity_tables_fails_closed(tmp_path):
    database = tmp_path / "untracked-history.sqlite3"
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
    with pytest.raises(sqlite3.DatabaseError, match="refusing to re-baseline"):
        store.initialize()

    with sqlite3.connect(database) as connection:
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )}
        rows = connection.execute("SELECT event_id, reason FROM audit_events").fetchall()
    assert tables == {"audit_events"}
    assert rows == [("legacy", "legacy row")]


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


def test_integrity_chain_tracks_each_operation_revision(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.initialize()
    store.record_pending_operation(event("chain-operation"))
    store.complete_operation("chain-operation", True, "SUCCEEDED", "VERIFIED")

    result = store.verify_integrity()
    assert result == {
        "valid": True,
        "checked_entries": 2,
        "checked_events": 1,
        "reason": "integrity chain and external checkpoint verified",
    }


def test_initialized_empty_store_verifies_zero_length_chain(tmp_path):
    store = AuditStore(tmp_path / "empty-audit.sqlite3")
    store.initialize()

    assert store.verify_integrity() == {
        "valid": True,
        "checked_entries": 0,
        "checked_events": 0,
        "reason": "integrity chain and external checkpoint verified",
    }


def test_integrity_verification_survives_store_reopen(tmp_path):
    database = tmp_path / "persistent-audit.sqlite3"
    first = AuditStore(database)
    first.initialize()
    first.record(event("persistent-event"))

    reopened = AuditStore(database)
    reopened.initialize()
    assert reopened.verify_integrity()["valid"] is True
    assert reopened.get_event("persistent-event")["event_id"] == "persistent-event"


def test_integrity_verification_detects_unauthorized_event_modification(tmp_path):
    database = tmp_path / "tampered-audit.sqlite3"
    store = AuditStore(database)
    store.initialize()
    store.record(event("tampered-event"))

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE audit_events SET verification_result = 'VERIFIED' WHERE event_id = ?",
            ("tampered-event",),
        )

    result = store.verify_integrity()
    assert result["valid"] is False
    assert result["reason"] == "audit events do not match their latest integrity snapshots"
    with pytest.raises(sqlite3.DatabaseError, match="integrity verification failed"):
        store.record(event("after-tamper"))


def test_integrity_verification_detects_missing_audit_event(tmp_path):
    database = tmp_path / "missing-audit.sqlite3"
    store = AuditStore(database)
    store.initialize()
    store.record(event("removed-event"))

    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM audit_events WHERE event_id = ?", ("removed-event",))

    result = store.verify_integrity()
    assert result["valid"] is False
    assert result["reason"] == "audit events do not match their latest integrity snapshots"


def test_integrity_verification_detects_removed_chain_entry(tmp_path):
    database = tmp_path / "missing-integrity-entry.sqlite3"
    store = AuditStore(database)
    store.initialize()
    store.record(event("first-event"))
    store.record(event("second-event"))

    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM audit_integrity WHERE event_id = ?", ("first-event",))

    result = store.verify_integrity()
    assert result["valid"] is False
    assert result["reason"] == "integrity sequence is incomplete"


def test_integrity_verification_rejects_malformed_snapshot_json(tmp_path):
    database = tmp_path / "malformed-snapshot.sqlite3"
    store = AuditStore(database)
    store.initialize()
    store.record(event("malformed-snapshot"))

    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "UPDATE audit_integrity SET snapshot_json = ? WHERE event_id = ?",
            ("not-json", "malformed-snapshot"),
        )
        connection.commit()
    finally:
        connection.close()

    result = store.verify_integrity()
    assert result["valid"] is False
    assert result["reason"] == "integrity snapshot is invalid"


def test_integrity_verification_reports_missing_integrity_table_as_invalid(tmp_path):
    database = tmp_path / "missing-integrity-table.sqlite3"
    store = AuditStore(database, checkpoint_key=b"t" * 32)
    store.initialize()
    store.record(event("table-event"))

    connection = sqlite3.connect(database)
    try:
        connection.execute("DROP TABLE audit_integrity")
        connection.commit()
    finally:
        connection.close()

    result = store.verify_integrity()
    assert result == {
        "valid": False,
        "checked_entries": 0,
        "checked_events": 0,
        "reason": "audit integrity data is malformed or unavailable (OperationalError)",
    }


def test_integrity_verification_detects_reordered_chain_entries(tmp_path):
    database = tmp_path / "reordered-integrity.sqlite3"
    store = AuditStore(database)
    store.initialize()
    store.record(event("first-event"))
    store.record(event("second-event"))

    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE audit_integrity SET sequence = 3 WHERE sequence = 1")
        connection.execute("UPDATE audit_integrity SET sequence = 1 WHERE sequence = 2")
        connection.execute("UPDATE audit_integrity SET sequence = 2 WHERE sequence = 3")

    result = store.verify_integrity()
    assert result["valid"] is False
    assert result["reason"] == "integrity chain link does not match"


def test_integrity_verification_detects_paired_tail_truncation(tmp_path):
    database = tmp_path / "tail-truncation.sqlite3"
    store = AuditStore(database)
    store.initialize()
    store.record(event("first-event"))
    store.record(event("last-event"))

    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM audit_events WHERE event_id = ?", ("last-event",))
        connection.execute("DELETE FROM audit_integrity WHERE event_id = ?", ("last-event",))

    result = store.verify_integrity()
    assert result["valid"] is False
    assert result["reason"] == "audit checkpoint head does not match"
    with pytest.raises(sqlite3.DatabaseError, match="checkpoint head does not match"):
        store.record(event("after-truncation"))


def test_checkpoint_tampering_fails_closed(tmp_path):
    store = AuditStore(tmp_path / "checkpoint-tampering.sqlite3")
    store.initialize()
    store.record(event("anchored-event"))

    with sqlite3.connect(store.checkpoint.path) as connection:
        connection.execute("UPDATE checkpoint_state SET head_hash = ?", ("f" * 64,))

    result = store.verify_integrity()
    assert result["valid"] is False
    assert result["reason"] == "audit checkpoint authentication failed"
    with pytest.raises(sqlite3.DatabaseError, match="checkpoint authentication failed"):
        store.record(event("after-checkpoint-tamper"))


def test_valid_length_wrong_checkpoint_key_fails_closed_for_verification_and_writes(tmp_path):
    database = tmp_path / "wrong-key.sqlite3"
    checkpoint = tmp_path / "wrong-key.checkpoint.sqlite3"
    correct_key = b"c" * 32
    store = AuditStore(database, checkpoint, checkpoint_key=correct_key)
    store.initialize()
    store.record(event("anchored-event"))

    wrong_key_store = AuditStore(database, checkpoint, checkpoint_key=b"w" * 32)

    assert wrong_key_store.verify_integrity() == {
        "valid": False,
        "checked_entries": 1,
        "checked_events": 1,
        "reason": "audit checkpoint authentication failed",
    }
    with pytest.raises(sqlite3.DatabaseError, match="audit checkpoint authentication failed"):
        wrong_key_store.record(event("must-not-write"))
    assert wrong_key_store.get_event("must-not-write") is None


def test_restoring_stale_audit_database_with_current_checkpoint_fails(tmp_path):
    database = tmp_path / "stale-database.sqlite3"
    checkpoint = tmp_path / "stale-database.checkpoint.sqlite3"
    stale_backup = tmp_path / "stale-database-backup.sqlite3"
    store = AuditStore(database, checkpoint, checkpoint_key=b"s" * 32)
    store.initialize()
    store.record(event("backup-head"))
    sqlite_backup(database, stale_backup)

    store.record(event("current-head"))
    sqlite_backup(stale_backup, database)

    result = store.verify_integrity()
    assert result["valid"] is False
    assert result["reason"] == "audit checkpoint head does not match"


def test_restoring_matching_audit_database_and_checkpoint_backup_verifies(tmp_path):
    database = tmp_path / "matching.sqlite3"
    checkpoint = tmp_path / "matching.checkpoint.sqlite3"
    database_backup = tmp_path / "matching-backup.sqlite3"
    checkpoint_backup = tmp_path / "matching-checkpoint-backup.sqlite3"
    store = AuditStore(database, checkpoint, checkpoint_key=b"m" * 32)
    store.initialize()
    store.record(event("matching-backup-event"))
    sqlite_backup(database, database_backup)
    sqlite_backup(checkpoint, checkpoint_backup)

    restored_database = tmp_path / "matching-restored.sqlite3"
    restored_checkpoint = tmp_path / "matching-restored-checkpoint.sqlite3"
    sqlite_backup(database_backup, restored_database)
    sqlite_backup(checkpoint_backup, restored_checkpoint)

    restored_store = AuditStore(
        restored_database,
        restored_checkpoint,
        checkpoint_key=b"m" * 32,
    )
    assert restored_store.verify_integrity() == {
        "valid": True,
        "checked_entries": 1,
        "checked_events": 1,
        "reason": "integrity chain and external checkpoint verified",
    }


def test_restoring_coordinated_older_database_and_checkpoint_pair_is_undetected(tmp_path):
    database = tmp_path / "rollback.sqlite3"
    checkpoint = tmp_path / "rollback.checkpoint.sqlite3"
    database_backup = tmp_path / "rollback-backup.sqlite3"
    checkpoint_backup = tmp_path / "rollback-checkpoint-backup.sqlite3"
    key = b"r" * 32
    store = AuditStore(database, checkpoint, checkpoint_key=key)
    store.initialize()
    store.record(event("older-event"))
    sqlite_backup(database, database_backup)
    sqlite_backup(checkpoint, checkpoint_backup)
    store.record(event("newer-event"))

    # A coordinated older restore is valid but undetectable without an external monotonic anchor.
    sqlite_backup(database_backup, database)
    sqlite_backup(checkpoint_backup, checkpoint)

    result = store.verify_integrity()
    assert result["valid"] is True
    assert result["reason"] == "integrity chain and external checkpoint verified"
    assert store.get_event("older-event") is not None
    assert store.get_event("newer-event") is None


def test_empty_checkpoint_after_interrupted_initialization_cannot_create_baseline(tmp_path):
    database = tmp_path / "empty-checkpoint.sqlite3"
    checkpoint = tmp_path / "empty-checkpoint.checkpoint.sqlite3"
    checkpoint.touch()
    store = AuditStore(database, checkpoint, checkpoint_key=b"e" * 32)

    with pytest.raises(
        sqlite3.DatabaseError,
        match="audit integrity verification failed during initialization",
    ):
        store.initialize()

    assert checkpoint.stat().st_size == 0
    result = store.verify_integrity()
    assert result["valid"] is False
    assert result["reason"] == "audit checkpoint state is missing"


def test_explicit_bootstrap_accepts_missing_but_rejects_present_invalid_checkpoint(tmp_path):
    key = b"b" * 32
    missing_database = tmp_path / "bootstrap-missing.sqlite3"
    missing_checkpoint = tmp_path / "bootstrap-missing.checkpoint.sqlite3"
    missing_store = AuditStore(
        missing_database,
        missing_checkpoint,
        checkpoint_key=key,
    )
    missing_store.initialize(allow_checkpoint_bootstrap=True)
    assert missing_checkpoint.is_file()
    assert missing_store.verify_integrity()["valid"] is True

    invalid_database = tmp_path / "bootstrap-invalid.sqlite3"
    invalid_checkpoint = tmp_path / "bootstrap-invalid.checkpoint.sqlite3"
    invalid_checkpoint.touch()
    invalid_store = AuditStore(
        invalid_database,
        invalid_checkpoint,
        checkpoint_key=key,
    )
    with pytest.raises(
        sqlite3.DatabaseError,
        match="audit integrity verification failed during initialization",
    ):
        invalid_store.initialize(allow_checkpoint_bootstrap=True)

    assert invalid_checkpoint.stat().st_size == 0
    result = invalid_store.verify_integrity()
    assert result["valid"] is False
    assert result["reason"] == "audit checkpoint state is missing"


def test_missing_checkpoint_fails_closed_without_rebaselining(tmp_path):
    store = AuditStore(tmp_path / "missing-checkpoint.sqlite3")
    store.initialize()
    store.record(event("anchored-event"))
    store.checkpoint.path.unlink()

    assert store.verify_integrity() == {
        "valid": False,
        "checked_entries": 1,
        "checked_events": 1,
        "reason": "audit checkpoint is missing",
    }
    with pytest.raises(sqlite3.DatabaseError, match="audit checkpoint is missing"):
        store.record(event("after-missing-checkpoint"))
    with pytest.raises(sqlite3.DatabaseError, match="refusing to establish a new baseline"):
        store.initialize()


def test_checkpoint_retry_is_idempotent(tmp_path):
    store = AuditStore(tmp_path / "checkpoint-retry.sqlite3")
    store.initialize()
    store.record(event("retry-event"))
    state = store.checkpoint.read()

    retried = store.checkpoint.compare_and_set(
        database_id=state["database_id"],
        expected_sequence=state["previous_sequence"],
        expected_hash=state["previous_hash"],
        sequence=state["sequence"],
        head_hash=state["head_hash"],
        operation_id=state["operation_id"],
    )
    assert retried == state


def test_checkpoint_verification_checks_identity_sequence_and_hash(tmp_path):
    store = AuditStore(tmp_path / "checkpoint-fields.sqlite3")
    store.initialize()
    store.record(event("checkpoint-fields"))
    state = store.checkpoint.read()

    mismatches = (
        {"database_id": "different-database"},
        {"sequence": state["sequence"] + 1},
        {"head_hash": "f" * 64},
    )
    for mismatch in mismatches:
        expected = {
            "database_id": state["database_id"],
            "sequence": state["sequence"],
            "head_hash": state["head_hash"],
        }
        expected.update(mismatch)
        assert store.checkpoint.verify(**expected) == {
            "valid": False,
            "reason": "audit checkpoint head does not match",
        }


def test_lost_checkpoint_acknowledgement_is_confirmed_idempotently(tmp_path, monkeypatch):
    store = AuditStore(tmp_path / "lost-ack.sqlite3")
    store.initialize()
    compare_and_set = store.checkpoint.compare_and_set

    def accept_then_lose_ack(**kwargs):
        compare_and_set(**kwargs)
        raise CheckpointError("simulated lost acknowledgement")

    monkeypatch.setattr(store.checkpoint, "compare_and_set", accept_then_lose_ack)
    store.record(event("lost-ack-event"))
    assert store.verify_integrity()["valid"] is True


def test_unavailable_checkpoint_fails_closed_for_reads_and_writes(tmp_path, monkeypatch):
    store = AuditStore(tmp_path / "unavailable-checkpoint.sqlite3")
    store.initialize()
    monkeypatch.setattr(
        store.checkpoint,
        "read",
        lambda: (_ for _ in ()).throw(CheckpointError("checkpoint unavailable")),
    )

    result = store.verify_integrity()
    assert result["valid"] is False
    assert result["reason"] == "checkpoint unavailable"
    with pytest.raises(sqlite3.DatabaseError, match="checkpoint unavailable"):
        store.record(event("must-not-write"))
    assert store.get_event("must-not-write") is None


def test_missing_checkpoint_key_fails_before_database_initialization(tmp_path):
    database = tmp_path / "missing-key.sqlite3"
    store = AuditStore(database, checkpoint_key="")

    with pytest.raises(CheckpointError, match="at least 32 bytes"):
        store.initialize()
    assert database.exists() is False


def test_interrupted_checkpoint_write_requires_explicit_recovery(tmp_path, monkeypatch):
    store = AuditStore(tmp_path / "interrupted-checkpoint.sqlite3")
    store.initialize()
    original_advance = store.checkpoint.compare_and_set

    def fail_before_checkpoint(**_kwargs):
        raise CheckpointError("simulated checkpoint outage")

    monkeypatch.setattr(store.checkpoint, "compare_and_set", fail_before_checkpoint)
    with pytest.raises(sqlite3.DatabaseError, match="requires recovery"):
        store.record(event("committed-before-checkpoint"))
    assert store.verify_integrity()["valid"] is False

    monkeypatch.setattr(store.checkpoint, "compare_and_set", original_advance)
    with pytest.raises(ValueError, match="explicit approval"):
        store.recover_checkpoint()
    result = store.recover_checkpoint(approve_unanchored_revision=True)
    assert result["valid"] is True
    assert store.get_event("committed-before-checkpoint") is not None


def test_concurrent_process_writers_advance_checkpoint_in_sequence(tmp_path):
    database = tmp_path / "concurrent-checkpoint.sqlite3"
    first = AuditStore(database)
    first.initialize()

    with ProcessPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_record_from_process, str(database), "concurrent-one"),
            pool.submit(_record_from_process, str(database), "concurrent-two"),
        ]
        for future in futures:
            future.result()

    result = first.verify_integrity()
    assert result["valid"] is True
    assert result["checked_entries"] == 2
    assert result["checked_events"] == 2


def test_missing_integrity_initialization_marker_does_not_rebaseline(tmp_path):
    database = tmp_path / "missing-integrity-marker.sqlite3"
    store = AuditStore(database)
    store.initialize()
    store.record(event("marker-event"))

    with sqlite3.connect(database) as connection:
        connection.execute(
            "DELETE FROM audit_integrity_meta WHERE key = 'baseline_initialized'"
        )

    result = store.verify_integrity()
    assert result["valid"] is False
    assert result["reason"] == "audit integrity initialization marker is missing or invalid"
    with pytest.raises(sqlite3.DatabaseError, match="initialization marker is missing"):
        store.initialize()
