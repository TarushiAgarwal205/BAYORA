import hashlib
import hmac
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from backend.audit_checkpoint import AuditCheckpoint, CheckpointError
from backend.config import AUDIT_CHECKPOINT_KEY


class AuditStore:
    """SQLite audit store with a verifiable, append-only event revision chain."""

    _ZERO_HASH = "0" * 64
    _EVENT_COLUMNS = (
        "event_id", "timestamp_utc", "session_id", "role", "action", "resource",
        "decision", "reason", "matched_rule_id", "observed_outcome",
        "verification_result", "operation_executed",
    )

    def __init__(self, database_path: Path, checkpoint_path=None, checkpoint_key=None):
        self.database_path = Path(database_path)
        if checkpoint_path is None:
            checkpoint_path = self.database_path.with_suffix(".checkpoint.sqlite3")
        self.checkpoint = AuditCheckpoint(
            checkpoint_path,
            AUDIT_CHECKPOINT_KEY if checkpoint_key is None else checkpoint_key,
        )

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self, *, allow_checkpoint_bootstrap=False):
        self.checkpoint.validate_key()
        database_was_new = not self.database_path.exists()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        checkpoint_bootstrap = None
        with self._connection() as connection:
            existing_tables = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            existing_integrity_tables = existing_tables.intersection(
                {"audit_integrity", "audit_integrity_meta"}
            )
            if "audit_events" in existing_tables and not existing_integrity_tables:
                existing_event = connection.execute(
                    "SELECT 1 FROM audit_events LIMIT 1"
                ).fetchone()
                if existing_event is not None:
                    raise sqlite3.DatabaseError(
                        "audit integrity tables are missing; refusing to re-baseline populated history"
                    )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp_utc TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY')),
                    reason TEXT NOT NULL,
                    matched_rule_id TEXT NOT NULL,
                    observed_outcome TEXT NOT NULL DEFAULT 'NOT_EXECUTED',
                    verification_result TEXT NOT NULL DEFAULT 'NOT_VERIFIED',
                    operation_executed INTEGER DEFAULT 0
                        CHECK (operation_executed IS NULL OR operation_executed IN (0, 1))
                )"""
            )
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(audit_events)")}
            if "operation_executed" not in columns:
                connection.execute(
                    "ALTER TABLE audit_events ADD COLUMN operation_executed INTEGER DEFAULT 0 "
                    "CHECK (operation_executed IS NULL OR operation_executed IN (0, 1))"
                )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS audit_integrity (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS audit_integrity_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )"""
            )
            initialized = connection.execute(
                "SELECT value FROM audit_integrity_meta WHERE key = 'baseline_initialized'"
            ).fetchone()
            if initialized is None:
                if existing_integrity_tables:
                    raise sqlite3.DatabaseError(
                        "audit integrity initialization marker is missing"
                    )
                rows = connection.execute(
                    "SELECT * FROM audit_events ORDER BY timestamp_utc, event_id"
                ).fetchall()
                for row in rows:
                    self._append_integrity_entry(connection, row["event_id"])
                connection.execute(
                    "INSERT INTO audit_integrity_meta (key, value) VALUES ('baseline_initialized', '1')"
                )
            elif initialized["value"] != "1":
                raise sqlite3.DatabaseError(
                    "audit integrity initialization marker is invalid"
                )

            local = self._verify_local_integrity_connection(connection)
            if not local["valid"]:
                raise sqlite3.DatabaseError(
                    "audit integrity verification failed during initialization"
                )
            database_id_row = connection.execute(
                "SELECT value FROM audit_integrity_meta WHERE key = 'database_id'"
            ).fetchone()
            checkpoint_exists = self.checkpoint.path.is_file()
            if database_id_row is None:
                if not database_was_new and not allow_checkpoint_bootstrap:
                    raise sqlite3.DatabaseError(
                        "audit checkpoint identity is missing; explicit bootstrap is required"
                    )
                database_id = uuid4().hex
                connection.execute(
                    "INSERT INTO audit_integrity_meta (key, value) VALUES ('database_id', ?)",
                    (database_id,),
                )
            else:
                database_id = database_id_row["value"]

            if not checkpoint_exists and not (database_was_new or allow_checkpoint_bootstrap):
                raise sqlite3.DatabaseError(
                    "audit checkpoint is missing; refusing to establish a new baseline"
                )
            if not checkpoint_exists:
                checkpoint_bootstrap = (
                    database_id, local["_head_sequence"], local["_head_hash"]
                )

        if checkpoint_bootstrap is not None:
            try:
                self.checkpoint.bootstrap(*checkpoint_bootstrap)
            except CheckpointError as error:
                raise sqlite3.DatabaseError(
                    "audit checkpoint could not be initialized"
                ) from error

        result = self.verify_integrity()
        if not result["valid"]:
            raise sqlite3.DatabaseError("audit integrity verification failed during initialization")

    def record(self, event):
        with self.checkpoint.writer_lock():
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                database_id, previous_sequence, previous_hash = self._assert_integrity(connection)
                # session_id is a correlation label scoped by the authenticated role.
                # It is not an authentication credential and may be reused by another role.
                self._insert_decision_event(connection, event)
                sequence, head_hash = self._current_head(connection)
            self._advance_checkpoint(
                database_id, previous_sequence, previous_hash, sequence, head_hash
            )
        return event

    def _insert_decision_event(self, connection, event):
        connection.execute(
            """INSERT INTO audit_events (
                event_id, timestamp_utc, session_id, role, action, resource,
                decision, reason, matched_rule_id, observed_outcome, verification_result,
                operation_executed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event["event_id"], event["timestamp_utc"], event["session_id"],
                event["role"], event["action"], event["resource"],
                event["decision"], event["reason"], event["matched_rule_id"],
                "NOT_EXECUTED",
                "NOT_VERIFIED",
                0,
            ),
        )
        self._append_integrity_entry(connection, event["event_id"])

    def record_pending_operation(self, event):
        if event["decision"] != "ALLOW":
            raise ValueError("only ALLOW decisions can start a resource operation")
        with self.checkpoint.writer_lock():
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                database_id, previous_sequence, previous_hash = self._assert_integrity(connection)
                connection.execute(
                    """INSERT INTO audit_events (
                        event_id, timestamp_utc, session_id, role, action, resource,
                        decision, reason, matched_rule_id, observed_outcome,
                        verification_result, operation_executed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 'NOT_VERIFIED', NULL)""",
                    (
                        event["event_id"], event["timestamp_utc"], event["session_id"],
                        event["role"], event["action"], event["resource"], event["decision"],
                        event["reason"], event["matched_rule_id"],
                    ),
                )
                self._append_integrity_entry(connection, event["event_id"])
                sequence, head_hash = self._current_head(connection)
            self._advance_checkpoint(
                database_id, previous_sequence, previous_hash, sequence, head_hash
            )
        return event

    def complete_operation(
        self, event_id, operation_executed, observed_outcome, verification_result,
        *, reason=None,
    ):
        valid = {
            (False, "NOT_EXECUTED", "NOT_VERIFIED"),
            (None, "UNKNOWN", "NOT_VERIFIED"),
            (True, "SUCCEEDED", "VERIFIED"),
            (True, "SUCCEEDED", "FAILED"),
            (True, "SUCCEEDED", "NOT_VERIFIED"),
            (True, "FAILED", "NOT_VERIFIED"),
            (True, "FAILED", "FAILED"),
        }
        if (operation_executed, observed_outcome, verification_result) not in valid:
            raise ValueError("invalid operation outcome or verification state")
        encoded_executed = None if operation_executed is None else int(operation_executed)
        with self.checkpoint.writer_lock():
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                database_id, previous_sequence, previous_hash = self._assert_integrity(connection)
                cursor = connection.execute(
                    """UPDATE audit_events
                       SET operation_executed = ?, observed_outcome = ?, verification_result = ?,
                           reason = COALESCE(?, reason)
                       WHERE event_id = ? AND decision = 'ALLOW' AND observed_outcome = 'PENDING'""",
                    (encoded_executed, observed_outcome, verification_result, reason, event_id),
                )
                if cursor.rowcount != 1:
                    raise ValueError("pending operation audit event not found")
                self._append_integrity_entry(connection, event_id)
                sequence, head_hash = self._current_head(connection)
            self._advance_checkpoint(
                database_id, previous_sequence, previous_hash, sequence, head_hash
            )

    def _append_integrity_entry(self, connection, event_id):
        row = connection.execute(
            "SELECT * FROM audit_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row is None:
            raise ValueError("audit event not found for integrity entry")
        snapshot = {column: row[column] for column in self._EVENT_COLUMNS}
        snapshot_json = json.dumps(
            snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        previous = connection.execute(
            "SELECT entry_hash FROM audit_integrity ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["entry_hash"] if previous else self._ZERO_HASH
        entry_hash = hashlib.sha256(
            f"{previous_hash}\n{snapshot_json}".encode("utf-8")
        ).hexdigest()
        connection.execute(
            """INSERT INTO audit_integrity
               (event_id, snapshot_json, previous_hash, entry_hash)
               VALUES (?, ?, ?, ?)""",
            (event_id, snapshot_json, previous_hash, entry_hash),
        )

    def _verify_local_integrity_connection(self, connection):
        initialized = connection.execute(
            "SELECT value FROM audit_integrity_meta WHERE key = 'baseline_initialized'"
        ).fetchone()
        if initialized is None or initialized["value"] != "1":
            return {
                "valid": False,
                "checked_entries": 0,
                "reason": "audit integrity initialization marker is missing or invalid",
            }

        rows = connection.execute(
            "SELECT * FROM audit_integrity ORDER BY sequence"
        ).fetchall()
        previous_hash = self._ZERO_HASH
        hashes_by_sequence = {0: self._ZERO_HASH}
        latest_snapshots = {}
        for expected_sequence, row in enumerate(rows, start=1):
            if row["sequence"] != expected_sequence:
                return {
                    "valid": False,
                    "checked_entries": expected_sequence - 1,
                    "reason": "integrity sequence is incomplete",
                }
            if row["previous_hash"] != previous_hash:
                return {
                    "valid": False,
                    "checked_entries": expected_sequence - 1,
                    "reason": "integrity chain link does not match",
                }
            try:
                snapshot = json.loads(row["snapshot_json"])
            except (TypeError, json.JSONDecodeError):
                return {
                    "valid": False,
                    "checked_entries": expected_sequence - 1,
                    "reason": "integrity snapshot is invalid",
                }
            if not isinstance(snapshot, dict) or set(snapshot) != set(self._EVENT_COLUMNS):
                return {
                    "valid": False,
                    "checked_entries": expected_sequence - 1,
                    "reason": "integrity snapshot fields are invalid",
                }
            canonical = json.dumps(
                snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            expected_hash = hashlib.sha256(
                f"{previous_hash}\n{canonical}".encode("utf-8")
            ).hexdigest()
            if row["entry_hash"] != expected_hash or row["event_id"] != snapshot["event_id"]:
                return {
                    "valid": False,
                    "checked_entries": expected_sequence - 1,
                    "reason": "integrity entry hash does not match",
                }
            previous_hash = row["entry_hash"]
            hashes_by_sequence[expected_sequence] = previous_hash
            latest_snapshots[row["event_id"]] = snapshot

        current_rows = connection.execute("SELECT * FROM audit_events").fetchall()
        current_snapshots = {
            row["event_id"]: {column: row[column] for column in self._EVENT_COLUMNS}
            for row in current_rows
        }
        if current_snapshots != latest_snapshots:
            return {
                "valid": False,
                "checked_entries": len(rows),
                "reason": "audit events do not match their latest integrity snapshots",
            }
        database_id_row = connection.execute(
            "SELECT value FROM audit_integrity_meta WHERE key = 'database_id'"
        ).fetchone()
        return {
            "valid": True,
            "checked_entries": len(rows),
            "checked_events": len(current_rows),
            "reason": "integrity chain verified",
            "_database_id": database_id_row["value"] if database_id_row else None,
            "_head_sequence": len(rows),
            "_head_hash": previous_hash,
            "_hashes_by_sequence": hashes_by_sequence,
        }

    def _verify_integrity_connection(self, connection):
        local = self._verify_local_integrity_connection(connection)
        if not local["valid"]:
            return local
        if not local["_database_id"]:
            return {
                "valid": False,
                "checked_entries": local["checked_entries"],
                "checked_events": local["checked_events"],
                "reason": "audit checkpoint database identity is missing",
            }
        checkpoint = self.checkpoint.verify(
            database_id=local["_database_id"],
            sequence=local["_head_sequence"],
            head_hash=local["_head_hash"],
        )
        if not checkpoint["valid"]:
            return {
                "valid": False,
                "checked_entries": local["checked_entries"],
                "checked_events": local["checked_events"],
                "reason": checkpoint["reason"],
            }
        return {
            "valid": True,
            "checked_entries": local["checked_entries"],
            "checked_events": local["checked_events"],
            "reason": "integrity chain and external checkpoint verified",
        }

    def _current_head(self, connection):
        row = connection.execute(
            "SELECT sequence, entry_hash FROM audit_integrity ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        return (row["sequence"], row["entry_hash"]) if row else (0, self._ZERO_HASH)

    def _advance_checkpoint(
        self, database_id, previous_sequence, previous_hash, sequence, head_hash
    ):
        operation_id = f"{database_id}:{sequence}"
        try:
            self.checkpoint.compare_and_set(
                database_id=database_id,
                expected_sequence=previous_sequence,
                expected_hash=previous_hash,
                sequence=sequence,
                head_hash=head_hash,
                operation_id=operation_id,
            )
        except CheckpointError as error:
            # The SQLite transaction already committed. A retry is safe only if
            # the persistent checkpoint proves this exact operation was accepted.
            try:
                state = self.checkpoint.read()
            except CheckpointError:
                state = None
            if not (
                state
                and state["operation_id"] == operation_id
                and state["database_id"] == database_id
                and state["sequence"] == sequence
                and state["head_hash"] == head_hash
                and state["previous_sequence"] == previous_sequence
                and state["previous_hash"] == previous_hash
            ):
                raise sqlite3.DatabaseError(
                    "audit checkpoint update failed; audit store requires recovery"
                ) from error

    def recover_checkpoint(self, *, approve_unanchored_revision=False):
        """Anchor one locally valid committed revision after explicit operator approval."""
        if not approve_unanchored_revision:
            raise ValueError("explicit approval is required to recover an unanchored audit revision")
        with self.checkpoint.writer_lock():
            with self._connection() as connection:
                local = self._verify_local_integrity_connection(connection)
                if not local["valid"] or not local["_database_id"]:
                    raise sqlite3.DatabaseError("local audit chain cannot be safely recovered")
            try:
                state = self.checkpoint.read()
            except CheckpointError as error:
                raise sqlite3.DatabaseError(
                    "audit checkpoint is unavailable; refusing to establish a new baseline"
                ) from error
            database_id = local["_database_id"]
            if state["database_id"] != database_id:
                raise sqlite3.DatabaseError("audit checkpoint database identity mismatch")
            if (
                state["sequence"] == local["_head_sequence"]
                and state["head_hash"] == local["_head_hash"]
            ):
                pass
            elif local["_head_sequence"] != state["sequence"] + 1:
                raise sqlite3.DatabaseError(
                    "recovery requires exactly one unanchored revision; manual restore is required"
                )
            elif local["_hashes_by_sequence"].get(state["sequence"]) != state["head_hash"]:
                raise sqlite3.DatabaseError(
                    "unanchored revision does not extend the trusted checkpoint"
                )
            else:
                self._advance_checkpoint(
                    database_id,
                    state["sequence"],
                    state["head_hash"],
                    local["_head_sequence"],
                    local["_head_hash"],
                )
        return self.verify_integrity()

    def _assert_integrity(self, connection):
        result = self._verify_integrity_connection(connection)
        if not result["valid"]:
            raise sqlite3.DatabaseError(
                f"audit integrity verification failed: {result['reason']}"
            )
        local = self._verify_local_integrity_connection(connection)
        return (
            local["_database_id"], local["_head_sequence"], local["_head_hash"]
        )

    def verify_integrity(self):
        # SQLite is committed before the independent checkpoint advances.
        # Share the writer lock so readers cannot observe that brief interval.
        try:
            with self.checkpoint.writer_lock():
                with self._connection() as connection:
                    return self._verify_integrity_connection(connection)
        except (OSError, sqlite3.DatabaseError, TypeError, ValueError, UnicodeError) as error:
            return {
                "valid": False,
                "checked_entries": 0,
                "checked_events": 0,
                "reason": f"audit integrity data is malformed or unavailable ({type(error).__name__})",
            }

    def get_session_role(self, session_id):
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT DISTINCT role FROM audit_events WHERE session_id = ? ORDER BY role",
                (session_id,),
            ).fetchall()
            return rows[0]["role"] if len(rows) == 1 else None

    def list_events(self, limit=50, offset=0, session_id=None, decision=None, role=None):
        clauses = []
        values = []
        if session_id is not None:
            clauses.append("session_id = ?")
            values.append(session_id)
        if decision is not None:
            clauses.append("decision = ?")
            values.append(decision)
        if role is not None:
            clauses.append("role = ?")
            values.append(role)
        where_clause = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        query = (
            "SELECT * FROM audit_events" + where_clause
            + " ORDER BY timestamp_utc DESC, event_id DESC LIMIT ? OFFSET ?"
        )
        values.extend((limit, offset))
        with self._connection() as connection:
            rows = connection.execute(query, values).fetchall()
            return [dict(row) for row in rows]

    def search_events(
        self, *, limit=50, offset=0, role=None, session_id=None, decision=None,
        action=None, query_text=None, since=None, until=None,
    ):
        """Search incident records; every filter remains a bound SQL value."""
        clauses = []
        values = []
        for field, value in (
            ("role", role), ("session_id", session_id),
            ("decision", decision), ("action", action),
        ):
            if value is not None:
                clauses.append(f"{field} = ?")
                values.append(value)
        if since is not None:
            clauses.append("timestamp_utc >= ?")
            values.append(since)
        if until is not None:
            clauses.append("timestamp_utc <= ?")
            values.append(until)
        if query_text:
            escaped = query_text.replace("!", "!!").replace("%", "!%").replace("_", "!_")
            clauses.append(
                "(event_id LIKE ? ESCAPE '!' OR session_id LIKE ? ESCAPE '!' "
                "OR action LIKE ? ESCAPE '!' OR resource LIKE ? ESCAPE '!' "
                "OR reason LIKE ? ESCAPE '!')"
            )
            pattern = f"%{escaped}%"
            values.extend((pattern,) * 5)
        where_clause = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT * FROM audit_events" + where_clause
            + " ORDER BY timestamp_utc DESC, event_id DESC LIMIT ? OFFSET ?"
        )
        values.extend((limit, offset))
        with self._connection() as connection:
            return [dict(row) for row in connection.execute(sql, values).fetchall()]

    def get_event(self, event_id, role=None):
        query = "SELECT * FROM audit_events WHERE event_id = ?"
        values = [event_id]
        if role is not None:
            query += " AND role = ?"
            values.append(role)
        with self._connection() as connection:
            row = connection.execute(query, values).fetchone()
            return dict(row) if row else None


def utc_timestamp():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
