import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


class AuditStore:
    """SQLite audit store with a verifiable, append-only event revision chain."""

    _ZERO_HASH = "0" * 64
    _EVENT_COLUMNS = (
        "event_id", "timestamp_utc", "session_id", "role", "action", "resource",
        "decision", "reason", "matched_rule_id", "observed_outcome",
        "verification_result", "operation_executed",
    )

    def __init__(self, database_path: Path):
        self.database_path = Path(database_path)

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

    def initialize(self):
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
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

    def record(self, event):
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_integrity(connection)
            # session_id is a correlation label scoped by the authenticated role.
            # It is not an authentication credential and may be reused by another role.
            self._insert_decision_event(connection, event)
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
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_integrity(connection)
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
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_integrity(connection)
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

    def _verify_integrity_connection(self, connection):
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
        return {
            "valid": True,
            "checked_entries": len(rows),
            "checked_events": len(current_rows),
            "reason": "integrity chain verified",
        }

    def _assert_integrity(self, connection):
        result = self._verify_integrity_connection(connection)
        if not result["valid"]:
            raise sqlite3.DatabaseError("audit integrity verification failed")

    def verify_integrity(self):
        with self._connection() as connection:
            return self._verify_integrity_connection(connection)

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
