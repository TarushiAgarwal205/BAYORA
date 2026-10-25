import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


class AuditStore:
    """Small SQLite store for policy decision events."""

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

    def record(self, event):
        with self._connection() as connection:
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

    def record_pending_operation(self, event):
        if event["decision"] != "ALLOW":
            raise ValueError("only ALLOW decisions can start a resource operation")
        with self._connection() as connection:
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

    def complete_operation(self, event_id, operation_executed, observed_outcome, verification_result):
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
            cursor = connection.execute(
                """UPDATE audit_events
                   SET operation_executed = ?, observed_outcome = ?, verification_result = ?
                   WHERE event_id = ? AND decision = 'ALLOW' AND observed_outcome = 'PENDING'""",
                (encoded_executed, observed_outcome, verification_result, event_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("pending operation audit event not found")

    def list_events(self, limit=50, offset=0, session_id=None, decision=None):
        clauses = []
        values = []
        if session_id is not None:
            clauses.append("session_id = ?")
            values.append(session_id)
        if decision is not None:
            clauses.append("decision = ?")
            values.append(decision)
        where_clause = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        query = (
            "SELECT * FROM audit_events" + where_clause
            + " ORDER BY timestamp_utc DESC, event_id DESC LIMIT ? OFFSET ?"
        )
        values.extend((limit, offset))
        with self._connection() as connection:
            rows = connection.execute(query, values).fetchall()
            return [dict(row) for row in rows]

    def get_event(self, event_id):
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM audit_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            return dict(row) if row else None


def utc_timestamp():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
