"""Persistent authenticated checkpoints for the SQLite audit revision chain."""

import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
from contextlib import contextmanager
import threading

if os.name == "nt":
    import msvcrt
else:
    import fcntl


_THREAD_LOCKS = {}
_THREAD_LOCKS_GUARD = threading.Lock()


class CheckpointError(RuntimeError):
    """Checkpoint state is missing, unavailable, or inconsistent."""


class AuditCheckpoint:
    """Store a signed chain head separately from the audit database."""

    _VERSION = 1
    _ZERO_HASH = "0" * 64

    def __init__(self, path, key):
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self.key = key.encode("utf-8") if isinstance(key, str) else (key or b"")

    def _require_key(self):
        if len(self.key) < 32:
            raise CheckpointError(
                "BAYORA_AUDIT_CHECKPOINT_KEY must contain at least 32 bytes"
            )

    def validate_key(self):
        """Fail before any audit-database mutation if checkpoint auth is misconfigured."""
        self._require_key()

    @contextmanager
    def writer_lock(self):
        """Serialize database-plus-checkpoint writes across local processes."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_name = os.path.normcase(str(self.lock_path.resolve()))
        with _THREAD_LOCKS_GUARD:
            thread_lock = _THREAD_LOCKS.setdefault(lock_name, threading.RLock())
        with thread_lock:
            with self.lock_path.open("a+b") as lock_file:
                if lock_file.seek(0, os.SEEK_END) == 0:
                    lock_file.write(b"\0")
                    lock_file.flush()
                lock_file.seek(0)
                if os.name == "nt":
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    lock_file.seek(0)
                    if os.name == "nt":
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _connect(self, *, create=False):
        if not create and not self.path.is_file():
            raise CheckpointError("audit checkpoint is missing")
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            connection = sqlite3.connect(self.path, timeout=5)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except (OSError, sqlite3.Error) as error:
            raise CheckpointError("audit checkpoint is unavailable") from error

    @staticmethod
    def _canonical(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def _signature(self, payload):
        self._require_key()
        message = ("bayora-audit-checkpoint-v1\n" + self._canonical(payload)).encode("utf-8")
        return hmac.new(self.key, message, hashlib.sha256).hexdigest()

    def _signed_state(self, database_id, sequence, head_hash, operation_id,
                      previous_sequence, previous_hash):
        payload = {
            "version": self._VERSION,
            "database_id": database_id,
            "sequence": sequence,
            "head_hash": head_hash,
            "operation_id": operation_id,
            "previous_sequence": previous_sequence,
            "previous_hash": previous_hash,
        }
        return payload, self._signature(payload)

    def _read_state(self, connection):
        try:
            tables = {
                row["name"] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            if "checkpoint_state" not in tables:
                raise CheckpointError("audit checkpoint state is missing")
            rows = connection.execute(
                "SELECT * FROM checkpoint_state WHERE singleton = 1"
            ).fetchall()
            if len(rows) != 1:
                raise CheckpointError("audit checkpoint state is missing or ambiguous")
            row = rows[0]
            payload = {
                "version": row["version"],
                "database_id": row["database_id"],
                "sequence": row["sequence"],
                "head_hash": row["head_hash"],
                "operation_id": row["operation_id"],
                "previous_sequence": row["previous_sequence"],
                "previous_hash": row["previous_hash"],
            }
            if not hmac.compare_digest(row["signature"], self._signature(payload)):
                raise CheckpointError("audit checkpoint authentication failed")
            if payload["version"] != self._VERSION:
                raise CheckpointError("audit checkpoint version is unsupported")
            return payload
        except CheckpointError:
            raise
        except (sqlite3.Error, TypeError, ValueError, KeyError) as error:
            raise CheckpointError("audit checkpoint is invalid or unavailable") from error

    def read(self):
        self._require_key()
        connection = self._connect()
        try:
            return self._read_state(connection)
        finally:
            connection.close()

    def bootstrap(self, database_id, sequence, head_hash):
        """Create a checkpoint only when explicitly invoked by initialization/migration."""
        self._require_key()
        if self.path.exists():
            raise CheckpointError("audit checkpoint already exists; refusing to replace it")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.writer_lock():
                connection = self._connect(create=True)
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(
                        """CREATE TABLE IF NOT EXISTS checkpoint_state (
                            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                            version INTEGER NOT NULL,
                            database_id TEXT NOT NULL,
                            sequence INTEGER NOT NULL,
                            head_hash TEXT NOT NULL,
                            operation_id TEXT NOT NULL,
                            previous_sequence INTEGER,
                            previous_hash TEXT,
                            signature TEXT NOT NULL
                        )"""
                    )
                    if connection.execute(
                        "SELECT 1 FROM checkpoint_state LIMIT 1"
                    ).fetchone():
                        raise CheckpointError(
                            "audit checkpoint already exists; refusing to replace it"
                        )
                    payload, signature = self._signed_state(
                        database_id, sequence, head_hash,
                        f"bootstrap:{database_id}", None, None,
                    )
                    connection.execute(
                        """INSERT INTO checkpoint_state (
                            singleton, version, database_id, sequence, head_hash,
                            operation_id, previous_sequence, previous_hash, signature
                        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            payload["version"], payload["database_id"],
                            payload["sequence"], payload["head_hash"],
                            payload["operation_id"], payload["previous_sequence"],
                            payload["previous_hash"], signature,
                        ),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
                finally:
                    connection.close()
        except CheckpointError:
            raise
        except (OSError, sqlite3.Error) as error:
            raise CheckpointError("audit checkpoint could not be initialized") from error

    def compare_and_set(self, *, database_id, expected_sequence, expected_hash,
                        sequence, head_hash, operation_id):
        """Advance exactly one chain revision; retries are idempotent by operation ID."""
        self._require_key()
        if sequence != expected_sequence + 1:
            raise CheckpointError("checkpoint update must advance exactly one revision")
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                state = self._read_state(connection)
                if state["database_id"] != database_id:
                    raise CheckpointError("audit checkpoint database identity mismatch")
                if state["operation_id"] == operation_id:
                    if (
                        state["sequence"] == sequence
                        and state["head_hash"] == head_hash
                        and state["previous_sequence"] == expected_sequence
                        and state["previous_hash"] == expected_hash
                    ):
                        connection.commit()
                        return state
                    raise CheckpointError("checkpoint retry conflicts with its committed operation")
                if (
                    state["sequence"] != expected_sequence
                    or state["head_hash"] != expected_hash
                ):
                    raise CheckpointError("audit checkpoint compare-and-set conflict")
                payload, signature = self._signed_state(
                    database_id, sequence, head_hash, operation_id,
                    expected_sequence, expected_hash,
                )
                connection.execute(
                    """UPDATE checkpoint_state SET version = ?, sequence = ?, head_hash = ?,
                        operation_id = ?, previous_sequence = ?, previous_hash = ?, signature = ?
                        WHERE singleton = 1""",
                    (
                        payload["version"], payload["sequence"], payload["head_hash"],
                        payload["operation_id"], payload["previous_sequence"],
                        payload["previous_hash"], signature,
                    ),
                )
                connection.commit()
                return payload
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except CheckpointError:
            raise
        except (OSError, sqlite3.Error) as error:
            raise CheckpointError("audit checkpoint update is unavailable") from error

    def verify(self, *, database_id, sequence, head_hash):
        try:
            state = self.read()
        except CheckpointError as error:
            return {"valid": False, "reason": str(error)}
        valid = (
            state["database_id"] == database_id
            and state["sequence"] == sequence
            and state["head_hash"] == head_hash
        )
        return {
            "valid": valid,
            "reason": "audit checkpoint matches" if valid else "audit checkpoint head does not match",
        }
