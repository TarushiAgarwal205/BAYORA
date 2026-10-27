"""Small validated configuration store for detection tuning."""

import json
import os
import tempfile
from pathlib import Path
from threading import RLock


DEFAULT_SECURITY_CONFIG = {
    "version": 1,
    "prompt_inspection_enabled": True,
    "block_high_severity": True,
    "anomaly_detection_enabled": True,
    "medium_severity_action": "FLAG",
    "repeated_denial_threshold": 3,
}


class SecurityConfigError(ValueError):
    pass


class SecurityConfigStore:
    """Persist only safe detection tuning; mandatory controls are immutable."""

    def __init__(self, path):
        self.path = Path(path)
        self._lock = RLock()

    def read(self):
        with self._lock:
            if not self.path.exists():
                return dict(DEFAULT_SECURITY_CONFIG)
            try:
                value = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise SecurityConfigError("security configuration is unreadable") from error
            return self.validate(value)

    def update(self, values):
        with self._lock:
            current = self.read()
            if not isinstance(values, dict) or not values:
                raise SecurityConfigError("at least one configuration field is required")
            mutable = {"medium_severity_action", "repeated_denial_threshold"}
            if set(values) - mutable:
                raise SecurityConfigError("requested fields are immutable or unsupported")
            updated = self.validate({**current, **values})
            self.path.parent.mkdir(parents=True, exist_ok=True)
            previous = self.path.read_bytes() if self.path.exists() else None
            encoded = (json.dumps(updated, indent=2, sort_keys=True) + "\n").encode("utf-8")
            temp_name = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb", dir=self.path.parent, prefix=f".{self.path.name}.",
                    suffix=".tmp", delete=False,
                ) as temporary:
                    temp_name = temporary.name
                    temporary.write(encoded)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                os.replace(temp_name, self.path)
                if self.read() != updated:
                    raise SecurityConfigError("configuration failed read-back validation")
            except Exception:
                if temp_name and os.path.exists(temp_name):
                    os.unlink(temp_name)
                self.restore(previous)
                raise
            return updated

    def restore(self, contents):
        with self._lock:
            if contents is None:
                if self.path.exists():
                    self.path.unlink()
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temp_name = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb", dir=self.path.parent, prefix=f".{self.path.name}.",
                    suffix=".tmp", delete=False,
                ) as temporary:
                    temp_name = temporary.name
                    temporary.write(contents)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                os.replace(temp_name, self.path)
            finally:
                if temp_name and os.path.exists(temp_name):
                    os.unlink(temp_name)
            self.read()

    @staticmethod
    def validate(value):
        if not isinstance(value, dict) or set(value) != set(DEFAULT_SECURITY_CONFIG):
            raise SecurityConfigError("security configuration has unsupported fields")
        if value.get("version") != 1:
            raise SecurityConfigError("security configuration version is invalid")
        mandatory = (
            "prompt_inspection_enabled", "block_high_severity", "anomaly_detection_enabled"
        )
        if any(value.get(key) is not True for key in mandatory):
            raise SecurityConfigError("required inspection and integrity controls cannot be disabled")
        if value.get("medium_severity_action") not in {"FLAG", "DENY"}:
            raise SecurityConfigError("medium severity action must be FLAG or DENY")
        threshold = value.get("repeated_denial_threshold")
        if isinstance(threshold, bool) or not isinstance(threshold, int) or not 3 <= threshold <= 10:
            raise SecurityConfigError("repeated denial threshold must be between 3 and 10")
        return dict(value)
