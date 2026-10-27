"""Validated, atomic management for the policy rule document."""

import json
import os
import tempfile
from pathlib import Path
from threading import RLock

from backend.policy import PolicyEngine


class PolicyManagementError(ValueError):
    pass


class PolicyFileStore:
    """Mutate rules without removing the required Red-to-Blue deny guard."""

    def __init__(self, rules_path):
        self.path = Path(rules_path)
        self._lock = RLock()

    def read(self):
        with self._lock:
            return self._read_document()

    def create(self, rule):
        with self._lock:
            document = self._read_document()
            if any(item["rule_id"] == rule["rule_id"] for item in document["rules"]):
                raise PolicyManagementError("rule ID already exists")
            updated = {**document, "rules": [*document["rules"], dict(rule)]}
            return self._save(updated)

    def update(self, rule_id, rule):
        with self._lock:
            document = self._read_document()
            found = False
            rules = []
            for current in document["rules"]:
                if current["rule_id"] == rule_id:
                    found = True
                    rules.append(dict(rule))
                else:
                    rules.append(current)
            if not found:
                raise PolicyManagementError("rule not found")
            return self._save({**document, "rules": rules})

    def set_enabled(self, rule_id, enabled):
        with self._lock:
            document = self._read_document()
            found = False
            rules = []
            for current in document["rules"]:
                if current["rule_id"] == rule_id:
                    found = True
                    changed = dict(current)
                    changed["enabled"] = enabled
                    rules.append(changed)
                else:
                    rules.append(current)
            if not found:
                raise PolicyManagementError("rule not found")
            return self._save({**document, "rules": rules})

    def delete(self, rule_id):
        with self._lock:
            document = self._read_document()
            rules = [item for item in document["rules"] if item["rule_id"] != rule_id]
            if len(rules) == len(document["rules"]):
                raise PolicyManagementError("rule not found")
            return self._save({**document, "rules": rules})

    def restore(self, contents):
        """Restore exact previous bytes if post-write auditing cannot finish."""
        with self._lock:
            self._atomic_write(contents)
            self._read_document()

    def _read_document(self):
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
            rules = PolicyEngine._validate_document(document)
            self._validate_security_invariants(rules)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise PolicyManagementError("policy file is missing or invalid; management is disabled") from error
        return {"version": 1, "rules": rules}

    def _save(self, document):
        try:
            rules = PolicyEngine._validate_document(document)
            self._validate_security_invariants(rules)
        except (TypeError, ValueError) as error:
            raise PolicyManagementError(str(error)) from error
        previous = self.path.read_bytes()
        encoded = (json.dumps({"version": 1, "rules": rules}, indent=2) + "\n").encode("utf-8")
        self._atomic_write(encoded)
        try:
            reread = self._read_document()
        except Exception:
            self._atomic_write(previous)
            raise
        if reread["rules"] != rules:
            self._atomic_write(previous)
            raise PolicyManagementError("policy write did not pass read-back validation")
        return {"version": 1, "rules": rules}, previous

    def _atomic_write(self, contents):
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

    @staticmethod
    def _validate_security_invariants(rules):
        protected_deny_present = any(
            rule.get("enabled", True)
            and rule["effect"] == "DENY"
            and rule["role"].strip().lower() == "red"
            and rule["action"].strip().lower() == "read_artifact"
            and rule["resource_match"].get("type") == "prefix"
            and rule["resource_match"].get("value", "").strip().lower() == "blue:"
            for rule in rules
        )
        if not protected_deny_present:
            raise PolicyManagementError(
                "the enabled Red-to-Blue resource deny rule is a required policy safeguard"
            )
