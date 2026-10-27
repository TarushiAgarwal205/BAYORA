import json
import re
from dataclasses import dataclass
from pathlib import Path


_RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    reason: str
    matched_rule_id: str


class PolicyEngine:
    """Loads explicit rules and evaluates normalized policy inputs."""

    def __init__(self, rules_path: Path):
        self.rules_path = Path(rules_path)
        self.rules = []
        self.configuration_error = None
        self._load_rules()

    def reload(self):
        """Reload rules after an administrator's validated atomic update."""
        self.rules = []
        self.configuration_error = None
        self._load_rules()
        return not self.configuration_error

    def _load_rules(self):
        try:
            with self.rules_path.open("r", encoding="utf-8") as rules_file:
                document = json.load(rules_file)
            self.rules = self._validate_document(document)
        except FileNotFoundError:
            self.configuration_error = "rules file is missing"
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError):
            self.configuration_error = "rules file is invalid"

    @staticmethod
    def _validate_document(document):
        if not isinstance(document, dict) or set(document) != {"version", "rules"}:
            raise ValueError("invalid rule document shape")
        if document["version"] != 1 or not isinstance(document["rules"], list):
            raise ValueError("invalid rule document version or list")

        rules = document["rules"]
        rule_ids = set()
        for rule in rules:
            if (
                not isinstance(rule, dict)
                or not {"rule_id", "effect", "role", "action", "resource_match"}.issubset(rule)
                or set(rule) - {"rule_id", "effect", "role", "action", "resource_match", "enabled"}
            ):
                raise ValueError("invalid rule shape")
            if "enabled" in rule and not isinstance(rule["enabled"], bool):
                raise ValueError("invalid enabled flag")
            rule_id = rule["rule_id"]
            if not isinstance(rule_id, str) or not _RULE_ID_PATTERN.fullmatch(rule_id):
                raise ValueError("invalid rule id")
            if rule_id in rule_ids:
                raise ValueError("duplicate rule id")
            rule_ids.add(rule_id)
            if rule["effect"] not in {"ALLOW", "DENY"}:
                raise ValueError("invalid effect")
            if rule["role"] not in {"red", "blue"}:
                raise ValueError("invalid rule role")
            for field in ("role", "action"):
                if not isinstance(rule[field], str) or not rule[field].strip() or len(rule[field]) > 64:
                    raise ValueError("invalid rule field")
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", rule["action"]):
                raise ValueError("invalid rule action")
            resource_match = rule["resource_match"]
            if not isinstance(resource_match, dict):
                raise ValueError("invalid resource matcher")
            matcher_type = resource_match.get("type")
            if matcher_type == "exact":
                if set(resource_match) != {"type", "values"}:
                    raise ValueError("invalid exact matcher")
                values = resource_match["values"]
                if (not isinstance(values, list) or not values or len(values) > 100 or
                        any(not isinstance(value, str) or not value or len(value) > 128 for value in values)):
                    raise ValueError("invalid exact values")
            elif matcher_type == "prefix":
                if set(resource_match) != {"type", "value"}:
                    raise ValueError("invalid prefix matcher")
                if (not isinstance(resource_match["value"], str) or not resource_match["value"]
                        or len(resource_match["value"]) > 128):
                    raise ValueError("invalid prefix value")
            else:
                raise ValueError("unknown matcher type")
        return rules

    def get_rules(self):
        if self.configuration_error:
            raise RuntimeError(self.configuration_error)
        return json.loads(json.dumps({"version": 1, "rules": self.rules}))

    def decide(self, role, action, resource):
        if self.configuration_error:
            return PolicyDecision(
                "DENY",
                f"policy configuration error: {self.configuration_error}",
                "configuration-error",
            )

        role = role.strip().lower()
        action = action.strip().lower()
        resource = resource.strip().lower()
        if ".." in resource:
            return PolicyDecision("DENY", "suspicious resource path syntax", "default-deny")

        matches = []
        for rule in self.rules:
            if rule.get("enabled", True) is False:
                continue
            if rule["role"].strip().lower() != role:
                continue
            if rule["action"].strip().lower() != action:
                continue
            matcher = rule["resource_match"]
            if matcher["type"] == "exact":
                resource_matches = resource in [value.strip().lower() for value in matcher["values"]]
            else:
                resource_matches = resource.startswith(matcher["value"].strip().lower())
            if resource_matches:
                matches.append(rule)

        deny = next((rule for rule in matches if rule["effect"] == "DENY"), None)
        if deny:
            return PolicyDecision("DENY", "matched explicit deny rule", deny["rule_id"])
        allow = next((rule for rule in matches if rule["effect"] == "ALLOW"), None)
        if allow:
            return PolicyDecision("ALLOW", "matched explicit allow rule", allow["rule_id"])
        return PolicyDecision("DENY", "no matching allow rule (default deny)", "default-deny")
