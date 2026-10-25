import json

from backend.policy import PolicyEngine


def test_approved_red_request_matches_exact_allow_rule():
    engine = PolicyEngine("policies/rules.json")
    result = engine.decide(" RED ", "RUN_APPROVED_TEST", "test:authorized_access")
    assert (result.decision, result.matched_rule_id) == ("ALLOW", "red-approved-tests")


def test_red_blue_artifact_request_matches_explicit_deny_rule():
    engine = PolicyEngine("policies/rules.json")
    result = engine.decide("red", "read_artifact", "blue:report")
    assert (result.decision, result.matched_rule_id) == ("DENY", "red-deny-blue-artifacts")


def test_deny_takes_precedence_over_matching_allow(tmp_path):
    engine = PolicyEngine("policies/rules.json")
    document = engine.get_rules()
    document["rules"].append({
        "rule_id": "additional-allow",
        "effect": "ALLOW",
        "role": "red",
        "action": "read_artifact",
        "resource_match": {"type": "prefix", "value": "blue:"},
    })
    temporary_rules = tmp_path / "precedence-rules.json"
    temporary_rules.write_text(json.dumps(document), encoding="utf-8")
    result = PolicyEngine(temporary_rules).decide("red", "read_artifact", "blue:report")
    assert (result.decision, result.matched_rule_id) == ("DENY", "red-deny-blue-artifacts")


def test_unknown_valid_action_defaults_to_deny():
    result = PolicyEngine("policies/rules.json").decide("red", "unknown", "test:authorized_access")
    assert result.decision == "DENY"
    assert result.matched_rule_id == "default-deny"


def test_traversal_like_values_cannot_match_allow_rule():
    engine = PolicyEngine("policies/rules.json")
    for resource in ("..", "test:..", "test:authorized_access..", "test:../authorized_access"):
        result = engine.decide("red", "run_approved_test", resource)
        assert result.decision == "DENY"
        assert result.matched_rule_id == "default-deny"


def test_missing_and_invalid_rules_fail_closed(tmp_path):
    missing = PolicyEngine(tmp_path / "missing.json")
    assert missing.decide("red", "run_approved_test", "test:authorized_access").decision == "DENY"

    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("not json", encoding="utf-8")
    invalid = PolicyEngine(invalid_path)
    assert invalid.decide("red", "run_approved_test", "test:authorized_access").decision == "DENY"
