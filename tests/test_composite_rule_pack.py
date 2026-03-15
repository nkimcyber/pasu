"""Validation tests for the composite detection rule pack.

Covers the four new rules (COMP-007 through COMP-010) added in the first
reviewed rule pack, plus cross-pack invariants that must hold across the
full set of 10 rules.

These tests are intentionally review-oriented: they document *why* each
rule is structured the way it is, not just *that* it loads.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.composite_detections import load_composite_detections, validate_rule
from app.composite_engine import evaluate_composite_rules
from app.action_classification import ClassificationLookupResult

_YAML_PATH = Path(__file__).resolve().parent.parent / "app" / "rules" / "composite_detections.yaml"

# All IDs that must be present after the first reviewed pack.
_PACK_IDS = {
    "COMP-001", "COMP-002", "COMP-003", "COMP-004", "COMP-005",
    "COMP-006", "COMP-007", "COMP-008", "COMP-009", "COMP-010",
}

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _confirmed(action: str, capabilities: list[str], confidence: str = "high") -> ClassificationLookupResult:
    return ClassificationLookupResult(
        action=action,
        found=True,
        record={
            "status": "classified",
            "capabilities": capabilities,
            "confidence": confidence,
            "notes": "",
        },
    )


def _rules_by_id() -> dict:
    rules = load_composite_detections()
    return {r.id: r for r in rules}


# ---------------------------------------------------------------------------
# Pack completeness
# ---------------------------------------------------------------------------

class TestPackCompleteness:
    def test_all_ten_rule_ids_present(self):
        loaded = {r.id for r in load_composite_detections()}
        missing = _PACK_IDS - loaded
        assert not missing, f"Rule pack is missing IDs: {sorted(missing)}"

    def test_pack_contains_exactly_ten_rules(self):
        assert len(load_composite_detections()) == 10

    def test_all_rules_pass_validate_rule(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        for rule in data["rules"]:
            validate_rule(rule)  # must not raise

    def test_all_rule_ids_are_unique(self):
        ids = [r.id for r in load_composite_detections()]
        assert len(ids) == len(set(ids))

    def test_rules_sorted_by_id(self):
        ids = [r.id for r in load_composite_detections()]
        assert ids == sorted(ids)


# ---------------------------------------------------------------------------
# COMP-007: Persistent Backdoor via Policy Rewrite and Credential Establishment
# ---------------------------------------------------------------------------

class TestComp007:
    def test_rule_exists(self):
        assert "COMP-007" in _rules_by_id()

    def test_required_capabilities(self):
        rule = _rules_by_id()["COMP-007"]
        assert set(rule.required_capabilities) == {"policy-modification", "credential-issuance"}

    def test_optional_includes_privilege_delegation(self):
        rule = _rules_by_id()["COMP-007"]
        assert "privilege-delegation" in rule.optional_capabilities

    def test_severity_is_critical(self):
        assert _rules_by_id()["COMP-007"].severity == "critical"

    def test_confidence_logic_is_all_high(self):
        assert _rules_by_id()["COMP-007"].confidence_logic == "all-high"

    def test_fires_on_policy_modification_and_credential_issuance(self):
        results = [
            _confirmed("iam:PutUserPolicy", ["policy-modification"]),
            _confirmed("iam:CreateAccessKey", ["credential-issuance"]),
        ]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-007"]
        assert len(findings) == 1

    def test_does_not_fire_on_policy_modification_alone(self):
        """Policy modification alone fires COMP-003 but not COMP-007."""
        results = [_confirmed("iam:PutUserPolicy", ["policy-modification"])]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-007"]
        assert findings == []

    def test_does_not_fire_on_credential_issuance_alone(self):
        """Credential issuance alone fires COMP-004 but not COMP-007."""
        results = [_confirmed("iam:CreateAccessKey", ["credential-issuance"])]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-007"]
        assert findings == []

    def test_confidence_downgraded_when_one_action_is_medium(self):
        """all-high logic: one medium input lowers overall confidence."""
        results = [
            _confirmed("iam:PutUserPolicy", ["policy-modification"], confidence="high"),
            _confirmed("iam:CreateAccessKey", ["credential-issuance"], confidence="medium"),
        ]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-007"]
        assert findings[0].confidence == "medium"

    def test_confidence_is_high_when_both_high(self):
        results = [
            _confirmed("iam:PutUserPolicy", ["policy-modification"], confidence="high"),
            _confirmed("iam:CreateAccessKey", ["credential-issuance"], confidence="high"),
        ]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-007"]
        assert findings[0].confidence == "high"

    def test_rationale_is_non_empty(self):
        assert _rules_by_id()["COMP-007"].rationale.strip()

    def test_no_capability_overlap_between_required_and_optional(self):
        rule = _rules_by_id()["COMP-007"]
        overlap = set(rule.required_capabilities) & set(rule.optional_capabilities)
        assert not overlap


# ---------------------------------------------------------------------------
# COMP-008: Shadow Admin via External Trust and Policy Grant
# ---------------------------------------------------------------------------

class TestComp008:
    def test_rule_exists(self):
        assert "COMP-008" in _rules_by_id()

    def test_required_capabilities(self):
        rule = _rules_by_id()["COMP-008"]
        assert set(rule.required_capabilities) == {"cross-account-trust", "policy-modification"}

    def test_optional_includes_privilege_delegation(self):
        rule = _rules_by_id()["COMP-008"]
        assert "privilege-delegation" in rule.optional_capabilities

    def test_severity_is_critical(self):
        assert _rules_by_id()["COMP-008"].severity == "critical"

    def test_confidence_logic_is_all_high(self):
        assert _rules_by_id()["COMP-008"].confidence_logic == "all-high"

    def test_fires_on_cross_account_trust_and_policy_modification(self):
        results = [
            _confirmed("iam:UpdateAssumeRolePolicy", ["cross-account-trust"]),
            _confirmed("iam:AttachRolePolicy", ["policy-modification"]),
        ]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-008"]
        assert len(findings) == 1

    def test_does_not_fire_on_cross_account_trust_alone(self):
        """cross-account-trust alone fires COMP-005 (when data-read-sensitive present), not COMP-008."""
        results = [_confirmed("iam:UpdateAssumeRolePolicy", ["cross-account-trust"])]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-008"]
        assert findings == []

    def test_distinct_from_comp005(self):
        """COMP-008 requires policy-modification; COMP-005 requires data-read-sensitive."""
        rule_005 = _rules_by_id()["COMP-005"]
        rule_008 = _rules_by_id()["COMP-008"]
        assert "policy-modification" not in rule_005.required_capabilities
        assert "data-read-sensitive" not in rule_008.required_capabilities

    def test_no_capability_overlap_between_required_and_optional(self):
        rule = _rules_by_id()["COMP-008"]
        overlap = set(rule.required_capabilities) & set(rule.optional_capabilities)
        assert not overlap


# ---------------------------------------------------------------------------
# COMP-009: Coordinated Intelligence Harvest
# ---------------------------------------------------------------------------

class TestComp009:
    def test_rule_exists(self):
        assert "COMP-009" in _rules_by_id()

    def test_required_capabilities(self):
        rule = _rules_by_id()["COMP-009"]
        assert set(rule.required_capabilities) == {"secret-read", "data-read-sensitive"}

    def test_no_optional_capabilities(self):
        rule = _rules_by_id()["COMP-009"]
        assert rule.optional_capabilities == ()

    def test_severity_is_high(self):
        assert _rules_by_id()["COMP-009"].severity == "high"

    def test_confidence_logic_is_weakest(self):
        assert _rules_by_id()["COMP-009"].confidence_logic == "weakest"

    def test_fires_on_secret_read_and_data_read(self):
        results = [
            _confirmed("secretsmanager:GetSecretValue", ["secret-read"]),
            _confirmed("s3:GetObject", ["data-read-sensitive"]),
        ]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-009"]
        assert len(findings) == 1

    def test_does_not_fire_on_secret_read_alone(self):
        results = [_confirmed("secretsmanager:GetSecretValue", ["secret-read"])]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-009"]
        assert findings == []

    def test_does_not_fire_on_data_read_alone(self):
        results = [_confirmed("s3:GetObject", ["data-read-sensitive"])]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-009"]
        assert findings == []

    def test_weakest_confidence_follows_lowest_input(self):
        results = [
            _confirmed("secretsmanager:GetSecretValue", ["secret-read"], confidence="high"),
            _confirmed("s3:GetObject", ["data-read-sensitive"], confidence="low"),
        ]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-009"]
        assert findings[0].confidence == "low"


# ---------------------------------------------------------------------------
# COMP-010: Ransomware and Double-Extortion Positioning
# ---------------------------------------------------------------------------

class TestComp010:
    def test_rule_exists(self):
        assert "COMP-010" in _rules_by_id()

    def test_required_capabilities(self):
        rule = _rules_by_id()["COMP-010"]
        assert set(rule.required_capabilities) == {"data-read-sensitive", "data-write-sensitive"}

    def test_optional_includes_public_exposure(self):
        rule = _rules_by_id()["COMP-010"]
        assert "public-exposure" in rule.optional_capabilities

    def test_severity_is_high(self):
        assert _rules_by_id()["COMP-010"].severity == "high"

    def test_confidence_logic_is_weakest(self):
        assert _rules_by_id()["COMP-010"].confidence_logic == "weakest"

    def test_fires_on_data_read_and_data_write(self):
        results = [
            _confirmed("s3:GetObject", ["data-read-sensitive"]),
            _confirmed("s3:PutObject", ["data-write-sensitive"]),
        ]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-010"]
        assert len(findings) == 1

    def test_optional_public_exposure_reflected_when_present(self):
        results = [
            _confirmed("s3:GetObject", ["data-read-sensitive"]),
            _confirmed("s3:PutObject", ["data-write-sensitive"]),
            _confirmed("s3:PutBucketAcl", ["public-exposure"]),
        ]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-010"]
        assert "public-exposure" in findings[0].matched_optional

    def test_does_not_fire_on_data_write_alone(self):
        results = [_confirmed("s3:PutObject", ["data-write-sensitive"])]
        rules = load_composite_detections()
        findings = [f for f in evaluate_composite_rules(results, rules) if f.rule_id == "COMP-010"]
        assert findings == []

    def test_no_capability_overlap_between_required_and_optional(self):
        rule = _rules_by_id()["COMP-010"]
        overlap = set(rule.required_capabilities) & set(rule.optional_capabilities)
        assert not overlap


# ---------------------------------------------------------------------------
# Cross-pack invariants
# ---------------------------------------------------------------------------

class TestCrossPackInvariants:
    """Invariants that must hold across the entire 10-rule pack."""

    def test_all_rules_have_non_empty_rationale(self):
        for rule in load_composite_detections():
            assert rule.rationale.strip(), f"{rule.id} has an empty rationale"

    def test_all_rules_have_at_least_one_required_capability(self):
        for rule in load_composite_detections():
            assert len(rule.required_capabilities) >= 1, (
                f"{rule.id} has no required capabilities"
            )

    def test_no_rule_has_capability_in_both_lists(self):
        for rule in load_composite_detections():
            overlap = set(rule.required_capabilities) & set(rule.optional_capabilities)
            assert not overlap, f"{rule.id} has overlap: {overlap}"

    def test_all_severity_values_are_valid(self):
        from app.composite_detections import SEVERITY_LEVELS
        for rule in load_composite_detections():
            assert rule.severity in SEVERITY_LEVELS, (
                f"{rule.id} has invalid severity {rule.severity!r}"
            )

    def test_all_confidence_logic_values_are_valid(self):
        from app.composite_detections import CONFIDENCE_LOGIC_VALUES
        for rule in load_composite_detections():
            assert rule.confidence_logic in CONFIDENCE_LOGIC_VALUES, (
                f"{rule.id} has invalid confidence_logic {rule.confidence_logic!r}"
            )

    def test_all_capability_names_are_in_vocabulary(self):
        from app.capabilities import CAPABILITY_NAMES
        for rule in load_composite_detections():
            for cap in rule.required_capabilities + rule.optional_capabilities:
                assert cap in CAPABILITY_NAMES, (
                    f"{rule.id} references unknown capability {cap!r}"
                )

    def test_critical_rules_use_all_high_or_weakest_confidence_logic(self):
        """Critical rules should not use majority logic — evidence must be precise."""
        for rule in load_composite_detections():
            if rule.severity == "critical":
                assert rule.confidence_logic in {"all-high", "weakest"}, (
                    f"Critical rule {rule.id} uses {rule.confidence_logic!r}; "
                    f"expected 'all-high' or 'weakest'"
                )

    def test_no_duplicate_required_capability_sets(self):
        """No two rules should share the exact same required capability set."""
        seen: dict[frozenset, str] = {}
        for rule in load_composite_detections():
            key = frozenset(rule.required_capabilities)
            assert key not in seen, (
                f"{rule.id} and {seen[key]} share identical required capabilities: {sorted(key)}"
            )
            seen[key] = rule.id

    def test_pack_covers_all_ten_capability_dimensions(self):
        """Every capability in the vocabulary must appear in at least one rule."""
        from app.capabilities import CAPABILITY_NAMES
        covered: set[str] = set()
        for rule in load_composite_detections():
            covered.update(rule.required_capabilities)
            covered.update(rule.optional_capabilities)
        uncovered = CAPABILITY_NAMES - covered
        assert not uncovered, (
            f"Capabilities not referenced by any rule: {sorted(uncovered)}"
        )
