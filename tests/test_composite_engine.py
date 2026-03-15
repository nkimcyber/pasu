"""Tests for app/composite_engine.py — composite rule matching engine.

Core invariants under test:
- A rule fires only when ALL required capabilities are confirmed present.
- Unknown actions (found=False) and not-applicable actions never contribute.
- Optional capabilities appear in the finding when present but are never
  required to trigger it.
- Output is sorted by rule_id regardless of input order.
- Confidence is derived correctly for each of the three confidence_logic
  strategies.
"""

from __future__ import annotations

import pytest

from app.action_classification import ClassificationLookupResult
from app.composite_detections import CompositeRule
from app.composite_engine import CompositeFinding, evaluate_composite_rules
from app.confidence import derive_confidence

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _result(
    action: str,
    capabilities: list[str],
    confidence: str = "high",
    status: str = "classified",
) -> ClassificationLookupResult:
    """Build a confirmed-risky ClassificationLookupResult."""
    return ClassificationLookupResult(
        action=action,
        found=True,
        record={
            "status": status,
            "capabilities": capabilities,
            "confidence": confidence,
            "notes": "",
        },
    )


def _unknown(action: str) -> ClassificationLookupResult:
    """Build an unknown (not-found) ClassificationLookupResult."""
    return ClassificationLookupResult(action=action, found=False, record=None)


def _not_applicable(action: str) -> ClassificationLookupResult:
    """Build a not-applicable ClassificationLookupResult (found but not risky)."""
    return ClassificationLookupResult(
        action=action,
        found=True,
        record={
            "status": "not-applicable",
            "capabilities": [],
            "confidence": "high",
            "notes": "",
        },
    )


def _rule(
    rule_id: str = "COMP-001",
    title: str = "Test Rule",
    required: list[str] | None = None,
    optional: list[str] | None = None,
    severity: str = "high",
    confidence_logic: str = "weakest",
) -> CompositeRule:
    return CompositeRule(
        id=rule_id,
        title=title,
        required_capabilities=tuple(required or ["privilege-delegation"]),
        optional_capabilities=tuple(optional or []),
        severity=severity,
        confidence_logic=confidence_logic,
        rationale="Test rationale.",
    )


# ---------------------------------------------------------------------------
# One-match case (positive)
# ---------------------------------------------------------------------------


class TestRuleFires:
    """Sprint minimum: one positive match test."""

    def test_fires_when_all_required_capabilities_present(self):
        """COMP-001 fires when privilege-delegation and compute-with-role are both confirmed."""
        results = [
            _result("iam:PassRole", ["privilege-delegation"]),
            _result("ec2:RunInstances", ["compute-with-role"]),
        ]
        rule = _rule(
            rule_id="COMP-001",
            required=["privilege-delegation", "compute-with-role"],
        )
        findings = evaluate_composite_rules(results, [rule])
        assert len(findings) == 1
        assert findings[0].rule_id == "COMP-001"

    def test_finding_contains_expected_fields(self):
        results = [_result("iam:PassRole", ["privilege-delegation"])]
        rule = _rule(
            rule_id="COMP-003",
            title="Direct IAM Policy Takeover",
            required=["privilege-delegation"],
            severity="critical",
            confidence_logic="all-high",
        )
        findings = evaluate_composite_rules(results, [rule])
        f = findings[0]
        assert f.rule_id == "COMP-003"
        assert f.title == "Direct IAM Policy Takeover"
        assert f.severity == "critical"
        assert f.matched_required == frozenset({"privilege-delegation"})

    def test_contributing_actions_in_finding(self):
        results = [
            _result("iam:PassRole", ["privilege-delegation"]),
            _result("ec2:RunInstances", ["compute-with-role"]),
        ]
        rule = _rule(required=["privilege-delegation", "compute-with-role"])
        findings = evaluate_composite_rules(results, [rule])
        assert "iam:PassRole" in findings[0].contributing_actions
        assert "ec2:RunInstances" in findings[0].contributing_actions

    def test_contributing_actions_are_sorted(self):
        results = [
            _result("iam:PassRole", ["privilege-delegation"]),
            _result("ec2:RunInstances", ["compute-with-role"]),
        ]
        rule = _rule(required=["privilege-delegation", "compute-with-role"])
        findings = evaluate_composite_rules(results, [rule])
        actions = list(findings[0].contributing_actions)
        assert actions == sorted(actions)


# ---------------------------------------------------------------------------
# Non-match case (negative)
# ---------------------------------------------------------------------------


class TestRuleDoesNotFire:
    """Sprint minimum: one negative non-match test."""

    def test_does_not_fire_when_required_capability_is_missing(self):
        """Rule requires compute-with-role; only privilege-delegation is present."""
        results = [_result("iam:PassRole", ["privilege-delegation"])]
        rule = _rule(required=["privilege-delegation", "compute-with-role"])
        findings = evaluate_composite_rules(results, [rule])
        assert findings == []

    def test_does_not_fire_when_no_capabilities_present(self):
        findings = evaluate_composite_rules([], [_rule()])
        assert findings == []

    def test_does_not_fire_when_only_optional_capability_present(self):
        results = [_result("secretsmanager:GetSecretValue", ["secret-read"])]
        rule = _rule(
            required=["privilege-delegation"],
            optional=["secret-read"],
        )
        findings = evaluate_composite_rules(results, [rule])
        assert findings == []

    def test_empty_rules_list_returns_empty(self):
        results = [_result("iam:PassRole", ["privilege-delegation"])]
        findings = evaluate_composite_rules(results, [])
        assert findings == []


# ---------------------------------------------------------------------------
# Unknown and not-applicable actions are excluded
# ---------------------------------------------------------------------------


class TestUnknownActionsExcluded:
    """Core guard: actions without confirmed classification never contribute."""

    def test_unknown_action_does_not_satisfy_requirement(self):
        """An action absent from the classification file must not trigger a rule."""
        results = [_unknown("svc:UnreviewedAction")]
        rule = _rule(required=["privilege-delegation"])
        # The unknown action cannot provide privilege-delegation.
        findings = evaluate_composite_rules(results, [rule])
        assert findings == []

    def test_not_applicable_action_does_not_satisfy_requirement(self):
        results = [_not_applicable("ec2:DescribeInstances")]
        rule = _rule(required=["compute-with-role"])
        findings = evaluate_composite_rules(results, [rule])
        assert findings == []

    def test_unknown_plus_confirmed_still_fires_correctly(self):
        """Unknown actions alongside confirmed ones do not interfere with a valid match."""
        results = [
            _unknown("svc:Unreviewed"),
            _result("iam:PassRole", ["privilege-delegation"]),
        ]
        rule = _rule(required=["privilege-delegation"])
        findings = evaluate_composite_rules(results, [rule])
        assert len(findings) == 1
        assert "svc:Unreviewed" not in findings[0].contributing_actions
        assert "iam:PassRole" in findings[0].contributing_actions

    def test_all_unknown_returns_no_findings(self):
        results = [_unknown(f"svc:Action{i}") for i in range(5)]
        rules = [_rule(required=["privilege-delegation"])]
        assert evaluate_composite_rules(results, rules) == []

    def test_duplicate_action_keys_counted_once(self):
        """Same action appearing twice must not inflate capability evidence."""
        results = [
            _result("iam:PassRole", ["privilege-delegation"]),
            _result("iam:PassRole", ["privilege-delegation"]),  # duplicate
        ]
        rule = _rule(required=["privilege-delegation", "compute-with-role"])
        findings = evaluate_composite_rules(results, [rule])
        # compute-with-role is still absent, so the rule must not fire.
        assert findings == []


# ---------------------------------------------------------------------------
# Optional capabilities
# ---------------------------------------------------------------------------


class TestOptionalCapabilities:
    def test_rule_fires_without_optional_capability(self):
        results = [_result("iam:PassRole", ["privilege-delegation"])]
        rule = _rule(
            required=["privilege-delegation"],
            optional=["secret-read"],
        )
        findings = evaluate_composite_rules(results, [rule])
        assert len(findings) == 1
        assert findings[0].matched_optional == frozenset()

    def test_optional_capability_appears_in_finding_when_present(self):
        results = [
            _result("iam:PassRole", ["privilege-delegation"]),
            _result("secretsmanager:GetSecretValue", ["secret-read"]),
        ]
        rule = _rule(
            required=["privilege-delegation"],
            optional=["secret-read"],
        )
        findings = evaluate_composite_rules(results, [rule])
        assert findings[0].matched_optional == frozenset({"secret-read"})

    def test_optional_action_included_in_contributing_actions_when_matched(self):
        results = [
            _result("iam:PassRole", ["privilege-delegation"]),
            _result("secretsmanager:GetSecretValue", ["secret-read"]),
        ]
        rule = _rule(
            required=["privilege-delegation"],
            optional=["secret-read"],
        )
        findings = evaluate_composite_rules(results, [rule])
        assert "secretsmanager:GetSecretValue" in findings[0].contributing_actions

    def test_matched_required_is_always_full_required_set(self):
        results = [
            _result("iam:PassRole", ["privilege-delegation"]),
            _result("ec2:RunInstances", ["compute-with-role"]),
        ]
        rule = _rule(required=["privilege-delegation", "compute-with-role"])
        findings = evaluate_composite_rules(results, [rule])
        assert findings[0].matched_required == frozenset(
            {"privilege-delegation", "compute-with-role"}
        )


# ---------------------------------------------------------------------------
# Confidence derivation
# ---------------------------------------------------------------------------


class TestDeriveConfidence:
    # all-high strategy
    def test_all_high_returns_high_when_all_are_high(self):
        assert derive_confidence("all-high", ["high", "high", "high"]).final == "high"

    def test_all_high_downgrades_when_any_medium(self):
        assert derive_confidence("all-high", ["high", "medium", "high"]).final == "medium"

    def test_all_high_downgrades_to_low_when_any_low(self):
        assert derive_confidence("all-high", ["high", "low"]).final == "low"

    def test_all_high_single_high_entry(self):
        assert derive_confidence("all-high", ["high"]).final == "high"

    # weakest strategy
    def test_weakest_returns_low_when_any_low(self):
        assert derive_confidence("weakest", ["high", "high", "low"]).final == "low"

    def test_weakest_returns_medium_when_no_low(self):
        assert derive_confidence("weakest", ["high", "medium"]).final == "medium"

    def test_weakest_returns_high_when_all_high(self):
        assert derive_confidence("weakest", ["high", "high"]).final == "high"

    # majority strategy
    def test_majority_returns_high_when_majority_high(self):
        assert derive_confidence("majority", ["high", "high", "medium"]).final == "high"

    def test_majority_returns_medium_when_not_majority_high(self):
        assert derive_confidence("majority", ["high", "medium", "medium"]).final == "medium"

    def test_majority_tie_is_not_majority(self):
        # Exactly half is NOT a strict majority.
        assert derive_confidence("majority", ["high", "medium"]).final == "medium"

    def test_majority_all_medium_returns_medium(self):
        assert derive_confidence("majority", ["medium", "medium"]).final == "medium"

    # edge: empty list
    def test_empty_list_returns_medium(self):
        assert derive_confidence("weakest", []).final == "medium"


class TestConfidencePropagatedToFinding:
    def test_weakest_confidence_propagated(self):
        results = [
            _result("iam:PassRole", ["privilege-delegation"], confidence="high"),
            _result("ec2:RunInstances", ["compute-with-role"], confidence="low"),
        ]
        rule = _rule(
            required=["privilege-delegation", "compute-with-role"],
            confidence_logic="weakest",
        )
        findings = evaluate_composite_rules(results, [rule])
        assert findings[0].confidence == "low"

    def test_all_high_propagated_when_all_confirmed_high(self):
        results = [
            _result("iam:PassRole", ["privilege-delegation"], confidence="high"),
            _result("ec2:RunInstances", ["compute-with-role"], confidence="high"),
        ]
        rule = _rule(
            required=["privilege-delegation", "compute-with-role"],
            confidence_logic="all-high",
        )
        findings = evaluate_composite_rules(results, [rule])
        assert findings[0].confidence == "high"

    def test_all_high_downgraded_when_one_medium(self):
        results = [
            _result("iam:PassRole", ["privilege-delegation"], confidence="high"),
            _result("ec2:RunInstances", ["compute-with-role"], confidence="medium"),
        ]
        rule = _rule(
            required=["privilege-delegation", "compute-with-role"],
            confidence_logic="all-high",
        )
        findings = evaluate_composite_rules(results, [rule])
        assert findings[0].confidence == "medium"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_output_sorted_by_rule_id(self):
        results = [
            _result("iam:PassRole", ["privilege-delegation"]),
            _result("ec2:RunInstances", ["compute-with-role"]),
            _result("lambda:CreateFunction", ["serverless-with-role"]),
        ]
        rules = [
            _rule("COMP-002", required=["privilege-delegation", "serverless-with-role"]),
            _rule("COMP-001", required=["privilege-delegation", "compute-with-role"]),
        ]
        findings = evaluate_composite_rules(results, rules)
        ids = [f.rule_id for f in findings]
        assert ids == sorted(ids)

    def test_same_inputs_same_output(self):
        results = [
            _result("iam:PassRole", ["privilege-delegation"]),
            _result("ec2:RunInstances", ["compute-with-role"]),
        ]
        rule = _rule(required=["privilege-delegation", "compute-with-role"])
        first = evaluate_composite_rules(results, [rule])
        second = evaluate_composite_rules(results, [rule])
        assert first == second


# ---------------------------------------------------------------------------
# Multiple rules
# ---------------------------------------------------------------------------


class TestMultipleRules:
    def test_multiple_rules_can_fire_simultaneously(self):
        """Capabilities sufficient for two rules should produce two findings."""
        results = [
            _result("iam:PassRole", ["privilege-delegation"]),
            _result("ec2:RunInstances", ["compute-with-role"]),
            _result("lambda:CreateFunction", ["serverless-with-role"]),
        ]
        rules = [
            _rule("COMP-001", required=["privilege-delegation", "compute-with-role"]),
            _rule("COMP-002", required=["privilege-delegation", "serverless-with-role"]),
        ]
        findings = evaluate_composite_rules(results, rules)
        assert len(findings) == 2
        assert {f.rule_id for f in findings} == {"COMP-001", "COMP-002"}

    def test_only_satisfied_rules_appear_in_output(self):
        """A third rule whose requirements are unmet must not appear."""
        results = [
            _result("iam:PassRole", ["privilege-delegation"]),
            _result("ec2:RunInstances", ["compute-with-role"]),
        ]
        rules = [
            _rule("COMP-001", required=["privilege-delegation", "compute-with-role"]),
            _rule("COMP-002", required=["privilege-delegation", "serverless-with-role"]),
        ]
        findings = evaluate_composite_rules(results, rules)
        assert len(findings) == 1
        assert findings[0].rule_id == "COMP-001"

    def test_one_action_contributing_to_multiple_rules(self):
        """iam:PassRole (privilege-delegation) can feed multiple rules at once."""
        results = [
            _result("iam:PassRole", ["privilege-delegation"]),
            _result("ec2:RunInstances", ["compute-with-role"]),
            _result("lambda:CreateFunction", ["serverless-with-role"]),
        ]
        rules = [
            _rule("COMP-001", required=["privilege-delegation", "compute-with-role"]),
            _rule("COMP-002", required=["privilege-delegation", "serverless-with-role"]),
        ]
        findings = evaluate_composite_rules(results, rules)
        for f in findings:
            assert "iam:PassRole" in f.contributing_actions


# ---------------------------------------------------------------------------
# CompositeFinding type contract
# ---------------------------------------------------------------------------


class TestCompositeFindingType:
    def test_finding_is_frozen(self):
        results = [_result("iam:PassRole", ["privilege-delegation"])]
        rule = _rule(required=["privilege-delegation"])
        findings = evaluate_composite_rules(results, [rule])
        f = findings[0]
        with pytest.raises((AttributeError, TypeError)):
            f.severity = "low"  # type: ignore[misc]

    def test_matched_required_is_frozenset(self):
        results = [_result("iam:PassRole", ["privilege-delegation"])]
        rule = _rule(required=["privilege-delegation"])
        findings = evaluate_composite_rules(results, [rule])
        assert isinstance(findings[0].matched_required, frozenset)

    def test_matched_optional_is_frozenset(self):
        results = [_result("iam:PassRole", ["privilege-delegation"])]
        rule = _rule(required=["privilege-delegation"])
        findings = evaluate_composite_rules(results, [rule])
        assert isinstance(findings[0].matched_optional, frozenset)

    def test_contributing_actions_is_tuple(self):
        results = [_result("iam:PassRole", ["privilege-delegation"])]
        rule = _rule(required=["privilege-delegation"])
        findings = evaluate_composite_rules(results, [rule])
        assert isinstance(findings[0].contributing_actions, tuple)


# ---------------------------------------------------------------------------
# Integration: real classification + real rules
# ---------------------------------------------------------------------------


class TestIntegrationWithRealRules:
    """Smoke tests using the actual loaded rules and classification file."""

    def test_no_findings_for_empty_action_set(self):
        from app.composite_detections import load_composite_detections

        rules = load_composite_detections()
        findings = evaluate_composite_rules([], rules)
        assert findings == []

    def test_passrole_alone_does_not_trigger_compute_rule(self):
        """iam:PassRole alone cannot satisfy COMP-001 (needs compute-with-role too)."""
        from app.action_classification import load_action_classification, lookup_action
        from app.composite_detections import load_composite_detections

        classification = load_action_classification()
        rules = load_composite_detections()

        results = [lookup_action("iam:PassRole", classification)]
        findings = evaluate_composite_rules(results, rules)

        comp001_findings = [f for f in findings if f.rule_id == "COMP-001"]
        assert comp001_findings == [], "COMP-001 must not fire on PassRole alone"

    def test_passrole_and_run_instances_trigger_comp001(self):
        """iam:PassRole + ec2:RunInstances together must trigger COMP-001."""
        from app.action_classification import load_action_classification, lookup_action
        from app.composite_detections import load_composite_detections

        classification = load_action_classification()
        rules = load_composite_detections()

        results = [
            lookup_action("iam:PassRole", classification),
            lookup_action("ec2:RunInstances", classification),
        ]
        findings = evaluate_composite_rules(results, rules)

        comp001_findings = [f for f in findings if f.rule_id == "COMP-001"]
        assert len(comp001_findings) == 1
        f = comp001_findings[0]
        assert f.severity == "critical"
        assert "iam:PassRole" in f.contributing_actions
        assert "ec2:RunInstances" in f.contributing_actions

    def test_unknown_action_against_real_rules(self):
        """Fabricated actions must not trigger any real rules."""
        from app.action_classification import load_action_classification, lookup_action
        from app.composite_detections import load_composite_detections

        classification = load_action_classification()
        rules = load_composite_detections()

        results = [lookup_action("svc:FictionalAction", classification)]
        findings = evaluate_composite_rules(results, rules)
        assert findings == []
