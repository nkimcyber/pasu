"""Golden corpus regression tests.

Each test class corresponds to one policy fixture in ``tests/corpus/fixtures/``.
The corpus covers eight representative scenarios:

  1. priv_escalation_ec2          — classified/high chain → COMP-001 fires, both removed by fix
  2. priv_escalation_lambda       — classified/high chain → COMP-002 fires, both removed by fix
  3. policy_modification          — classified/high policy-mod → COMP-003 fires, both removed by fix
  4. credential_and_secret_read   — medium-risk set only → COMP-004 fires, fix retains both (not in HIGH_RISK)
  5. unknown_action_only          — no evidence layer matches → no findings, fix untouched
  6. data_read_no_composite       — data-read-sensitive only → no composite fires (missing required caps)
  7. mixed_classified_and_unknown — one classified/high + one unknown → only classified action removed
  8. not_applicable_gate          — HIGH_RISK catalog match + not-applicable classification → R003 fires,
                                    fix gate blocks removal

Design principles
-----------------
- Tests load fixtures from disk so policy content is authoritative and version-controlled.
- Expected values are anchored against the *current* reviewed classification file; if the
  classification file changes, these tests act as a signal that output semantics shifted.
- Assertions are intentionally structural (rule IDs, action presence/absence, composite rule IDs)
  rather than full-string matches, to stay stable as wording evolves.
"""

from __future__ import annotations

import json
import pathlib

import pytest

# ---------------------------------------------------------------------------
# Corpus helpers
# ---------------------------------------------------------------------------

_CORPUS_DIR = pathlib.Path(__file__).parent / "corpus"
_FIXTURES_DIR = _CORPUS_DIR / "fixtures"


def _load_fixture(name: str) -> str:
    """Return the raw policy JSON string for a named fixture file."""
    return (_FIXTURES_DIR / name).read_text(encoding="utf-8")


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def _r003_action_names(findings) -> set[str]:
    return {
        f.title.split(": ", 1)[1]
        for f in findings
        if f.rule_id == "R003"
    }


def _r004_action_names(findings) -> set[str]:
    return {
        f.title.split(": ", 1)[1]
        for f in findings
        if f.rule_id == "R004"
    }


def _composite_rule_ids(policy_json: str) -> set[str]:
    from app.action_classification import load_action_classification, lookup_action
    from app.composite_detections import load_composite_detections
    from app.composite_engine import evaluate_composite_rules

    classification = load_action_classification()
    parsed = json.loads(policy_json)
    action_results = []
    seen: set[str] = set()
    for stmt in parsed.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for a in actions:
            al = a.lower()
            if al in seen:
                continue
            seen.add(al)
            # Use the original casing from classification where available
            canonical = {k.lower(): k for k in classification}
            key = canonical.get(al, a)
            action_results.append(lookup_action(key, classification))

    rules = load_composite_detections()
    findings = evaluate_composite_rules(action_results, rules)
    return {f.rule_id for f in findings}


def _fixed_remaining_actions(fix_result) -> list[str]:
    """Return the Action list from the first statement of the fixed policy."""
    stmts = fix_result.fixed_policy.get("Statement", [])
    if not stmts:
        return []
    actions = stmts[0].get("Action", [])
    return actions if isinstance(actions, list) else [actions]


# ---------------------------------------------------------------------------
# 1. Privilege escalation via EC2
# ---------------------------------------------------------------------------

class TestPrivEscalationEc2:
    """Fixture: priv_escalation_ec2.json — iam:PassRole + ec2:RunInstances"""

    @pytest.fixture(scope="class")
    def policy(self):
        return _load_fixture("priv_escalation_ec2.json")

    def test_r003_fires_for_both_actions(self, policy):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(policy)
        names = _r003_action_names(findings)
        assert "iam:passrole" in names
        assert "ec2:runinstances" in names

    def test_no_r004_findings(self, policy):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(policy)
        assert not any(f.rule_id == "R004" for f in findings)

    def test_comp001_fires(self, policy):
        assert "COMP-001" in _composite_rule_ids(policy)

    def test_no_other_composite_rules_fire(self, policy):
        fired = _composite_rule_ids(policy)
        assert fired == {"COMP-001"}, f"Unexpected composite rules: {fired - {'COMP-001'}}"

    def test_fix_removes_both_actions(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        removed = {c.action.lower() for c in result.changes if c.type == "removed_action"}
        assert "iam:passrole" in removed
        assert "ec2:runinstances" in removed

    def test_fix_has_no_gate_blocks(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        gate_blocks = [n for n in result.manual_review_needed if "auto-fix withheld" in n]
        assert gate_blocks == []


# ---------------------------------------------------------------------------
# 2. Privilege escalation via Lambda
# ---------------------------------------------------------------------------

class TestPrivEscalationLambda:
    """Fixture: priv_escalation_lambda.json — iam:PassRole + lambda:CreateFunction"""

    @pytest.fixture(scope="class")
    def policy(self):
        return _load_fixture("priv_escalation_lambda.json")

    def test_r003_fires_for_both_actions(self, policy):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(policy)
        names = _r003_action_names(findings)
        assert "iam:passrole" in names
        assert "lambda:createfunction" in names

    def test_comp002_fires(self, policy):
        assert "COMP-002" in _composite_rule_ids(policy)

    def test_comp001_does_not_fire(self, policy):
        assert "COMP-001" not in _composite_rule_ids(policy)

    def test_fix_removes_both_actions(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        removed = {c.action.lower() for c in result.changes if c.type == "removed_action"}
        assert "iam:passrole" in removed
        assert "lambda:createfunction" in removed


# ---------------------------------------------------------------------------
# 3. Direct IAM policy modification / takeover
# ---------------------------------------------------------------------------

class TestPolicyModification:
    """Fixture: policy_modification.json — iam:AttachRolePolicy + iam:CreatePolicyVersion"""

    @pytest.fixture(scope="class")
    def policy(self):
        return _load_fixture("policy_modification.json")

    def test_r003_fires_for_both_actions(self, policy):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(policy)
        names = _r003_action_names(findings)
        assert "iam:attachrolepolicy" in names
        assert "iam:createpolicyversion" in names

    def test_comp003_fires(self, policy):
        assert "COMP-003" in _composite_rule_ids(policy)

    def test_fix_removes_both_actions(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        removed = {c.action.lower() for c in result.changes if c.type == "removed_action"}
        assert "iam:attachrolepolicy" in removed
        assert "iam:createpolicyversion" in removed


# ---------------------------------------------------------------------------
# 4. Credential issuance + secret read (composite fires; fix retains both)
# ---------------------------------------------------------------------------

class TestCredentialAndSecretRead:
    """Fixture: credential_and_secret_read.json — iam:CreateAccessKey + secretsmanager:GetSecretValue

    Key property: both actions are in MEDIUM_RISK_ACTIONS (not HIGH_RISK_ACTIONS), so the
    fix engine does not auto-remove them — yet COMP-004 fires, demonstrating that composite
    detection surfaces risk that individual R004 findings cannot represent.
    """

    @pytest.fixture(scope="class")
    def policy(self):
        return _load_fixture("credential_and_secret_read.json")

    def test_no_r003_findings(self, policy):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(policy)
        assert not any(f.rule_id == "R003" for f in findings)

    def test_r004_fires_for_both_actions(self, policy):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(policy)
        names = _r004_action_names(findings)
        assert "iam:createaccesskey" in names
        assert "secretsmanager:getsecretvalue" in names

    def test_comp004_fires(self, policy):
        assert "COMP-004" in _composite_rule_ids(policy)

    def test_fix_does_not_remove_either_action(self, policy):
        """Neither action is in HIGH_RISK_ACTIONS — fix engine never attempts removal."""
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        removed = {c.action.lower() for c in result.changes if c.type == "removed_action"}
        assert "iam:createaccesskey" not in removed
        assert "secretsmanager:getsecretvalue" not in removed

    def test_actions_remain_in_fixed_policy(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        remaining = [a.lower() for a in _fixed_remaining_actions(result)]
        assert "iam:createaccesskey" in remaining
        assert "secretsmanager:getsecretvalue" in remaining

    def test_no_gate_block_notes(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        gate_notes = [n for n in result.manual_review_needed if "auto-fix withheld" in n]
        assert gate_notes == []


# ---------------------------------------------------------------------------
# 5. Unknown action only — no evidence layer matches
# ---------------------------------------------------------------------------

class TestUnknownActionOnly:
    """Fixture: unknown_action_only.json — svc:UnreviewedAction

    Proves the system does not over-classify actions absent from every evidence layer.
    """

    @pytest.fixture(scope="class")
    def policy(self):
        return _load_fixture("unknown_action_only.json")

    def test_no_r003_findings(self, policy):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(policy)
        assert not any(f.rule_id == "R003" for f in findings)

    def test_no_r004_findings(self, policy):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(policy)
        assert not any(f.rule_id == "R004" for f in findings)

    def test_no_composite_findings(self, policy):
        assert _composite_rule_ids(policy) == set()

    def test_fix_retains_unknown_action(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        remaining = [a.lower() for a in _fixed_remaining_actions(result)]
        assert "svc:unreviewedaction" in remaining

    def test_fix_has_no_removal_changes(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        removed = [c for c in result.changes if c.type == "removed_action"]
        assert removed == []

    def test_fix_has_no_gate_block_note(self, policy):
        """Unknown action is not in HIGH_RISK_ACTIONS — gate is never evaluated."""
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        gate_notes = [n for n in result.manual_review_needed if "auto-fix withheld" in n]
        assert gate_notes == []


# ---------------------------------------------------------------------------
# 6. Data-read-only — composite does not fire
# ---------------------------------------------------------------------------

class TestDataReadNoComposite:
    """Fixture: data_read_no_composite.json — rds:CopyDBSnapshot + dynamodb:Scan

    Both actions have only data-read-sensitive capability. No composite rule requires
    data-read-sensitive alone — COMP-009 also needs secret-read; COMP-010 needs
    data-write-sensitive. Verifies composite engine does not fire on partial evidence.
    """

    @pytest.fixture(scope="class")
    def policy(self):
        return _load_fixture("data_read_no_composite.json")

    def test_no_composite_findings(self, policy):
        assert _composite_rule_ids(policy) == set()

    def test_no_r003_findings(self, policy):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(policy)
        assert not any(f.rule_id == "R003" for f in findings)

    def test_at_least_one_r004_finding(self, policy):
        """rds:CopyDBSnapshot is in MEDIUM_RISK_ACTIONS so R004 must fire."""
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R004" for f in findings)

    def test_fix_retains_both_actions(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        remaining = {a.lower() for a in _fixed_remaining_actions(result)}
        assert "rds:copydbsnapshot" in remaining
        assert "dynamodb:scan" in remaining


# ---------------------------------------------------------------------------
# 7. Mixed: one classified/high + one unknown
# ---------------------------------------------------------------------------

class TestMixedClassifiedAndUnknown:
    """Fixture: mixed_classified_and_unknown.json — iam:PassRole + svc:FutureAction

    Verifies that fix correctly targets only the classified action (iam:PassRole) while
    leaving the unknown action (svc:FutureAction) untouched, with no spurious gate notes.
    """

    @pytest.fixture(scope="class")
    def policy(self):
        return _load_fixture("mixed_classified_and_unknown.json")

    def test_r003_fires_only_for_passrole(self, policy):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(policy)
        names = _r003_action_names(findings)
        assert "iam:passrole" in names
        # Unknown action must not produce an R003 finding
        assert not any("futureaction" in n.lower() for n in names)

    def test_no_composite_findings(self, policy):
        """privilege-delegation alone does not satisfy any composite rule."""
        assert _composite_rule_ids(policy) == set()

    def test_fix_removes_passrole(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        removed = {c.action.lower() for c in result.changes if c.type == "removed_action"}
        assert "iam:passrole" in removed

    def test_fix_retains_unknown_action(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        remaining = [a.lower() for a in _fixed_remaining_actions(result)]
        assert "svc:futureaction" in remaining

    def test_no_gate_block_for_unknown_action(self, policy):
        """Unknown non-HIGH_RISK action must not produce a gate-block note."""
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        gate_notes = [n for n in result.manual_review_needed if "auto-fix withheld" in n]
        assert gate_notes == []


# ---------------------------------------------------------------------------
# 8. Not-applicable gate: HIGH_RISK catalog match overridden by classification
# ---------------------------------------------------------------------------

class TestNotApplicableGate:
    """Fixture: not_applicable_gate.json — kms:DescribeKey

    kms:DescribeKey is in the static HIGH_RISK_ACTIONS set, so R003 fires.
    However, the reviewed classification marks it not-applicable, meaning the
    fix gate must block removal and explain why.

    This is the canonical example of catalog evidence diverging from reviewed judgment.
    """

    @pytest.fixture(scope="class")
    def policy(self):
        return _load_fixture("not_applicable_gate.json")

    def test_r003_fires_from_catalog_match(self, policy):
        """Rule engine uses static HIGH_RISK_ACTIONS set — classification is not consulted."""
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(policy)
        names = _r003_action_names(findings)
        assert "kms:describekey" in names

    def test_no_composite_findings(self, policy):
        """not-applicable classification → is_confirmed_risky=False → no capabilities contributed."""
        assert _composite_rule_ids(policy) == set()

    def test_fix_does_not_remove_action(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        removed = {c.action.lower() for c in result.changes if c.type == "removed_action"}
        assert "kms:describekey" not in removed

    def test_action_retained_in_fixed_policy(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        remaining = [a.lower() for a in _fixed_remaining_actions(result)]
        assert "kms:describekey" in remaining

    def test_gate_block_note_mentions_not_applicable(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        combined = " ".join(result.manual_review_needed).lower()
        assert "not-applicable" in combined, (
            f"Expected 'not-applicable' in manual_review_needed; got: {result.manual_review_needed}"
        )

    def test_gate_block_note_mentions_action(self, policy):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy)
        combined = " ".join(result.manual_review_needed).lower()
        assert "kms:describekey" in combined
