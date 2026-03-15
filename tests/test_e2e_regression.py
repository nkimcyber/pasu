"""End-to-end regression tests for the full roadmap pipeline.

Pipeline stages under test
--------------------------
1. Queue generation   — catalog + classification → review queue (unclassified actions only)
2. Classification     — lookup produces reviewed evidence; unknown/not-applicable produce none
3. Composite engine   — only confirmed-risky actions contribute; result sorted by rule_id
4. CLI segmentation   — confirmed vs needs-review sections are stable
5. Fix gating         — only high/medium-confidence classified actions are auto-removed
6. Determinism        — every stage produces identical output on repeated calls

Design principles
-----------------
- Golden corpus fixtures in ``tests/corpus/fixtures/`` are the canonical policy inputs.
- Real classification and composite rule files are used throughout (no mocks, except where
  a stage is deliberately isolated to test a boundary condition).
- Each test class covers one pipeline stage; inter-stage dependence is explicit.
- Assertions are structural (rule IDs, action presence/absence, section headers, change types)
  rather than full-string comparisons so they stay stable as wording evolves.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup — scripts/ is not a package, so add it to sys.path once
# ---------------------------------------------------------------------------

_REPO_ROOT    = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR  = _REPO_ROOT / "scripts"
_CORPUS_DIR   = _REPO_ROOT / "tests" / "corpus" / "fixtures"
_SCHEMA_FILE  = _REPO_ROOT / "app" / "data" / "review_queue.schema.json"

if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from sync_aws_catalog import generate_review_queue  # noqa: E402


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _capture_stdout():
    buf = io.StringIO()
    old, sys.stdout = sys.stdout, buf
    try:
        yield buf
    finally:
        sys.stdout = old


def _fixture(name: str) -> str:
    """Return policy JSON string for a named corpus fixture."""
    return (_CORPUS_DIR / name).read_text(encoding="utf-8")


def _catalog(actions: dict, version: int = 1) -> dict:
    return {
        "version": version,
        "generated_at": "2026-03-14T17:22:09+00:00",
        "source": {"name": "AWS Service Authorization Reference"},
        "actions": actions,
    }


def _action(service: str, name: str, access_level: str = "Write") -> dict:
    return {
        "service": service,
        "name": name,
        "access_level": access_level,
        "resource_types": [],
        "condition_keys": [],
        "dependent_actions": [],
    }


def _lookup_results_from_policy(policy_json: str):
    """Return ClassificationLookupResult list for all Allow actions in a policy."""
    from app.action_classification import load_action_classification, lookup_action
    classification = load_action_classification()
    canonical = {k.lower(): k for k in classification}
    parsed = json.loads(policy_json)
    results = []
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
            key = canonical.get(al, a)
            results.append(lookup_action(key, classification))
    return results


def _composite_findings_from_policy(policy_json: str):
    """Run composite engine against a policy and return findings."""
    from app.composite_detections import load_composite_detections
    from app.composite_engine import evaluate_composite_rules
    results = _lookup_results_from_policy(policy_json)
    rules = load_composite_detections()
    return evaluate_composite_rules(results, rules)


def _fix_output_text(policy_json: str) -> str:
    """Run fix_policy_local and capture the full text output of _print_fix."""
    from app.analyzer import fix_policy_local, calculate_risk_score
    from app.cli import _print_fix
    result = fix_policy_local(policy_json)
    orig  = calculate_risk_score(policy_json)
    fixed = calculate_risk_score(json.dumps(result.fixed_policy))
    with _capture_stdout() as buf:
        _print_fix(result, None, orig, fixed)
    return buf.getvalue()


def _escalate_output_text(policy_json: str) -> str:
    """Run escalate_policy_local and capture the full text output of _print_escalate."""
    from app.analyzer import escalate_policy_local
    from app.cli import _print_escalate
    result = escalate_policy_local(policy_json)
    with _capture_stdout() as buf:
        _print_escalate(result, policy_json=policy_json)
    return buf.getvalue()


# ===========================================================================
# Stage 1 — Queue generation from catalog / classification differences
# ===========================================================================

class TestQueueGenerationPipeline:
    """Verify that generate_review_queue() emits only unclassified actions."""

    def _classified_set(self) -> set[str]:
        """Lowercase action keys present in the real classification file."""
        from app.action_classification import load_action_classification
        return {k.lower() for k in load_action_classification()}

    def test_unclassified_action_appears_in_queue(self):
        catalog = _catalog({"svc:NewAction": _action("svc", "NewAction")})
        result = generate_review_queue(catalog, classified_actions=set())
        keys = [item["action"] for item in result["items"]]
        assert "svc:NewAction" in keys

    def test_classified_action_excluded_from_queue(self):
        """An action already in the classification file must not appear in the queue."""
        catalog = _catalog({"iam:PassRole": _action("iam", "PassRole")})
        classified = self._classified_set()
        result = generate_review_queue(catalog, classified_actions=classified)
        keys = {item["action"] for item in result["items"]}
        assert "iam:PassRole" not in keys

    def test_mixed_catalog_only_unclassified_queued(self):
        catalog = _catalog({
            "iam:PassRole":    _action("iam", "PassRole"),
            "svc:FutureWrite": _action("svc", "FutureWrite"),
        })
        classified = self._classified_set()
        result = generate_review_queue(catalog, classified_actions=classified)
        keys = {item["action"] for item in result["items"]}
        assert "svc:FutureWrite" in keys
        assert "iam:PassRole" not in keys

    def test_catalog_version_propagates_to_queue(self):
        catalog = _catalog({"svc:Act": _action("svc", "Act")}, version=42)
        result = generate_review_queue(catalog, classified_actions=set())
        assert result["source_catalog_version"] == 42

    def test_all_queue_items_default_to_unclassified(self):
        catalog = _catalog({
            "svc:Alpha": _action("svc", "Alpha"),
            "svc:Beta":  _action("svc", "Beta"),
        })
        result = generate_review_queue(catalog, classified_actions=set())
        for item in result["items"]:
            assert item["status"] == "unclassified", (
                f"Expected unclassified, got {item['status']!r} for {item['action']}"
            )

    def test_queue_items_sorted_lexicographically(self):
        catalog = _catalog({
            "zzz:Last":  _action("zzz", "Last"),
            "aaa:First": _action("aaa", "First"),
            "mmm:Mid":   _action("mmm", "Mid"),
        })
        result = generate_review_queue(catalog, classified_actions=set())
        keys = [item["action"] for item in result["items"]]
        assert keys == sorted(keys), f"Queue items not sorted: {keys}"

    def test_queue_validates_against_schema(self):
        import jsonschema
        schema = json.loads(_SCHEMA_FILE.read_text(encoding="utf-8"))
        catalog = _catalog({
            "svc:CreateWidget": _action("svc", "CreateWidget", "Write"),
        })
        result = generate_review_queue(catalog, classified_actions=set())
        jsonschema.validate(instance=result, schema=schema)

    def test_generation_is_deterministic(self):
        catalog = _catalog({
            "iam:CreateUser":   _action("iam", "CreateUser"),
            "ec2:StartSession": _action("ec2", "StartSession"),
            "s3:PutObject":     _action("s3",  "PutObject"),
        })
        r1 = generate_review_queue(catalog, classified_actions=set())
        r2 = generate_review_queue(catalog, classified_actions=set())
        assert r1["items"] == r2["items"]
        assert r1["source_catalog_version"] == r2["source_catalog_version"]

    def test_empty_catalog_produces_empty_items(self):
        result = generate_review_queue(_catalog({}), classified_actions=set())
        assert result["items"] == []

    def test_real_classification_excludes_all_known_actions(self):
        """Every action in the real classification file must be absent from a queue
        built from a catalog that contains only those same actions."""
        from app.action_classification import load_action_classification
        classification = load_action_classification()
        classified = {k.lower() for k in classification}
        # Build a catalog that contains exactly the classified actions
        actions = {
            k: _action(k.split(":")[0], k.split(":")[1])
            for k in classification
        }
        catalog = _catalog(actions)
        result = generate_review_queue(catalog, classified_actions=classified)
        assert result["items"] == [], (
            "All classified actions should be excluded; queue should be empty"
        )


# ===========================================================================
# Stage 2 — Classification lookup produces reviewed evidence
# ===========================================================================

class TestClassificationLookupIntegrity:
    """Verify ClassificationLookupResult carries correct reviewed evidence."""

    def _lookup(self, action_key: str):
        from app.action_classification import load_action_classification, lookup_action
        c = load_action_classification()
        return lookup_action(action_key, c)

    def test_classified_high_confidence_action_is_confirmed_risky(self):
        result = self._lookup("iam:PassRole")
        assert result.is_confirmed_risky is True

    def test_classified_medium_confidence_action_is_confirmed_risky(self):
        """Medium-confidence classified actions are still confirmed risky."""
        result = self._lookup("iam:CreateRole")
        assert result.is_confirmed_risky is True

    def test_not_applicable_action_is_not_confirmed_risky(self):
        result = self._lookup("ec2:DescribeInstances")
        assert result.is_confirmed_risky is False

    def test_unknown_action_is_not_confirmed_risky(self):
        result = self._lookup("svc:UnreviewedAction")
        assert result.is_confirmed_risky is False

    def test_classified_action_has_capabilities(self):
        result = self._lookup("iam:PassRole")
        assert result.capabilities
        assert "privilege-delegation" in result.capabilities

    def test_not_applicable_action_has_empty_capabilities(self):
        result = self._lookup("ec2:DescribeInstances")
        assert result.capabilities == []

    def test_unknown_action_has_empty_capabilities(self):
        result = self._lookup("svc:Nonexistent")
        assert result.capabilities == []

    def test_classified_action_confidence_is_preserved(self):
        result = self._lookup("iam:PassRole")
        assert result.confidence == "high"

    def test_not_applicable_action_found_is_true(self):
        """not-applicable actions ARE in the classification file; found=True."""
        result = self._lookup("ec2:DescribeInstances")
        assert result.found is True

    def test_unknown_action_found_is_false(self):
        result = self._lookup("svc:NeverSeen")
        assert result.found is False

    def test_lookup_result_is_frozen(self):
        result = self._lookup("iam:PassRole")
        with pytest.raises((AttributeError, TypeError)):
            result.found = False  # type: ignore[misc]

    def test_lookup_with_empty_classification_returns_not_found(self):
        from app.action_classification import lookup_action
        result = lookup_action("iam:PassRole", {})
        assert result.found is False
        assert result.is_confirmed_risky is False


# ===========================================================================
# Stage 3 — Composite detection triggers only on reviewed capabilities
# ===========================================================================

class TestCompositeDetectionBoundary:
    """Verify composite engine fires only on confirmed-risky action evidence."""

    def _findings_for_actions(self, action_keys: list[str], classification_override=None):
        """Run composite engine for a specific set of action keys.

        If *classification_override* is provided it replaces the real file,
        allowing boundary testing with controlled confidence values.
        """
        from app.action_classification import load_action_classification, lookup_action
        from app.composite_detections import load_composite_detections
        from app.composite_engine import evaluate_composite_rules

        classification = (
            classification_override
            if classification_override is not None
            else load_action_classification()
        )
        results = [lookup_action(k, classification) for k in action_keys]
        rules = load_composite_detections()
        return evaluate_composite_rules(results, rules)

    def test_comp001_fires_with_both_required_capabilities(self):
        """privilege-delegation + compute-with-role → COMP-001."""
        findings = self._findings_for_actions(["iam:PassRole", "ec2:RunInstances"])
        ids = {f.rule_id for f in findings}
        assert "COMP-001" in ids

    def test_comp001_does_not_fire_with_only_privilege_delegation(self):
        findings = self._findings_for_actions(["iam:PassRole"])
        assert not any(f.rule_id == "COMP-001" for f in findings)

    def test_comp001_does_not_fire_with_only_compute_with_role(self):
        findings = self._findings_for_actions(["ec2:RunInstances"])
        assert not any(f.rule_id == "COMP-001" for f in findings)

    def test_comp002_fires_with_serverless_chain(self):
        findings = self._findings_for_actions(["iam:PassRole", "lambda:CreateFunction"])
        assert any(f.rule_id == "COMP-002" for f in findings)

    def test_comp004_fires_with_credential_issuance_alone(self):
        """COMP-004 requires only credential-issuance (secret-read is optional)."""
        findings = self._findings_for_actions(["iam:CreateAccessKey"])
        assert any(f.rule_id == "COMP-004" for f in findings)

    def test_unknown_action_does_not_contribute_to_composite(self):
        """An unknown action cannot substitute for a required capability."""
        from app.action_classification import load_action_classification, lookup_action
        from app.composite_detections import load_composite_detections
        from app.composite_engine import evaluate_composite_rules

        classification = load_action_classification()
        # Only one real action; the other is unknown
        results = [
            lookup_action("iam:PassRole", classification),     # privilege-delegation
            lookup_action("svc:UnknownCompute", classification),  # unknown → not confirmed
        ]
        rules = load_composite_detections()
        findings = evaluate_composite_rules(results, rules)
        assert not any(f.rule_id == "COMP-001" for f in findings), (
            "Unknown action must not satisfy compute-with-role; COMP-001 must not fire"
        )

    def test_not_applicable_action_does_not_contribute_to_composite(self):
        """not-applicable records have is_confirmed_risky=False → ignored by engine."""
        from app.action_classification import load_action_classification, lookup_action
        from app.composite_detections import load_composite_detections
        from app.composite_engine import evaluate_composite_rules

        classification = load_action_classification()
        # ec2:DescribeInstances is not-applicable → should not contribute
        results = [
            lookup_action("iam:PassRole", classification),
            lookup_action("ec2:DescribeInstances", classification),
        ]
        rules = load_composite_detections()
        findings = evaluate_composite_rules(results, rules)
        assert not any(f.rule_id == "COMP-001" for f in findings), (
            "not-applicable ec2:DescribeInstances must not satisfy compute-with-role"
        )

    def test_composite_results_sorted_by_rule_id(self):
        """Engine always returns findings in ascending COMP-NNN order."""
        findings = self._findings_for_actions([
            "iam:PassRole",
            "ec2:RunInstances",
            "lambda:CreateFunction",
            "iam:AttachRolePolicy",
        ])
        ids = [f.rule_id for f in findings]
        assert ids == sorted(ids)

    def test_composite_run_is_deterministic(self):
        """Same action set → identical findings on repeated calls."""
        actions = ["iam:PassRole", "ec2:RunInstances"]
        r1 = self._findings_for_actions(actions)
        r2 = self._findings_for_actions(actions)
        assert [(f.rule_id, f.confidence, f.contributing_actions) for f in r1] == \
               [(f.rule_id, f.confidence, f.contributing_actions) for f in r2]

    def test_composite_run_stable_under_action_list_reversal(self):
        """Rule firing must not depend on the order actions appear in input."""
        actions = ["iam:PassRole", "ec2:RunInstances"]
        fwd = {f.rule_id for f in self._findings_for_actions(actions)}
        rev = {f.rule_id for f in self._findings_for_actions(list(reversed(actions)))}
        assert fwd == rev

    def test_empty_action_list_produces_no_findings(self):
        findings = self._findings_for_actions([])
        assert findings == []

    def test_contributing_actions_are_sorted_within_finding(self):
        findings = self._findings_for_actions(["ec2:RunInstances", "iam:PassRole"])
        comp001 = next(f for f in findings if f.rule_id == "COMP-001")
        actions = list(comp001.contributing_actions)
        assert actions == sorted(actions)


# ===========================================================================
# Stage 4 — CLI output segmentation stability
# ===========================================================================

class TestCliSegmentationStability:
    """Verify the Confirmed / Needs Review section split remains stable."""

    def test_priv_escalation_ec2_has_confirmed_section(self):
        output = _escalate_output_text(_fixture("priv_escalation_ec2.json"))
        assert "Confirmed Risky Actions" in output

    def test_priv_escalation_ec2_actions_in_confirmed_not_needs_review(self):
        output = _escalate_output_text(_fixture("priv_escalation_ec2.json"))
        lower = output.lower()
        confirmed_pos = lower.find("confirmed risky actions")
        needs_pos = lower.find("needs review")
        # The actions appear before any "Needs Review" section
        passrole_pos = lower.find("iam:passrole")
        ec2_pos = lower.find("ec2:runinstances")
        assert passrole_pos > confirmed_pos
        if needs_pos != -1:
            assert passrole_pos < needs_pos or ec2_pos < needs_pos

    def test_unknown_action_only_has_no_confirmed_section(self):
        output = _escalate_output_text(_fixture("unknown_action_only.json"))
        assert "Confirmed Risky Actions" not in output

    def test_confirmed_section_precedes_needs_review_section(self):
        """When both sections exist, Confirmed must appear before Needs Review."""
        from app.analyzer import escalate_policy_local
        from app.cli import _print_escalate
        # Build a policy with both a high-risk and a medium-risk action
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": [
                "iam:PassRole",       # high-risk → Confirmed
                "iam:CreateAccessKey" # medium-risk → Needs Review
            ], "Resource": "*"}],
        })
        result = escalate_policy_local(policy)
        with _capture_stdout() as buf:
            _print_escalate(result, policy_json=policy)
        output = buf.getvalue().lower()
        confirmed_pos = output.find("confirmed risky actions")
        needs_pos = output.find("needs review")
        if confirmed_pos != -1 and needs_pos != -1:
            assert confirmed_pos < needs_pos

    def test_medium_risk_action_in_needs_review_section(self):
        from app.analyzer import escalate_policy_local
        from app.cli import _print_escalate
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["iam:CreateAccessKey"], "Resource": "*"}],
        })
        result = escalate_policy_local(policy)
        with _capture_stdout() as buf:
            _print_escalate(result, policy_json=policy)
        output = buf.getvalue().lower()
        needs_pos = output.find("needs review")
        assert needs_pos != -1, "Medium-risk action must produce a Needs Review section"

    def test_wildcard_action_in_needs_review_section(self):
        from app.analyzer import escalate_policy_local
        from app.cli import _print_escalate
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}],
        })
        result = escalate_policy_local(policy)
        with _capture_stdout() as buf:
            _print_escalate(result, policy_json=policy)
        output = buf.getvalue().lower()
        assert "needs review" in output
        assert "s3:*" in output

    def test_escalate_output_is_stable_across_two_runs(self):
        policy = _fixture("priv_escalation_ec2.json")
        out1 = _escalate_output_text(policy)
        out2 = _escalate_output_text(policy)
        assert out1 == out2

    def test_mixed_policy_confirmed_section_excludes_unknown(self):
        policy = _fixture("mixed_classified_and_unknown.json")
        output = _escalate_output_text(policy)
        lower = output.lower()
        confirmed_pos = lower.find("confirmed risky actions")
        needs_pos = lower.find("needs review")
        # iam:PassRole must appear in Confirmed Risky section
        passrole_pos = lower.find("iam:passrole")
        assert passrole_pos != -1
        assert confirmed_pos != -1
        assert passrole_pos > confirmed_pos
        if needs_pos != -1:
            # svc:FutureAction is not HIGH_RISK, so it will not appear in confirmed section
            future_action_pos = lower.find("svc:futureaction")
            # It should not be between confirmed_pos and either end-of-confirmed or needs_pos
            if future_action_pos != -1 and needs_pos != -1:
                # future action must not be in the confirmed section
                assert future_action_pos > confirmed_pos + len("confirmed risky actions") or \
                       future_action_pos > needs_pos or \
                       future_action_pos < confirmed_pos

    def test_r003_title_uses_reviewed_vocabulary(self):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(_fixture("priv_escalation_ec2.json"))
        r003 = [f for f in findings if f.rule_id == "R003"]
        for f in r003:
            assert "Reviewed high-risk action" in f.title, (
                f"R003 title vocabulary mismatch: {f.title!r}"
            )

    def test_r004_title_uses_reviewed_vocabulary(self):
        from app.analyzer import analyze_policy_rules
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["iam:CreateAccessKey"], "Resource": "*"}],
        })
        findings = analyze_policy_rules(policy)
        r004 = [f for f in findings if f.rule_id == "R004"]
        for f in r004:
            assert "Reviewed medium-risk action" in f.title, (
                f"R004 title vocabulary mismatch: {f.title!r}"
            )

    def test_escalate_summary_uses_reviewed_vocabulary_for_high(self):
        from app.analyzer import escalate_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": [
                "iam:PassRole", "iam:CreateRole", "iam:AttachRolePolicy",
                "iam:PutRolePolicy", "iam:CreatePolicyVersion",
                "iam:SetDefaultPolicyVersion", "sts:AssumeRole", "iam:AddUserToGroup",
            ], "Resource": "*"}],
        })
        result = escalate_policy_local(policy)
        assert "dangerous" not in result.summary.lower()
        assert "reviewed high-risk" in result.summary


# ===========================================================================
# Stage 5 — Fix gating respects the confidence boundary
# ===========================================================================

class TestFixGatingBoundary:
    """Verify fix_policy_local gates auto-removal on classification + confidence."""

    def test_high_confidence_classified_action_is_auto_removed(self):
        from app.analyzer import fix_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}],
        })
        result = fix_policy_local(policy)
        removed = {c.action.lower() for c in result.changes if c.type == "removed_action"}
        assert "iam:passrole" in removed

    def test_not_applicable_action_kept_and_gate_note_present(self):
        from app.analyzer import fix_policy_local
        # kms:DescribeKey is in HIGH_RISK_ACTIONS but classified as not-applicable
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["kms:DescribeKey"], "Resource": "*"}],
        })
        result = fix_policy_local(policy)
        fixed_actions = result.fixed_policy["Statement"][0].get("Action", [])
        fixed_lower = [a.lower() for a in fixed_actions]
        assert "kms:describekey" in fixed_lower, "not-applicable action must be kept"
        combined = " ".join(result.manual_review_needed).lower()
        assert "not-applicable" in combined

    def test_low_confidence_classified_action_kept_and_gate_note_present(self):
        """An action patched to low confidence must be blocked from auto-removal."""
        from app.analyzer import fix_policy_local
        from unittest.mock import patch
        low_classification = {
            "iam:passrole": {
                "status": "classified",
                "capabilities": ["privilege-delegation"],
                "confidence": "low",
                "notes": "Test low confidence.",
            }
        }
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}],
        })
        with patch("app.analyzer._load_classification_lower", return_value=low_classification):
            result = fix_policy_local(policy)

        fixed_actions = result.fixed_policy["Statement"][0].get("Action", [])
        assert "iam:PassRole" in fixed_actions, "Low-confidence action must remain"
        combined = " ".join(result.manual_review_needed).lower()
        assert "low" in combined

    def test_unknown_action_not_in_high_risk_has_no_gate_note(self):
        """An unknown action that isn't in HIGH_RISK_ACTIONS is left alone silently."""
        from app.analyzer import fix_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["svc:FutureAction"], "Resource": "*"}],
        })
        result = fix_policy_local(policy)
        gate_notes = [n for n in result.manual_review_needed if "auto-fix withheld" in n]
        assert gate_notes == []

    def test_gate_blocking_note_names_the_action(self):
        from app.analyzer import fix_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["kms:DescribeKey"], "Resource": "*"}],
        })
        result = fix_policy_local(policy)
        combined = " ".join(result.manual_review_needed).lower()
        assert "kms:describekey" in combined

    def test_gate_blocking_note_contains_reason(self):
        from app.analyzer import fix_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["kms:DescribeKey"], "Resource": "*"}],
        })
        result = fix_policy_local(policy)
        combined = " ".join(result.manual_review_needed).lower()
        assert "not-applicable" in combined or "auto-fix withheld" in combined

    def test_all_high_confidence_policy_has_no_gate_blocks(self):
        """When all HIGH_RISK actions are classified/high, no gate blocks should appear."""
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_fixture("priv_escalation_ec2.json"))
        gate_notes = [n for n in result.manual_review_needed if "auto-fix withheld" in n]
        assert gate_notes == []

    def test_fix_preserves_non_high_risk_actions(self):
        """Actions outside HIGH_RISK_ACTIONS are never auto-removed."""
        from app.analyzer import fix_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": [
                "iam:PassRole",         # HIGH_RISK — removed
                "iam:CreateAccessKey",  # MEDIUM_RISK — kept
            ], "Resource": "*"}],
        })
        result = fix_policy_local(policy)
        fixed_actions = result.fixed_policy["Statement"][0].get("Action", [])
        fixed_lower = [a.lower() for a in fixed_actions]
        assert "iam:passrole" not in fixed_lower
        assert "iam:createaccesskey" in fixed_lower

    def test_fix_output_text_mentions_context_dependent_for_medium_risk(self):
        """CLI note for retained medium-risk actions must say 'context-dependent'."""
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["iam:CreateAccessKey"], "Resource": "*"}],
        })
        output = _fix_output_text(policy)
        assert "context-dependent" in output.lower()


# ===========================================================================
# Stage 6 — Full pipeline integration using corpus fixtures
# ===========================================================================

class TestFullPipelineRegressions:
    """End-to-end: each corpus fixture is run through all pipeline stages."""

    # ── priv_escalation_ec2 ───────────────────────────────────────────────────

    def test_ec2_escalation_r003_findings_present(self):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(_fixture("priv_escalation_ec2.json"))
        r3_names = {
            f.title.split(": ", 1)[1]
            for f in findings if f.rule_id == "R003"
        }
        assert "iam:passrole" in r3_names
        assert "ec2:runinstances" in r3_names

    def test_ec2_escalation_comp001_fires(self):
        findings = _composite_findings_from_policy(_fixture("priv_escalation_ec2.json"))
        assert any(f.rule_id == "COMP-001" for f in findings)

    def test_ec2_escalation_fix_removes_both(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_fixture("priv_escalation_ec2.json"))
        removed = {c.action.lower() for c in result.changes if c.type == "removed_action"}
        assert "iam:passrole" in removed
        assert "ec2:runinstances" in removed

    def test_ec2_escalation_fix_has_no_gate_blocks(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_fixture("priv_escalation_ec2.json"))
        assert not any("auto-fix withheld" in n for n in result.manual_review_needed)

    # ── unknown_action_only ───────────────────────────────────────────────────

    def test_unknown_action_only_no_r003_or_r004(self):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(_fixture("unknown_action_only.json"))
        assert not any(f.rule_id in ("R003", "R004") for f in findings)

    def test_unknown_action_only_no_composite_findings(self):
        findings = _composite_findings_from_policy(_fixture("unknown_action_only.json"))
        assert findings == []

    def test_unknown_action_only_fix_has_no_removals(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_fixture("unknown_action_only.json"))
        assert not any(c.type == "removed_action" for c in result.changes)

    def test_unknown_action_only_fix_retains_action(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_fixture("unknown_action_only.json"))
        stmts = result.fixed_policy.get("Statement", [])
        all_actions = [
            a.lower()
            for s in stmts
            for a in (s.get("Action", []) if isinstance(s.get("Action"), list) else [s.get("Action", "")])
        ]
        assert "svc:unreviewedaction" in all_actions

    # ── credential_and_secret_read ────────────────────────────────────────────

    def test_cred_secret_comp004_fires(self):
        findings = _composite_findings_from_policy(_fixture("credential_and_secret_read.json"))
        assert any(f.rule_id == "COMP-004" for f in findings)

    def test_cred_secret_fix_retains_both_actions(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_fixture("credential_and_secret_read.json"))
        stmts = result.fixed_policy.get("Statement", [])
        all_actions = {
            a.lower()
            for s in stmts
            for a in (s.get("Action", []) if isinstance(s.get("Action"), list) else [s.get("Action", "")])
        }
        assert "iam:createaccesskey" in all_actions
        assert "secretsmanager:getsecretvalue" in all_actions

    def test_cred_secret_no_removed_action_changes(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_fixture("credential_and_secret_read.json"))
        assert not any(c.type == "removed_action" for c in result.changes)

    # ── not_applicable_gate ───────────────────────────────────────────────────

    def test_not_applicable_r003_fires_from_catalog(self):
        """R003 is based on static HIGH_RISK_ACTIONS — not classification status."""
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(_fixture("not_applicable_gate.json"))
        r3_names = {
            f.title.split(": ", 1)[1]
            for f in findings if f.rule_id == "R003"
        }
        assert "kms:describekey" in r3_names

    def test_not_applicable_composite_is_silent(self):
        """not-applicable is_confirmed_risky=False — no composite evidence."""
        findings = _composite_findings_from_policy(_fixture("not_applicable_gate.json"))
        assert findings == []

    def test_not_applicable_fix_blocked_with_note(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_fixture("not_applicable_gate.json"))
        combined = " ".join(result.manual_review_needed).lower()
        assert "kms:describekey" in combined
        assert "not-applicable" in combined

    # ── data_read_no_composite ────────────────────────────────────────────────

    def test_data_read_no_composite_fires(self):
        """data-read-sensitive only: COMP-009/COMP-010 require additional capabilities."""
        findings = _composite_findings_from_policy(_fixture("data_read_no_composite.json"))
        assert findings == []

    def test_data_read_no_composite_r003_absent(self):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(_fixture("data_read_no_composite.json"))
        assert not any(f.rule_id == "R003" for f in findings)


# ===========================================================================
# Stage 7 — Determinism across all pipeline stages
# ===========================================================================

class TestPipelineDeterminism:
    """Every stage must produce identical output on repeated calls with the same input."""

    _POLICY_EC2 = _fixture.__func__ if hasattr(_fixture, "__func__") else None  # resolved lazily

    def _ec2_policy(self) -> str:
        return _fixture("priv_escalation_ec2.json")

    def _run_composite(self, policy_json: str):
        return [
            (f.rule_id, f.confidence, f.contributing_actions, f.matched_required)
            for f in _composite_findings_from_policy(policy_json)
        ]

    def _run_fix(self, policy_json: str):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(policy_json)
        return {
            "fixed_policy": result.fixed_policy,
            "changes": [(c.type, c.action) for c in result.changes],
            "manual_review": result.manual_review_needed,
        }

    def test_queue_generation_deterministic_three_runs(self):
        catalog = _catalog({
            "iam:CreateUser": _action("iam", "CreateUser"),
            "ec2:StartSession": _action("ec2", "StartSession"),
        })
        results = [
            generate_review_queue(catalog, classified_actions=set())["items"]
            for _ in range(3)
        ]
        assert results[0] == results[1] == results[2]

    def test_composite_detection_deterministic_three_runs(self):
        policy = self._ec2_policy()
        r1 = self._run_composite(policy)
        r2 = self._run_composite(policy)
        r3 = self._run_composite(policy)
        assert r1 == r2 == r3

    def test_fix_policy_deterministic_three_runs(self):
        policy = self._ec2_policy()
        r1 = self._run_fix(policy)
        r2 = self._run_fix(policy)
        r3 = self._run_fix(policy)
        assert r1 == r2 == r3

    def test_escalate_cli_output_deterministic_three_runs(self):
        policy = self._ec2_policy()
        outputs = [_escalate_output_text(policy) for _ in range(3)]
        assert outputs[0] == outputs[1] == outputs[2]

    def test_fix_cli_output_deterministic_three_runs(self):
        policy = self._ec2_policy()
        outputs = [_fix_output_text(policy) for _ in range(3)]
        assert outputs[0] == outputs[1] == outputs[2]

    def test_corpus_fixtures_all_deterministic(self):
        """All eight corpus fixtures produce identical outputs on two runs."""
        fixture_names = [
            "priv_escalation_ec2.json",
            "priv_escalation_lambda.json",
            "policy_modification.json",
            "credential_and_secret_read.json",
            "unknown_action_only.json",
            "data_read_no_composite.json",
            "mixed_classified_and_unknown.json",
            "not_applicable_gate.json",
        ]
        for name in fixture_names:
            policy = _fixture(name)
            r1 = self._run_composite(policy)
            r2 = self._run_composite(policy)
            assert r1 == r2, f"Non-deterministic composite output for {name}"

    def test_classification_lookup_deterministic_for_all_known_actions(self):
        """lookup_action on the real file returns identical results on every call."""
        from app.action_classification import load_action_classification, lookup_action
        classification = load_action_classification()
        for action_key in list(classification.keys())[:10]:
            r1 = lookup_action(action_key, classification)
            r2 = lookup_action(action_key, classification)
            assert (r1.found, r1.is_confirmed_risky, r1.capabilities, r1.confidence) == \
                   (r2.found, r2.is_confirmed_risky, r2.capabilities, r2.confidence), \
                   f"Non-deterministic lookup for {action_key}"

    def test_composite_stable_under_input_permutation(self):
        """Rule firing must not depend on which order actions are fed to the engine."""
        from app.action_classification import load_action_classification, lookup_action
        from app.composite_detections import load_composite_detections
        from app.composite_engine import evaluate_composite_rules

        classification = load_action_classification()
        rules = load_composite_detections()
        action_keys = ["iam:PassRole", "ec2:RunInstances", "lambda:CreateFunction"]

        for i in range(len(action_keys)):
            rotated = action_keys[i:] + action_keys[:i]
            results = [lookup_action(k, classification) for k in rotated]
            ids = {f.rule_id for f in evaluate_composite_rules(results, rules)}
            assert "COMP-001" in ids, (
                f"COMP-001 not in findings for rotation {rotated}"
            )
