"""Integration tests: composite detection wired into the normal scan path.

These tests verify the end-to-end behaviour from policy JSON → escalate_policy_local()
→ CLI text/JSON output — including:

1. COMP-001 fires for iam:PassRole + ec2:RunInstances (complete chain).
2. COMP-001 does NOT fire for iam:PassRole alone (missing compute-with-role).
3. COMP-001 does NOT fire for ec2:RunInstances alone (missing privilege-delegation).
4. COMP-004 fires for iam:CreateAccessKey + secretsmanager:GetSecretValue.
5. COMP-003 fires for a policy-modification action alone (single-capability rule).
6. Composite findings are present in the JSON escalate output.
7. CLI text output contains an "High-Risk Permission Patterns" section with required fields.
8. Summary line mentions composite finding count.
"""

from __future__ import annotations

import io
import json
import sys

import pytest


# ---------------------------------------------------------------------------
# Policy fixtures
# ---------------------------------------------------------------------------

_EC2_CHAIN = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["iam:PassRole", "ec2:RunInstances"],
        "Resource": "*",
    }],
})

_PASSROLE_ONLY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["iam:PassRole"],
        "Resource": "*",
    }],
})

_EC2_ONLY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["ec2:RunInstances"],
        "Resource": "*",
    }],
})

_CRED_EXFIL = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["iam:CreateAccessKey", "secretsmanager:GetSecretValue"],
        "Resource": "*",
    }],
})

_POLICY_MOD = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["iam:AttachRolePolicy", "iam:CreatePolicyVersion"],
        "Resource": "*",
    }],
})


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _capture_escalate_text(policy_json: str) -> str:
    from app.analyzer import escalate_policy_local
    from app.cli import _print_escalate
    result = escalate_policy_local(policy_json)
    buf = io.StringIO()
    old, sys.stdout = sys.stdout, buf
    try:
        _print_escalate(result, policy_json=policy_json)
    finally:
        sys.stdout = old
    return buf.getvalue()


def _composite_rule_ids(policy_json: str) -> set[str]:
    from app.analyzer import escalate_policy_local
    result = escalate_policy_local(policy_json)
    return {f["rule_id"] for f in result.composite_findings}


# ---------------------------------------------------------------------------
# 1. COMP-001 fires for iam:PassRole + ec2:RunInstances
# ---------------------------------------------------------------------------

class TestComp001Fires:
    def test_comp001_in_composite_findings(self):
        assert "COMP-001" in _composite_rule_ids(_EC2_CHAIN)

    def test_composite_findings_non_empty(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_EC2_CHAIN)
        assert result.composite_findings, (
            "escalate_policy_local must return composite_findings for EC2 chain"
        )

    def test_comp001_finding_has_required_fields(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_EC2_CHAIN)
        comp001 = next(f for f in result.composite_findings if f["rule_id"] == "COMP-001")
        for key in ("rule_id", "title", "severity", "confidence",
                    "contributing_actions", "rationale", "confidence_explanation"):
            assert key in comp001, f"CompositeFinding dict missing key: {key!r}"

    def test_comp001_contributing_actions_include_passrole(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_EC2_CHAIN)
        comp001 = next(f for f in result.composite_findings if f["rule_id"] == "COMP-001")
        actions_lower = [a.lower() for a in comp001["contributing_actions"]]
        assert any("passrole" in a for a in actions_lower)

    def test_comp001_contributing_actions_include_runinstances(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_EC2_CHAIN)
        comp001 = next(f for f in result.composite_findings if f["rule_id"] == "COMP-001")
        actions_lower = [a.lower() for a in comp001["contributing_actions"]]
        assert any("runinstances" in a for a in actions_lower)

    def test_comp001_severity_is_critical(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_EC2_CHAIN)
        comp001 = next(f for f in result.composite_findings if f["rule_id"] == "COMP-001")
        assert comp001["severity"] == "critical"

    def test_comp001_rationale_non_empty(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_EC2_CHAIN)
        comp001 = next(f for f in result.composite_findings if f["rule_id"] == "COMP-001")
        assert comp001["rationale"], "rationale must be non-empty"

    def test_summary_mentions_composite_count(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_EC2_CHAIN)
        assert "composite" in result.summary.lower(), (
            f"Summary must mention composite findings; got: {result.summary!r}"
        )


# ---------------------------------------------------------------------------
# 2. COMP-001 does NOT fire for iam:PassRole alone
# ---------------------------------------------------------------------------

class TestComp001DoesNotFirePassroleOnly:
    def test_comp001_absent(self):
        assert "COMP-001" not in _composite_rule_ids(_PASSROLE_ONLY), (
            "COMP-001 must not fire when only iam:PassRole is present "
            "(compute-with-role capability is missing)"
        )

    def test_passrole_still_detected(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_PASSROLE_ONLY)
        assert any("passrole" in a.lower() for a in result.detected_actions)


# ---------------------------------------------------------------------------
# 3. COMP-001 does NOT fire for ec2:RunInstances alone
# ---------------------------------------------------------------------------

class TestComp001DoesNotFireEc2Only:
    def test_comp001_absent(self):
        assert "COMP-001" not in _composite_rule_ids(_EC2_ONLY), (
            "COMP-001 must not fire when only ec2:RunInstances is present "
            "(privilege-delegation capability is missing)"
        )


# ---------------------------------------------------------------------------
# 4. COMP-004 fires for iam:CreateAccessKey + secretsmanager:GetSecretValue
# ---------------------------------------------------------------------------

class TestComp004Fires:
    def test_comp004_in_composite_findings(self):
        assert "COMP-004" in _composite_rule_ids(_CRED_EXFIL), (
            "COMP-004 must fire for iam:CreateAccessKey + secretsmanager:GetSecretValue"
        )

    def test_comp001_absent_for_cred_exfil(self):
        """COMP-001 must not fire — no compute-with-role capability present."""
        assert "COMP-001" not in _composite_rule_ids(_CRED_EXFIL)

    def test_comp004_finding_severity_is_high(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_CRED_EXFIL)
        comp004 = next(f for f in result.composite_findings if f["rule_id"] == "COMP-004")
        assert comp004["severity"] == "high"


# ---------------------------------------------------------------------------
# 5. COMP-003 fires for direct IAM policy modification
# ---------------------------------------------------------------------------

class TestComp003Fires:
    def test_comp003_in_composite_findings(self):
        """policy-modification alone satisfies COMP-003 required capabilities."""
        assert "COMP-003" in _composite_rule_ids(_POLICY_MOD), (
            "COMP-003 must fire for iam:AttachRolePolicy + iam:CreatePolicyVersion"
        )

    def test_comp003_is_not_false_positive_for_ec2_chain(self):
        """EC2 chain has no policy-modification capability — COMP-003 must not fire."""
        assert "COMP-003" not in _composite_rule_ids(_EC2_CHAIN)


# ---------------------------------------------------------------------------
# 6. JSON output includes composite_findings
# ---------------------------------------------------------------------------

class TestJsonOutputIncludesCompositeFindings:
    def test_composite_findings_key_present_in_json(self):
        from app.analyzer import escalate_policy_local, analyze_policy_rules
        from app.cli import _escalate_to_json
        result = escalate_policy_local(_EC2_CHAIN)
        rule_findings = analyze_policy_rules(_EC2_CHAIN)
        data = _escalate_to_json(result, rule_findings)
        assert "composite_findings" in data, (
            "_escalate_to_json output must contain 'composite_findings' key"
        )

    def test_comp001_present_in_json_composite_findings(self):
        from app.analyzer import escalate_policy_local, analyze_policy_rules
        from app.cli import _escalate_to_json
        result = escalate_policy_local(_EC2_CHAIN)
        rule_findings = analyze_policy_rules(_EC2_CHAIN)
        data = _escalate_to_json(result, rule_findings)
        rule_ids = {f["rule_id"] for f in data["composite_findings"]}
        assert "COMP-001" in rule_ids

    def test_composite_findings_json_serialisable(self):
        """Composite findings dict must round-trip through JSON without error."""
        from app.analyzer import escalate_policy_local, analyze_policy_rules
        from app.cli import _escalate_to_json
        result = escalate_policy_local(_EC2_CHAIN)
        rule_findings = analyze_policy_rules(_EC2_CHAIN)
        data = _escalate_to_json(result, rule_findings)
        serialised = json.dumps(data)  # must not raise
        parsed_back = json.loads(serialised)
        assert parsed_back["composite_findings"]

    def test_empty_composite_findings_for_safe_policy(self):
        safe_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                           "Resource": "arn:aws:s3:::my-bucket/*"}],
        })
        from app.analyzer import escalate_policy_local, analyze_policy_rules
        from app.cli import _escalate_to_json
        result = escalate_policy_local(safe_policy)
        rule_findings = analyze_policy_rules(safe_policy)
        data = _escalate_to_json(result, rule_findings)
        # s3:GetObject has data-read-sensitive cap; no second capability → no composite
        assert isinstance(data["composite_findings"], list)


# ---------------------------------------------------------------------------
# 7. CLI text output contains High-Risk Permission Patterns section
# ---------------------------------------------------------------------------

class TestCliTextCompositeSection:
    def test_composite_findings_section_header_present(self):
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "High-Risk Permission Patterns" in output, (
            "CLI text output must contain an 'High-Risk Permission Patterns' section header"
        )

    def test_comp001_rule_id_in_output(self):
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "COMP-001" in output

    def test_comp001_title_in_output(self):
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "Privilege Escalation via EC2" in output

    def test_severity_shown_in_output(self):
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "CRITICAL" in output.upper()

    def test_confidence_shown_in_output(self):
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "confidence" in output.lower()

    def test_contributing_actions_shown_in_output(self):
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "passrole" in output.lower() or "iam:PassRole" in output

    def test_rationale_shown_in_output(self):
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "Why:" in output

    def test_no_composite_section_for_passrole_only(self):
        """No attack-patterns section when the chain is incomplete."""
        output = _capture_escalate_text(_PASSROLE_ONLY)
        assert "High-Risk Permission Patterns" not in output, (
            "High-Risk Permission Patterns section must not appear when no composite rule fires"
        )

    def test_no_composite_section_for_ec2_only(self):
        output = _capture_escalate_text(_EC2_ONLY)
        assert "High-Risk Permission Patterns" not in output


# ---------------------------------------------------------------------------
# 8. Summary line reflects composite findings
# ---------------------------------------------------------------------------

class TestSummaryReflectsCompositeFindings:
    def test_summary_mentions_composite_for_ec2_chain(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_EC2_CHAIN)
        assert "composite" in result.summary.lower(), (
            f"Summary must mention composite findings; got: {result.summary!r}"
        )

    def test_summary_composite_count_correct(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_EC2_CHAIN)
        n = len(result.composite_findings)
        assert str(n) in result.summary, (
            f"Summary must include the composite finding count ({n}); "
            f"got: {result.summary!r}"
        )

    def test_summary_no_composite_mention_for_passrole_only(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_PASSROLE_ONLY)
        assert "composite" not in result.summary.lower(), (
            f"Summary must not mention composite when no rule fires; "
            f"got: {result.summary!r}"
        )
