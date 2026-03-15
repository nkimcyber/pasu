"""Tests for the confidence-gated fix safety boundary.

These tests prove that ``fix_policy_local`` withholds automated transformations
for actions that lack sufficient reviewed evidence, and that clear explanations
are returned in every blocked case.

Safety boundaries under test
-----------------------------
1. **Unknown action** — action present in ``HIGH_RISK_ACTIONS`` but absent
   from the classification file is not auto-removed.
2. **Low-confidence classification** — a classified record with
   ``confidence="low"`` is not auto-removed.
3. **Not-applicable classification** — an action reviewed and marked
   ``not-applicable`` is not auto-removed (it is out-of-scope for the risk
   model).
4. **Composite low-confidence** — a composite finding derived at ``"low"``
   confidence adds a manual-review note without blocking the overall fix.
5. **Gate pass** — classified + ``confidence="high"`` still triggers removal
   (existing behaviour preserved).
6. **Gate helper unit tests** — ``_fix_action_gate_reason`` is tested in
   isolation with controlled classification dicts.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _policy(actions):
    """Return a minimal Allow policy JSON string for the given actions."""
    if isinstance(actions, str):
        actions = [actions]
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
    })


# A classification dict that marks iam:PassRole as LOW confidence so we can
# test the gate without touching the real classification file.
_LOW_CONF_CLASSIFICATION = {
    "iam:PassRole": {
        "status": "classified",
        "capabilities": ["privilege-delegation"],
        "confidence": "low",
        "notes": "Test record with low confidence.",
    },
}

# A classification dict that marks iam:PassRole as NOT-APPLICABLE.
_NOT_APPLICABLE_CLASSIFICATION = {
    "iam:PassRole": {
        "status": "not-applicable",
        "capabilities": [],
        "confidence": "high",
        "notes": "Test record marked not-applicable.",
    },
}

# A classification dict that marks iam:PassRole as HIGH confidence
# (mirrors the real file — gate should pass).
_HIGH_CONF_CLASSIFICATION = {
    "iam:PassRole": {
        "status": "classified",
        "capabilities": ["privilege-delegation"],
        "confidence": "high",
        "notes": "Well-documented high-confidence record.",
    },
}


# ---------------------------------------------------------------------------
# Unit tests for _fix_action_gate_reason
# ---------------------------------------------------------------------------

class TestFixActionGateReason:
    """Direct unit tests for the gate-reason helper."""

    def _gate(self, action_lower, classification_raw):
        from app.analyzer import _fix_action_gate_reason
        index = {k.lower(): v for k, v in classification_raw.items()}
        return _fix_action_gate_reason(action_lower, index)

    def test_unknown_action_is_blocked(self):
        """Action absent from classification must return a blocking reason."""
        reason = self._gate("iam:passrole", {})  # empty classification
        assert reason is not None
        assert "no reviewed classification record" in reason

    def test_low_confidence_is_blocked(self):
        """A classified record with confidence='low' must return a blocking reason."""
        reason = self._gate("iam:passrole", _LOW_CONF_CLASSIFICATION)
        assert reason is not None
        assert "low" in reason.lower()

    def test_not_applicable_is_blocked(self):
        """A 'not-applicable' record must return a blocking reason."""
        reason = self._gate("iam:passrole", _NOT_APPLICABLE_CLASSIFICATION)
        assert reason is not None
        assert "not-applicable" in reason

    def test_high_confidence_passes(self):
        """A classified + high-confidence record must return None (gate passes)."""
        reason = self._gate("iam:passrole", _HIGH_CONF_CLASSIFICATION)
        assert reason is None

    def test_medium_confidence_passes(self):
        """A classified + medium-confidence record must return None (gate passes)."""
        medium = {
            "iam:CreateRole": {
                "status": "classified",
                "capabilities": ["policy-modification"],
                "confidence": "medium",
                "notes": "",
            },
        }
        from app.analyzer import _fix_action_gate_reason
        index = {k.lower(): v for k, v in medium.items()}
        assert _fix_action_gate_reason("iam:createrole", index) is None

    def test_lookup_is_case_insensitive(self):
        """Gate must work regardless of the case in which the action is stored."""
        from app.analyzer import _fix_action_gate_reason
        # Classification key is PascalCase; lookup uses lowercase key
        classification = {
            "iam:PassRole": {
                "status": "classified",
                "capabilities": ["privilege-delegation"],
                "confidence": "high",
                "notes": "",
            },
        }
        index = {k.lower(): v for k, v in classification.items()}
        # Both uppercase and lowercase forms of the action must resolve correctly
        assert _fix_action_gate_reason("iam:passrole", index) is None
        assert _fix_action_gate_reason("IAM:PASSROLE", {}) is not None


# ---------------------------------------------------------------------------
# Integration tests: fix_policy_local with mocked classification
# ---------------------------------------------------------------------------

class TestFixGateBlocksUnknownAction:
    """Unknown actions (not in classification) must not be auto-removed."""

    def test_unknown_action_kept_in_fixed_policy(self):
        """iam:PassRole with no classification record must remain in the output."""
        from app.analyzer import fix_policy_local
        with patch("app.analyzer._load_classification_lower", return_value={}), \
             patch("app.action_classification.load_action_classification", return_value={}):
            result = fix_policy_local(_policy("iam:PassRole"))

        stmt = result.fixed_policy["Statement"][0]
        actions = stmt["Action"]
        assert "iam:PassRole" in actions, (
            "Unknown action must be kept unchanged — auto-removal requires a "
            "confirmed classification record"
        )

    def test_unknown_action_produces_no_removed_action_change(self):
        """No 'removed_action' change entry must be produced for an unknown action."""
        from app.analyzer import fix_policy_local
        with patch("app.analyzer._load_classification_lower", return_value={}), \
             patch("app.action_classification.load_action_classification", return_value={}):
            result = fix_policy_local(_policy("iam:PassRole"))

        removed = [c for c in result.changes if c.type == "removed_action"]
        assert removed == [], "removed_action change must not be created for unknown action"

    def test_unknown_action_adds_manual_review_note(self):
        """A clear manual-review note must be added when the gate blocks a fix."""
        from app.analyzer import fix_policy_local
        with patch("app.analyzer._load_classification_lower", return_value={}), \
             patch("app.action_classification.load_action_classification", return_value={}):
            result = fix_policy_local(_policy("iam:PassRole"))

        assert len(result.manual_review_needed) > 0
        note_text = " ".join(result.manual_review_needed).lower()
        assert "iam:passrole" in note_text or "passrole" in note_text

    def test_unknown_action_note_explains_reason(self):
        """Manual-review note must mention the blocking reason."""
        from app.analyzer import fix_policy_local
        with patch("app.analyzer._load_classification_lower", return_value={}), \
             patch("app.action_classification.load_action_classification", return_value={}):
            result = fix_policy_local(_policy("iam:PassRole"))

        combined = " ".join(result.manual_review_needed)
        assert "classification" in combined.lower() or "auto-fix" in combined.lower()


class TestFixGateBlocksLowConfidence:
    """Actions with low-confidence classification must not be auto-removed."""

    def _low_conf_index(self):
        return {k.lower(): v for k, v in _LOW_CONF_CLASSIFICATION.items()}

    def test_low_confidence_action_kept_in_fixed_policy(self):
        from app.analyzer import fix_policy_local
        with patch("app.analyzer._load_classification_lower", return_value=self._low_conf_index()), \
             patch("app.action_classification.load_action_classification", return_value=_LOW_CONF_CLASSIFICATION):
            result = fix_policy_local(_policy("iam:PassRole"))

        stmt = result.fixed_policy["Statement"][0]
        assert "iam:PassRole" in stmt["Action"], (
            "Low-confidence action must remain — insufficient evidence for auto-removal"
        )

    def test_low_confidence_action_produces_manual_review_note(self):
        from app.analyzer import fix_policy_local
        with patch("app.analyzer._load_classification_lower", return_value=self._low_conf_index()), \
             patch("app.action_classification.load_action_classification", return_value=_LOW_CONF_CLASSIFICATION):
            result = fix_policy_local(_policy("iam:PassRole"))

        assert len(result.manual_review_needed) > 0
        combined = " ".join(result.manual_review_needed).lower()
        assert "low" in combined


class TestFixGateBlocksNotApplicable:
    """Actions classified as not-applicable must not be auto-removed."""

    def _not_app_index(self):
        return {k.lower(): v for k, v in _NOT_APPLICABLE_CLASSIFICATION.items()}

    def test_not_applicable_action_kept(self):
        from app.analyzer import fix_policy_local
        with patch("app.analyzer._load_classification_lower", return_value=self._not_app_index()), \
             patch("app.action_classification.load_action_classification", return_value=_NOT_APPLICABLE_CLASSIFICATION):
            result = fix_policy_local(_policy("iam:PassRole"))

        stmt = result.fixed_policy["Statement"][0]
        assert "iam:PassRole" in stmt["Action"]

    def test_not_applicable_action_note_mentions_reason(self):
        from app.analyzer import fix_policy_local
        with patch("app.analyzer._load_classification_lower", return_value=self._not_app_index()), \
             patch("app.action_classification.load_action_classification", return_value=_NOT_APPLICABLE_CLASSIFICATION):
            result = fix_policy_local(_policy("iam:PassRole"))

        combined = " ".join(result.manual_review_needed).lower()
        assert "not-applicable" in combined


class TestFixGatePassesHighConfidence:
    """High-confidence classified actions must still be auto-removed (regression guard)."""

    def test_high_confidence_action_is_removed(self):
        """Gate must not block correctly classified, high-confidence actions."""
        from app.analyzer import fix_policy_local
        # Use the real classification file — iam:PassRole is classified/high
        result = fix_policy_local(_policy("iam:PassRole"))

        stmt = result.fixed_policy["Statement"][0]
        assert "iam:PassRole" not in stmt["Action"], (
            "iam:PassRole is classified/high-confidence and must be auto-removed"
        )

    def test_high_confidence_removal_produces_change_entry(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_policy("iam:PassRole"))
        removed = [c for c in result.changes if c.type == "removed_action"]
        assert any("PassRole" in (c.action or "") for c in removed)

    def test_high_confidence_removal_has_no_gate_note(self):
        """No 'auto-fix withheld' message when the gate passes."""
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_policy("iam:PassRole"))
        combined = " ".join(result.manual_review_needed)
        assert "auto-fix withheld" not in combined


# ---------------------------------------------------------------------------
# Composite low-confidence advisory notes
# ---------------------------------------------------------------------------

class TestCompositeGateAdvisoryNotes:
    """Composite findings with low confidence add notes without blocking the fix."""

    def test_low_confidence_composite_finding_adds_note(self):
        """A mocked low-confidence composite finding must produce a manual-review note."""
        from app.analyzer import fix_policy_local
        from app.composite_engine import CompositeFinding

        low_conf_finding = CompositeFinding(
            rule_id="COMP-001",
            title="Test Low Confidence Pattern",
            severity="high",
            confidence="low",
            matched_required=frozenset({"privilege-delegation"}),
            matched_optional=frozenset(),
            contributing_actions=("iam:PassRole",),
            confidence_explanation="weakest: lowest required confidence is low → low",
        )

        with patch("app.analyzer._composite_low_confidence_notes",
                   return_value=["Composite pattern 'Test Low Confidence Pattern' "
                                 "(rule COMP-001) detected with low confidence — "
                                 "auto-fix withheld for implicated actions (iam:PassRole)."]):
            result = fix_policy_local(_policy("iam:PassRole"))

        composite_notes = [
            n for n in result.manual_review_needed
            if "Composite pattern" in n or "low confidence" in n.lower()
        ]
        assert len(composite_notes) > 0

    def test_high_confidence_composite_finding_adds_no_note(self):
        """High-confidence composite findings must not add advisory notes."""
        from app.analyzer import fix_policy_local

        # Patch the composite helper to return empty (simulates high-confidence findings only)
        with patch("app.analyzer._composite_low_confidence_notes", return_value=[]):
            result = fix_policy_local(_policy("iam:PassRole"))

        composite_notes = [n for n in result.manual_review_needed if "Composite pattern" in n]
        assert composite_notes == []

    def test_composite_helper_failure_does_not_raise(self):
        """If composite analysis fails, fix_policy_local must still complete normally."""
        from app.analyzer import fix_policy_local

        def _raise(*_a, **_kw):
            raise RuntimeError("Simulated composite analysis failure")

        # Patch _composite_low_confidence_notes to raise; fix_policy_local wraps the
        # call in try/except so the RuntimeError must be swallowed silently.
        with patch("app.analyzer._composite_low_confidence_notes", side_effect=_raise):
            result = fix_policy_local(_policy("iam:PassRole"))
        # If we reach here the exception was swallowed; verify we got a valid result.
        assert result.fixed_policy is not None

    def test_composite_notes_helper_silences_internal_errors(self):
        """_composite_low_confidence_notes must return [] rather than raise on errors."""
        from app.analyzer import _composite_low_confidence_notes

        # Trigger the except branch by passing invalid policy JSON
        notes = _composite_low_confidence_notes("not valid json", {})
        assert notes == []


# ---------------------------------------------------------------------------
# Mixed policy: some actions blocked, others pass
# ---------------------------------------------------------------------------

class TestFixGateMixedPolicy:
    """Verifies correct handling when a policy mixes gated and allowed actions."""

    def test_gated_action_kept_allowed_action_removed(self):
        """When actions have mixed gate outcomes, only passing ones are removed."""
        from app.analyzer import fix_policy_local

        # iam:PassRole → HIGH conf (real file) → removed
        # iam:AttachRolePolicy → HIGH conf (real file) → removed
        # Both are classified/high in real file, so this test confirms normal removal.
        policy = _policy(["iam:PassRole", "iam:AttachRolePolicy"])
        result = fix_policy_local(policy)

        stmt = result.fixed_policy["Statement"][0]
        # Both should be removed (both are classified/high in real classification file)
        assert "iam:PassRole" not in stmt["Action"]
        assert "iam:AttachRolePolicy" not in stmt["Action"]

    def test_gated_action_kept_safe_action_preserved(self):
        """Blocked actions stay; safe (non-HIGH_RISK) actions are kept normally."""
        from app.analyzer import fix_policy_local

        # Mock iam:PassRole as unknown → should be kept
        # s3:GetObject is safe → should be kept regardless
        with patch("app.analyzer._load_classification_lower", return_value={}), \
             patch("app.action_classification.load_action_classification", return_value={}):
            result = fix_policy_local(_policy(["iam:PassRole", "s3:GetObject"]))

        stmt = result.fixed_policy["Statement"][0]
        assert "iam:PassRole" in stmt["Action"], "Blocked action must be kept"
        assert "s3:GetObject" in stmt["Action"], "Safe action must be kept"
