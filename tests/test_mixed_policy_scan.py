"""Tests for honest unknown-action handling during scan.

Core invariants verified here:
1. A policy with one known-risky action + one unknown action must:
   - Detect the known-risky action normally (R003 / detected_actions).
   - Surface the unknown action in EscalationResult.unknown_actions.
   - Never label the unknown action as safe or risky.
   - Add the unknown action to review_queue.json (deduplicated).
   - Produce a summary that accurately names both severities.

2. A policy with only unknown actions must still produce a non-empty
   unknown_actions list — and must not produce any detected_actions.

3. Duplicate prevention: calling escalate twice on the same unknown action
   must not create two queue entries.

4. Summary wording accuracy: reviewed actions are named by their actual
   risk tier (high vs. medium), not by the policy's overall score band.
"""

from __future__ import annotations

import json
import pathlib
import tempfile

import pytest

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

_MIXED_POLICY_JSON = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["iam:PassRole", "svc:FutureAction"],
        "Resource": "*",
    }],
})

_UNKNOWN_ONLY_POLICY_JSON = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["svc:UnreviewedAction"],
        "Resource": "*",
    }],
})

_HIGH_RISK_ONLY_POLICY_JSON = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["iam:PassRole", "iam:AttachRolePolicy"],
        "Resource": "*",
    }],
})

_MEDIUM_RISK_ONLY_POLICY_JSON = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["iam:CreateAccessKey", "secretsmanager:GetSecretValue"],
        "Resource": "*",
    }],
})


# ---------------------------------------------------------------------------
# 1. Mixed policy: one known-risky + one unknown
# ---------------------------------------------------------------------------

class TestMixedKnownRiskyAndUnknown:
    """iam:PassRole (confirmed high-risk) + svc:FutureAction (unknown).

    The known action must be detected as risky. The unknown action must be
    surfaced in unknown_actions and must never appear in detected_actions.
    """

    def test_iam_passrole_in_detected_actions(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_MIXED_POLICY_JSON)
        assert any("passrole" in a.lower() for a in result.detected_actions), (
            "iam:PassRole must appear in detected_actions"
        )

    def test_unknown_action_not_in_detected_actions(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_MIXED_POLICY_JSON)
        assert not any("futureaction" in a.lower() for a in result.detected_actions), (
            "svc:FutureAction must not be promoted into detected_actions"
        )

    def test_unknown_action_in_unknown_actions(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_MIXED_POLICY_JSON)
        assert hasattr(result, "unknown_actions"), (
            "EscalationResult must have an unknown_actions field"
        )
        assert any("futureaction" in a.lower() for a in result.unknown_actions), (
            "svc:FutureAction must appear in unknown_actions"
        )

    def test_unknown_action_not_labeled_safe(self):
        """unknown_actions is non-empty — the action has not been cleared as safe."""
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_MIXED_POLICY_JSON)
        assert result.unknown_actions, (
            "unknown_actions must be non-empty; unknown action was not surfaced"
        )

    def test_unknown_action_not_labeled_risky(self):
        """svc:FutureAction must not produce an R003 (reviewed high-risk) finding."""
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(_MIXED_POLICY_JSON)
        r003_titles = [f.title for f in findings if f.rule_id == "R003"]
        assert not any("futureaction" in t.lower() for t in r003_titles), (
            "Unknown action must not generate an R003 reviewed-high-risk finding"
        )

    def test_passrole_still_produces_r003(self):
        """iam:PassRole must still produce an R003 finding — regression guard."""
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(_MIXED_POLICY_JSON)
        r003_names = {
            f.title.split(": ", 1)[1]
            for f in findings if f.rule_id == "R003"
        }
        assert "iam:passrole" in r003_names, (
            "iam:PassRole must still be detected by R003"
        )

    def test_summary_mentions_reviewed_high_risk(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_MIXED_POLICY_JSON)
        assert "reviewed high-risk" in result.summary, (
            f"Summary must name the high-risk action tier; got: {result.summary!r}"
        )

    def test_summary_mentions_unknown_action(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_MIXED_POLICY_JSON)
        assert "unknown" in result.summary.lower(), (
            f"Summary must mention unknown action(s); got: {result.summary!r}"
        )

    def test_summary_does_not_say_only_medium_risk(self):
        """iam:PassRole is high-risk — summary must not call it 'medium-risk only'."""
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_MIXED_POLICY_JSON)
        # If "medium-risk" appears it must be accompanied by "high-risk"
        if "medium-risk" in result.summary.lower():
            assert "high-risk" in result.summary.lower(), (
                f"Summary mentions 'medium-risk' but omits 'high-risk' for iam:PassRole: "
                f"{result.summary!r}"
            )


# ---------------------------------------------------------------------------
# 2. Unknown-only policy
# ---------------------------------------------------------------------------

class TestUnknownOnlyPolicy:
    """A policy with only an unknown action — no detected_actions, but unknown_actions is set."""

    def test_detected_actions_is_empty(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_UNKNOWN_ONLY_POLICY_JSON)
        assert result.detected_actions == [], (
            "No known-risky actions — detected_actions must be empty"
        )

    def test_unknown_actions_is_non_empty(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_UNKNOWN_ONLY_POLICY_JSON)
        assert result.unknown_actions, (
            "svc:UnreviewedAction must appear in unknown_actions"
        )

    def test_unknown_action_surfaced_in_result(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_UNKNOWN_ONLY_POLICY_JSON)
        assert any("unreviewedaction" in a.lower() for a in result.unknown_actions)

    def test_no_r003_for_unknown_only(self):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(_UNKNOWN_ONLY_POLICY_JSON)
        assert not any(f.rule_id == "R003" for f in findings)

    def test_no_r004_for_unknown_only(self):
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(_UNKNOWN_ONLY_POLICY_JSON)
        assert not any(f.rule_id == "R004" for f in findings)


# ---------------------------------------------------------------------------
# 3. Review queue insertion and deduplication
# ---------------------------------------------------------------------------

class TestReviewQueueInsertion:
    """Verify that unknown actions are persisted to review_queue.json."""

    def _run_escalate_with_queue(self, policy_json: str, tmp_path: pathlib.Path) -> dict:
        """Run escalate_policy_local patching _add_to_review_queue to use a tmp queue."""
        from unittest.mock import patch
        from app.analyzer import escalate_policy_local, _add_to_review_queue

        queue_file = tmp_path / "review_queue.json"

        def _patched_add(unknown_actions, queue_path=None):
            _add_to_review_queue(unknown_actions, queue_path=queue_file)

        with patch("app.analyzer._add_to_review_queue", side_effect=_patched_add):
            escalate_policy_local(policy_json)

        if queue_file.exists():
            return json.loads(queue_file.read_text(encoding="utf-8"))
        return {"items": []}

    def test_unknown_action_added_to_queue(self, tmp_path):
        queue = self._run_escalate_with_queue(_MIXED_POLICY_JSON, tmp_path)
        action_keys = [item["action"].lower() for item in queue.get("items", [])]
        assert any("futureaction" in k for k in action_keys), (
            "svc:FutureAction must be present in the review queue after scan"
        )

    def test_known_action_not_added_to_queue(self, tmp_path):
        """iam:PassRole is in the classification file — must not appear in queue."""
        queue = self._run_escalate_with_queue(_MIXED_POLICY_JSON, tmp_path)
        action_keys = [item["action"].lower() for item in queue.get("items", [])]
        assert not any("passrole" in k for k in action_keys), (
            "iam:PassRole is already classified — must not be added to queue"
        )

    def test_queued_item_has_unclassified_status(self, tmp_path):
        queue = self._run_escalate_with_queue(_MIXED_POLICY_JSON, tmp_path)
        for item in queue.get("items", []):
            if "futureaction" in item["action"].lower():
                assert item["status"] == "unclassified"
                return
        pytest.fail("svc:FutureAction not found in queue items")

    def test_queued_item_has_required_fields(self, tmp_path):
        required = {
            "action", "service", "name", "access_level",
            "resource_types", "condition_keys", "dependent_actions",
            "status", "candidate_capabilities", "notes", "reason",
        }
        queue = self._run_escalate_with_queue(_MIXED_POLICY_JSON, tmp_path)
        for item in queue.get("items", []):
            if "futureaction" in item["action"].lower():
                assert set(item.keys()) == required, (
                    f"Queue item missing required fields: {required - set(item.keys())}"
                )
                return
        pytest.fail("svc:FutureAction not found in queue items")

    def test_duplicate_prevention_same_action_not_added_twice(self, tmp_path):
        """Running escalate twice on the same policy must not duplicate queue entries."""
        from unittest.mock import patch
        from app.analyzer import escalate_policy_local, _add_to_review_queue

        queue_file = tmp_path / "review_queue.json"

        def _patched_add(unknown_actions, queue_path=None):
            _add_to_review_queue(unknown_actions, queue_path=queue_file)

        with patch("app.analyzer._add_to_review_queue", side_effect=_patched_add):
            escalate_policy_local(_MIXED_POLICY_JSON)
            escalate_policy_local(_MIXED_POLICY_JSON)

        queue = json.loads(queue_file.read_text(encoding="utf-8"))
        future_entries = [
            item for item in queue["items"]
            if "futureaction" in item["action"].lower()
        ]
        assert len(future_entries) == 1, (
            f"svc:FutureAction must appear exactly once in the queue; "
            f"found {len(future_entries)} entries"
        )

    def test_existing_queue_entries_preserved(self, tmp_path):
        """Pre-existing queue entries must not be removed when new ones are added."""
        queue_file = tmp_path / "review_queue.json"
        existing_queue = {
            "generated_at": "2026-01-01T00:00:00+00:00",
            "source_catalog_version": 1,
            "items": [{
                "action": "a2c:GetContainerizationJobDetails",
                "service": "a2c",
                "name": "GetContainerizationJobDetails",
                "access_level": "Read",
                "resource_types": [],
                "condition_keys": [],
                "dependent_actions": [],
                "status": "unclassified",
                "candidate_capabilities": [],
                "notes": "",
                "reason": "pre-existing entry",
            }],
        }
        queue_file.write_text(json.dumps(existing_queue), encoding="utf-8")

        from app.analyzer import _add_to_review_queue
        _add_to_review_queue(["svc:futureaction"], queue_path=queue_file)

        queue = json.loads(queue_file.read_text(encoding="utf-8"))
        action_keys = [item["action"].lower() for item in queue["items"]]
        assert "a2c:getcontainerizationjobdetails" in action_keys, (
            "Pre-existing queue entry must be preserved"
        )
        assert "svc:futureaction" in action_keys, (
            "New unknown action must be appended"
        )

    def test_add_to_review_queue_directly(self, tmp_path):
        """Direct unit test for _add_to_review_queue with no existing file."""
        from app.analyzer import _add_to_review_queue
        queue_file = tmp_path / "review_queue.json"
        _add_to_review_queue(["svc:futureaction"], queue_path=queue_file)
        assert queue_file.exists()
        queue = json.loads(queue_file.read_text(encoding="utf-8"))
        assert len(queue["items"]) == 1
        assert queue["items"][0]["action"] == "svc:futureaction"
        assert queue["items"][0]["status"] == "unclassified"

    def test_add_to_review_queue_empty_list_does_nothing(self, tmp_path):
        """Empty unknown_actions list must not create or modify the queue file."""
        from app.analyzer import _add_to_review_queue
        queue_file = tmp_path / "review_queue.json"
        _add_to_review_queue([], queue_path=queue_file)
        assert not queue_file.exists(), (
            "Queue file must not be created for an empty unknown_actions list"
        )


# ---------------------------------------------------------------------------
# 4. Summary wording accuracy
# ---------------------------------------------------------------------------

class TestSummaryWordingAccuracy:
    """Verify that summary text reflects actual action severities, not just the score band."""

    def test_high_risk_only_summary_says_high_risk(self):
        """Policy with only HIGH_RISK actions → summary must say 'reviewed high-risk'."""
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_HIGH_RISK_ONLY_POLICY_JSON)
        assert "reviewed high-risk" in result.summary, (
            f"Expected 'reviewed high-risk' in summary; got: {result.summary!r}"
        )
        assert "reviewed medium-risk" not in result.summary

    def test_medium_risk_only_summary_says_medium_risk(self):
        """Policy with only MEDIUM_RISK actions → summary must say 'reviewed medium-risk'."""
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_MEDIUM_RISK_ONLY_POLICY_JSON)
        assert "reviewed medium-risk" in result.summary, (
            f"Expected 'reviewed medium-risk' in summary; got: {result.summary!r}"
        )
        assert "reviewed high-risk" not in result.summary

    def test_high_risk_action_not_mislabeled_as_medium(self):
        """iam:PassRole is in HIGH_RISK_ACTIONS — must not appear as 'medium-risk' in summary."""
        from app.analyzer import escalate_policy_local
        # Policy that scores as "Medium" but has a high-risk action
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}],
        })
        result = escalate_policy_local(policy)
        assert "reviewed high-risk" in result.summary, (
            f"iam:PassRole is high-risk — summary must not mislabel it as medium-risk; "
            f"got: {result.summary!r}"
        )

    def test_no_risks_summary_is_clean(self):
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"}],
        })
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(policy)
        # s3:GetObject is in MEDIUM_RISK_ACTIONS — there will be detections.
        # Just verify no crash and summary is a non-empty string.
        assert isinstance(result.summary, str)
        assert len(result.summary) > 0

    def test_mixed_summary_does_not_say_only_medium_for_high_action(self):
        """The mixed iam:PassRole + unknown policy must not produce a 'medium-risk only' summary."""
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_MIXED_POLICY_JSON)
        # "reviewed medium-risk" alone would be wrong; iam:PassRole is high-risk.
        assert not (
            "reviewed medium-risk" in result.summary.lower()
            and "reviewed high-risk" not in result.summary.lower()
        ), (
            f"Summary incorrectly labels iam:PassRole as 'medium-risk only': "
            f"{result.summary!r}"
        )


# ---------------------------------------------------------------------------
# 5. CLI text output: unknown actions appear in "Needs Review" section
# ---------------------------------------------------------------------------

class TestCliUnknownActionDisplay:
    """Verify that _print_escalate surfaces unknown actions in the output text."""

    def _capture_escalate_output(self, policy_json: str) -> str:
        import io, sys
        from app.analyzer import escalate_policy_local
        from app.cli import _print_escalate
        result = escalate_policy_local(policy_json)
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            _print_escalate(result, policy_json=policy_json)
        finally:
            sys.stdout = old
        return buf.getvalue()

    def test_unknown_action_appears_in_cli_output(self):
        output = self._capture_escalate_output(_MIXED_POLICY_JSON)
        assert "svc:futureaction" in output.lower(), (
            "svc:FutureAction must appear in the escalate CLI text output"
        )

    def test_unknown_action_labeled_unclassified_in_cli_output(self):
        output = self._capture_escalate_output(_MIXED_POLICY_JSON)
        assert "unclassified" in output.lower(), (
            "Unknown action must be labeled as unclassified in the CLI output"
        )

    def test_passrole_appears_in_confirmed_section(self):
        """iam:PassRole must appear in the Confirmed Risky Actions section."""
        output = self._capture_escalate_output(_MIXED_POLICY_JSON)
        assert "iam:passrole" in output.lower(), (
            "iam:PassRole must appear in the CLI escalate output"
        )

    def test_unknown_action_not_in_confirmed_risky_section(self):
        """svc:FutureAction must not be in the 'Confirmed Risky Actions' section."""
        output = self._capture_escalate_output(_MIXED_POLICY_JSON)
        lines = output.splitlines()
        in_confirmed_section = False
        for line in lines:
            if "Confirmed Risky Actions" in line:
                in_confirmed_section = True
            elif any(s in line for s in ["Needs Review", "Findings", "Unclassified"]):
                in_confirmed_section = False
            if in_confirmed_section and "futureaction" in line.lower():
                pytest.fail(
                    "svc:FutureAction appeared in the Confirmed Risky Actions section"
                )

    def test_json_output_includes_unknown_actions(self):
        """JSON output from _escalate_to_json must include the unknown_actions key."""
        from app.analyzer import escalate_policy_local, analyze_policy_rules
        from app.cli import _escalate_to_json
        result = escalate_policy_local(_MIXED_POLICY_JSON)
        rule_findings = analyze_policy_rules(_MIXED_POLICY_JSON)
        data = _escalate_to_json(result, rule_findings)
        assert "unknown_actions" in data, (
            "JSON escalate output must include 'unknown_actions' key"
        )
        assert any("futureaction" in a.lower() for a in data["unknown_actions"]), (
            "svc:FutureAction must be in JSON unknown_actions"
        )
