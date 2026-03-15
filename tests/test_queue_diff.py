"""Unit tests for diff_review_queues() and its Markdown rendering.

All tests are pure (no I/O, no network).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from sync_aws_catalog import (  # noqa: E402
    _render_queue_diff_section,
    diff_review_queues,
    render_markdown_report,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _queue(actions: list[str]) -> dict:
    """Build a minimal review queue dict from a list of action key strings."""
    return {
        "generated_at": "2026-03-14T17:22:09+00:00",
        "source_catalog_version": 1,
        "items": [{"action": a} for a in actions],
    }


def _item(action: str) -> dict:
    """Full ReviewItem skeleton — used when item fields matter."""
    svc, name = action.split(":", 1)
    return {
        "action": action,
        "service": svc,
        "name": name,
        "access_level": "Read",
        "resource_types": [],
        "condition_keys": [],
        "dependent_actions": [],
        "status": "unclassified",
        "candidate_capabilities": [],
        "notes": "",
        "reason": "test",
    }


def _catalog_diff_base() -> dict:
    """Minimal catalog diff dict that render_markdown_report() can render."""
    return {
        "generated_at": "2026-03-14T17:22:09+00:00",
        "source": "AWS Service Authorization Reference",
        "count_summary": {
            "previous_action_count": 0,
            "current_action_count": 0,
            "new_action_count": 0,
            "removed_action_count": 0,
            "changed_action_count": 0,
            "new_unclassified_action_count": 0,
        },
        "new_actions": [],
        "removed_actions": [],
        "changed_actions": [],
        "new_unclassified_actions": [],
        "services_with_new_unclassified_actions": [],
    }


# ---------------------------------------------------------------------------
# diff_review_queues — top-level structure
# ---------------------------------------------------------------------------

class TestDiffReviewQueuesStructure:
    def test_required_keys_present(self):
        result = diff_review_queues(None, _queue([]))
        assert "count_summary" in result
        assert "new_unclassified_actions" in result
        assert "removed_from_queue" in result
        assert "services_with_new_unclassified_actions" in result
        assert "new_unclassified_count_by_service" in result

    def test_count_summary_keys_present(self):
        result = diff_review_queues(None, _queue([]))
        cs = result["count_summary"]
        assert "previous_queue_count" in cs
        assert "current_queue_count" in cs
        assert "new_to_queue_count" in cs
        assert "removed_from_queue_count" in cs

    def test_no_extra_top_level_keys(self):
        result = diff_review_queues(None, _queue([]))
        assert set(result.keys()) == {
            "count_summary",
            "new_unclassified_actions",
            "removed_from_queue",
            "services_with_new_unclassified_actions",
            "new_unclassified_count_by_service",
        }


# ---------------------------------------------------------------------------
# diff_review_queues — count_summary correctness
# ---------------------------------------------------------------------------

class TestCountSummary:
    def test_no_previous_queue(self):
        cs = diff_review_queues(None, _queue(["iam:CreateUser", "s3:ListBuckets"]))["count_summary"]
        assert cs["previous_queue_count"] == 0
        assert cs["current_queue_count"] == 2
        assert cs["new_to_queue_count"] == 2
        assert cs["removed_from_queue_count"] == 0

    def test_empty_queues(self):
        cs = diff_review_queues(_queue([]), _queue([]))["count_summary"]
        assert cs == {
            "previous_queue_count": 0,
            "current_queue_count": 0,
            "new_to_queue_count": 0,
            "removed_from_queue_count": 0,
        }

    def test_identical_queues_produce_zero_deltas(self):
        actions = ["iam:CreateUser", "s3:ListBuckets", "ec2:DescribeInstances"]
        cs = diff_review_queues(_queue(actions), _queue(actions))["count_summary"]
        assert cs["new_to_queue_count"] == 0
        assert cs["removed_from_queue_count"] == 0

    def test_all_removed(self):
        prev = _queue(["iam:CreateUser", "s3:ListBuckets"])
        curr = _queue([])
        cs = diff_review_queues(prev, curr)["count_summary"]
        assert cs["previous_queue_count"] == 2
        assert cs["current_queue_count"] == 0
        assert cs["new_to_queue_count"] == 0
        assert cs["removed_from_queue_count"] == 2

    def test_partial_overlap(self):
        prev = _queue(["iam:CreateUser", "s3:ListBuckets"])
        curr = _queue(["s3:ListBuckets", "kms:Decrypt"])
        cs = diff_review_queues(prev, curr)["count_summary"]
        assert cs["previous_queue_count"] == 2
        assert cs["current_queue_count"] == 2
        assert cs["new_to_queue_count"] == 1   # kms:Decrypt
        assert cs["removed_from_queue_count"] == 1  # iam:CreateUser


# ---------------------------------------------------------------------------
# diff_review_queues — new_unclassified_actions & removed_from_queue
# ---------------------------------------------------------------------------

class TestNewAndRemoved:
    def test_new_actions_identified(self):
        prev = _queue(["iam:CreateUser"])
        curr = _queue(["iam:CreateUser", "s3:ListBuckets", "kms:Decrypt"])
        result = diff_review_queues(prev, curr)
        assert result["new_unclassified_actions"] == ["kms:Decrypt", "s3:ListBuckets"]

    def test_removed_actions_identified(self):
        prev = _queue(["iam:CreateUser", "s3:ListBuckets", "kms:Decrypt"])
        curr = _queue(["iam:CreateUser"])
        result = diff_review_queues(prev, curr)
        assert result["removed_from_queue"] == ["kms:Decrypt", "s3:ListBuckets"]

    def test_new_and_removed_are_sorted(self):
        prev = _queue(["z:ZAction", "a:AAction"])
        curr = _queue(["m:MAction", "b:BAction"])
        result = diff_review_queues(prev, curr)
        assert result["new_unclassified_actions"] == sorted(result["new_unclassified_actions"])
        assert result["removed_from_queue"] == sorted(result["removed_from_queue"])

    def test_unchanged_actions_absent_from_both_lists(self):
        shared = "iam:CreateUser"
        prev = _queue([shared, "s3:ListBuckets"])
        curr = _queue([shared, "kms:Decrypt"])
        result = diff_review_queues(prev, curr)
        assert shared not in result["new_unclassified_actions"]
        assert shared not in result["removed_from_queue"]

    def test_no_previous_all_current_are_new(self):
        curr = _queue(["iam:CreateUser", "s3:ListBuckets"])
        result = diff_review_queues(None, curr)
        assert set(result["new_unclassified_actions"]) == {"iam:CreateUser", "s3:ListBuckets"}
        assert result["removed_from_queue"] == []


# ---------------------------------------------------------------------------
# diff_review_queues — services_with_new & count_by_service
# ---------------------------------------------------------------------------

class TestServiceGrouping:
    def test_services_with_new_sorted(self):
        curr = _queue(["s3:ListBuckets", "ec2:DescribeInstances", "s3:GetObject"])
        result = diff_review_queues(None, curr)
        svcs = result["services_with_new_unclassified_actions"]
        assert svcs == sorted(svcs)

    def test_services_with_new_deduplicated(self):
        curr = _queue(["s3:ListBuckets", "s3:GetObject", "s3:PutObject"])
        result = diff_review_queues(None, curr)
        assert result["services_with_new_unclassified_actions"] == ["s3"]

    def test_count_by_service_correct(self):
        curr = _queue([
            "s3:ListBuckets", "s3:GetObject",
            "iam:CreateUser",
            "ec2:DescribeInstances", "ec2:RunInstances",
        ])
        result = diff_review_queues(None, curr)
        cbs = result["new_unclassified_count_by_service"]
        assert cbs["s3"] == 2
        assert cbs["iam"] == 1
        assert cbs["ec2"] == 2

    def test_count_by_service_sorted_by_service_name(self):
        curr = _queue(["z:ZAction", "a:AAction", "m:MAction"])
        result = diff_review_queues(None, curr)
        keys = list(result["new_unclassified_count_by_service"].keys())
        assert keys == sorted(keys)

    def test_count_by_service_empty_when_no_new(self):
        actions = ["iam:CreateUser", "s3:ListBuckets"]
        result = diff_review_queues(_queue(actions), _queue(actions))
        assert result["new_unclassified_count_by_service"] == {}

    def test_removed_actions_not_counted_in_by_service(self):
        prev = _queue(["iam:CreateUser"])
        curr = _queue(["s3:ListBuckets"])
        result = diff_review_queues(prev, curr)
        assert "iam" not in result["new_unclassified_count_by_service"]
        assert result["new_unclassified_count_by_service"].get("s3") == 1


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_repeated_calls_produce_identical_output(self):
        prev = _queue(["iam:CreateUser", "s3:ListBuckets"])
        curr = _queue(["s3:ListBuckets", "kms:Decrypt", "ec2:DescribeInstances"])
        first = diff_review_queues(prev, curr)
        second = diff_review_queues(prev, curr)
        assert first == second

    def test_dict_insertion_order_does_not_affect_result(self):
        """Queue item order should not affect which actions are new/removed."""
        prev = _queue(["b:BAction", "a:AAction"])
        curr_fwd = _queue(["a:AAction", "c:CAction"])
        curr_rev = _queue(["c:CAction", "a:AAction"])
        r1 = diff_review_queues(prev, curr_fwd)
        r2 = diff_review_queues(prev, curr_rev)
        assert r1["new_unclassified_actions"] == r2["new_unclassified_actions"]
        assert r1["removed_from_queue"] == r2["removed_from_queue"]


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

class TestMarkdownRendering:
    def _queue_diff_with_changes(self) -> dict:
        prev = _queue(["iam:CreateUser", "s3:ListBuckets"])
        curr = _queue(["s3:ListBuckets", "kms:Decrypt", "ec2:DescribeInstances"])
        return diff_review_queues(prev, curr)

    def test_section_header_present(self):
        lines = _render_queue_diff_section(self._queue_diff_with_changes())
        text = "\n".join(lines)
        assert "## Review Queue Diff" in text

    def test_count_summary_subsection_present(self):
        lines = _render_queue_diff_section(self._queue_diff_with_changes())
        text = "\n".join(lines)
        assert "Queue Count Summary" in text
        assert "Previous queue count" in text
        assert "Current queue count" in text
        assert "New to queue" in text
        assert "Removed from queue" in text

    def test_new_action_keys_appear_in_output(self):
        lines = _render_queue_diff_section(self._queue_diff_with_changes())
        text = "\n".join(lines)
        assert "kms:Decrypt" in text
        assert "ec2:DescribeInstances" in text

    def test_removed_action_keys_appear_in_output(self):
        lines = _render_queue_diff_section(self._queue_diff_with_changes())
        text = "\n".join(lines)
        assert "iam:CreateUser" in text

    def test_by_service_counts_appear_in_output(self):
        lines = _render_queue_diff_section(self._queue_diff_with_changes())
        text = "\n".join(lines)
        assert "kms" in text
        assert "ec2" in text

    def test_no_change_renders_empty_state_messages(self):
        actions = ["iam:CreateUser", "s3:ListBuckets"]
        qd = diff_review_queues(_queue(actions), _queue(actions))
        lines = _render_queue_diff_section(qd)
        text = "\n".join(lines).lower()
        assert "no new unclassified actions" in text
        assert "no removed from queue" in text

    def test_queue_diff_section_in_full_report(self):
        base = _catalog_diff_base()
        base["queue_diff"] = self._queue_diff_with_changes()
        report = render_markdown_report(base)
        assert "## Review Queue Diff" in report
        assert "kms:Decrypt" in report
        assert "iam:CreateUser" in report

    def test_no_queue_diff_key_renders_without_section(self):
        """Backward compat: existing diff dicts without queue_diff still render."""
        report = render_markdown_report(_catalog_diff_base())
        assert "## Review Queue Diff" not in report

    def test_report_ends_with_newline(self):
        base = _catalog_diff_base()
        base["queue_diff"] = diff_review_queues(None, _queue([]))
        report = render_markdown_report(base)
        assert report.endswith("\n")
