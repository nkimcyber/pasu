"""Tests for app/review_status.py.

Covers:
- ReviewStatus enum membership and string equality
- validate_status: accepts all valid values, rejects unknown labels
- validate_transition: permits legal moves, rejects illegal ones
- Metadata completeness (descriptions, valid_contexts, allowed_transitions)
- Integration: generate_review_queue emits ReviewStatus values
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from app.review_status import (
    ALLOWED_TRANSITIONS,
    DESCRIPTIONS,
    VALID_CONTEXTS,
    ReviewStatus,
    validate_status,
    validate_transition,
)

# ---------------------------------------------------------------------------
# ReviewStatus enum
# ---------------------------------------------------------------------------

class TestReviewStatusEnum:
    def test_all_five_members_exist(self):
        values = {s.value for s in ReviewStatus}
        assert values == {
            "unclassified",
            "classified",
            "deferred",
            "needs-research",
            "not-applicable",
        }

    def test_str_mixin_equality_with_string(self):
        assert ReviewStatus.UNCLASSIFIED == "unclassified"
        assert ReviewStatus.CLASSIFIED == "classified"
        assert ReviewStatus.DEFERRED == "deferred"
        assert ReviewStatus.NEEDS_RESEARCH == "needs-research"
        assert ReviewStatus.NOT_APPLICABLE == "not-applicable"

    def test_string_equality_is_symmetric(self):
        assert "unclassified" == ReviewStatus.UNCLASSIFIED

    def test_members_are_distinct(self):
        members = list(ReviewStatus)
        assert len(members) == len({m.value for m in members})


# ---------------------------------------------------------------------------
# validate_status — valid inputs
# ---------------------------------------------------------------------------

class TestValidateStatusAccepts:
    @pytest.mark.parametrize("value,expected", [
        ("unclassified",   ReviewStatus.UNCLASSIFIED),
        ("classified",     ReviewStatus.CLASSIFIED),
        ("deferred",       ReviewStatus.DEFERRED),
        ("needs-research", ReviewStatus.NEEDS_RESEARCH),
        ("not-applicable", ReviewStatus.NOT_APPLICABLE),
    ])
    def test_accepts_all_valid_strings(self, value: str, expected: ReviewStatus):
        assert validate_status(value) is expected

    def test_returns_review_status_instance(self):
        result = validate_status("classified")
        assert isinstance(result, ReviewStatus)

    def test_accepts_enum_member_passed_as_string(self):
        # ReviewStatus is a str subclass; passing a member directly must work
        assert validate_status(ReviewStatus.DEFERRED) is ReviewStatus.DEFERRED


# ---------------------------------------------------------------------------
# validate_status — invalid inputs (enforcement)
# ---------------------------------------------------------------------------

class TestValidateStatusRejects:
    @pytest.mark.parametrize("bad_value", [
        "pending",
        "done",
        "skipped",
        "approved",
        "rejected",
        "in-progress",
        "unknown",
        "",
        "UNCLASSIFIED",        # wrong case
        "Unclassified",        # wrong case
        "needs_research",      # underscore instead of hyphen
        "not_applicable",      # underscore instead of hyphen
        "classified ",         # trailing space
        " unclassified",       # leading space
    ])
    def test_rejects_unknown_label(self, bad_value: str):
        with pytest.raises(ValueError):
            validate_status(bad_value)

    def test_error_message_lists_allowed_values(self):
        with pytest.raises(ValueError, match="unclassified"):
            validate_status("bogus")

    def test_error_message_contains_rejected_value(self):
        with pytest.raises(ValueError, match="bogus"):
            validate_status("bogus")


# ---------------------------------------------------------------------------
# validate_transition — permitted moves
# ---------------------------------------------------------------------------

class TestValidateTransitionPermitted:
    @pytest.mark.parametrize("from_s,to_s", [
        ("unclassified",   "classified"),
        ("unclassified",   "deferred"),
        ("unclassified",   "needs-research"),
        ("unclassified",   "not-applicable"),
        ("classified",     "needs-research"),
        ("classified",     "not-applicable"),
        ("deferred",       "unclassified"),
        ("deferred",       "classified"),
        ("deferred",       "not-applicable"),
        ("needs-research", "unclassified"),
        ("needs-research", "classified"),
        ("needs-research", "not-applicable"),
        ("not-applicable", "unclassified"),
    ])
    def test_legal_transition_does_not_raise(self, from_s: str, to_s: str):
        validate_transition(from_s, to_s)  # must not raise

    def test_accepts_enum_members_directly(self):
        validate_transition(ReviewStatus.UNCLASSIFIED, ReviewStatus.CLASSIFIED)


# ---------------------------------------------------------------------------
# validate_transition — forbidden moves
# ---------------------------------------------------------------------------

class TestValidateTransitionForbidden:
    @pytest.mark.parametrize("from_s,to_s", [
        # self-transitions are not listed as allowed
        ("unclassified",   "unclassified"),
        ("classified",     "classified"),
        ("deferred",       "deferred"),
        ("needs-research", "needs-research"),
        ("not-applicable", "not-applicable"),
        # specific illegal forward paths
        ("classified",     "unclassified"),    # can't go back to start
        ("classified",     "deferred"),        # can't defer after classifying
        ("not-applicable", "classified"),      # can't classify without unclassifying first
        ("not-applicable", "deferred"),
        ("not-applicable", "needs-research"),
    ])
    def test_illegal_transition_raises(self, from_s: str, to_s: str):
        with pytest.raises(ValueError):
            validate_transition(from_s, to_s)

    def test_error_message_names_both_statuses(self):
        with pytest.raises(ValueError, match="not-applicable"):
            validate_transition("not-applicable", "classified")

    def test_error_message_lists_permitted_next_states(self):
        with pytest.raises(ValueError, match="unclassified"):
            validate_transition("not-applicable", "classified")

    def test_invalid_current_status_raises(self):
        with pytest.raises(ValueError):
            validate_transition("bogus", "classified")

    def test_invalid_next_status_raises(self):
        with pytest.raises(ValueError):
            validate_transition("unclassified", "bogus")


# ---------------------------------------------------------------------------
# Metadata completeness
# ---------------------------------------------------------------------------

class TestMetadataCompleteness:
    def test_descriptions_covers_all_statuses(self):
        assert set(DESCRIPTIONS.keys()) == set(ReviewStatus)

    def test_descriptions_are_non_empty_strings(self):
        for status, desc in DESCRIPTIONS.items():
            assert isinstance(desc, str) and len(desc) > 10, (
                f"Description for {status!r} is too short or missing"
            )

    def test_valid_contexts_covers_all_statuses(self):
        assert set(VALID_CONTEXTS.keys()) == set(ReviewStatus)

    def test_valid_contexts_values_are_frozensets_of_strings(self):
        for status, contexts in VALID_CONTEXTS.items():
            assert isinstance(contexts, frozenset), f"{status!r} contexts is not a frozenset"
            for ctx in contexts:
                assert isinstance(ctx, str)

    def test_allowed_transitions_covers_all_statuses(self):
        assert set(ALLOWED_TRANSITIONS.keys()) == set(ReviewStatus)

    def test_allowed_transitions_values_are_frozensets_of_review_status(self):
        for status, nexts in ALLOWED_TRANSITIONS.items():
            assert isinstance(nexts, frozenset), f"{status!r} transitions is not a frozenset"
            for next_s in nexts:
                assert isinstance(next_s, ReviewStatus), (
                    f"Transition target {next_s!r} for {status!r} is not a ReviewStatus"
                )

    def test_unclassified_valid_only_in_review_queue(self):
        assert VALID_CONTEXTS[ReviewStatus.UNCLASSIFIED] == frozenset({"review_queue"})

    def test_classified_valid_in_both_contexts(self):
        assert "review_queue" in VALID_CONTEXTS[ReviewStatus.CLASSIFIED]
        assert "classification" in VALID_CONTEXTS[ReviewStatus.CLASSIFIED]

    def test_not_applicable_valid_in_both_contexts(self):
        assert "review_queue" in VALID_CONTEXTS[ReviewStatus.NOT_APPLICABLE]
        assert "classification" in VALID_CONTEXTS[ReviewStatus.NOT_APPLICABLE]

    def test_deferred_and_needs_research_only_in_review_queue(self):
        for status in (ReviewStatus.DEFERRED, ReviewStatus.NEEDS_RESEARCH):
            assert VALID_CONTEXTS[status] == frozenset({"review_queue"})


# ---------------------------------------------------------------------------
# Integration: generate_review_queue uses ReviewStatus
# ---------------------------------------------------------------------------

class TestGeneratorUsesReviewStatus:
    """Ensure the queue generator emits ReviewStatus values (not bare strings)."""

    def _setup(self):
        scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
        if str(scripts_dir) not in sys.path:
            sys.path.insert(0, str(scripts_dir))
        from sync_aws_catalog import generate_review_queue
        return generate_review_queue

    def test_generated_status_is_review_status_instance(self):
        generate_review_queue = self._setup()
        catalog = {
            "version": 1,
            "generated_at": "2026-03-14T17:22:09+00:00",
            "source": {"name": "AWS Service Authorization Reference"},
            "actions": {
                "iam:CreateUser": {
                    "service": "iam", "name": "CreateUser",
                    "access_level": "Write",
                    "resource_types": [], "condition_keys": [], "dependent_actions": [],
                }
            },
        }
        result = generate_review_queue(catalog, classified_actions=set())
        status_value = result["items"][0]["status"]
        # Must be a ReviewStatus (str subclass), not a plain unknown string
        assert isinstance(status_value, ReviewStatus), (
            f"Expected ReviewStatus, got {type(status_value)}"
        )
        assert status_value == ReviewStatus.UNCLASSIFIED

    def test_generated_status_validates_cleanly(self):
        generate_review_queue = self._setup()
        catalog = {
            "version": 1,
            "generated_at": "2026-03-14T17:22:09+00:00",
            "source": {"name": "AWS Service Authorization Reference"},
            "actions": {
                "s3:ListBuckets": {
                    "service": "s3", "name": "ListBuckets",
                    "access_level": "List",
                    "resource_types": [], "condition_keys": [], "dependent_actions": [],
                }
            },
        }
        result = generate_review_queue(catalog, classified_actions=set())
        # validate_status must accept whatever the generator emits without error
        validated = validate_status(result["items"][0]["status"])
        assert validated is ReviewStatus.UNCLASSIFIED
