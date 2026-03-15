"""Tests for the unknown-action safe-handling guard.

Core invariant: an AWS action that is absent from the classification file
must never be auto-promoted to a risky finding.  These tests prove that
``lookup_action`` and ``ClassificationLookupResult.is_confirmed_risky``
enforce that invariant unconditionally.

These tests are kept separate from the broader action_classification tests
so the guard's intent remains easy to audit on its own.
"""

from __future__ import annotations

import pytest

from app.action_classification import (
    ClassificationLookupResult,
    load_action_classification,
    lookup_action,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

# A minimal classification dict that covers all result types.
_CLASSIFICATION: dict = {
    "iam:PassRole": {
        "status": "classified",
        "capabilities": ["privilege-delegation"],
        "confidence": "high",
        "notes": "Core privilege escalation primitive.",
    },
    "ec2:DescribeInstances": {
        "status": "not-applicable",
        "capabilities": [],
        "confidence": "high",
        "notes": "Read-only, no escalation path.",
    },
}

_UNKNOWN_KEYS = [
    "svc:NewUndocumentedAction",
    "iam:SomeHypotheticalFutureAction",
    "s3:NotYetReviewed",
    "ec2:RunInstances",        # real action, but absent from this fixture
    "",                         # empty string — definitely not a known action
    "totally:random",
]


# ---------------------------------------------------------------------------
# Unknown action: found=False
# ---------------------------------------------------------------------------

class TestUnknownActionNotFound:
    @pytest.mark.parametrize("key", _UNKNOWN_KEYS)
    def test_found_is_false_for_unknown_action(self, key: str):
        result = lookup_action(key, _CLASSIFICATION)
        assert result.found is False

    def test_record_is_none_for_unknown_action(self):
        result = lookup_action("svc:UnknownAction", _CLASSIFICATION)
        assert result.record is None

    def test_action_key_preserved_in_result(self):
        key = "svc:UnknownAction"
        result = lookup_action(key, _CLASSIFICATION)
        assert result.action == key


# ---------------------------------------------------------------------------
# Core guard: unknown action is NEVER promoted to risky
# ---------------------------------------------------------------------------

class TestUnknownActionNotPromoted:
    """This class contains the definitive guard tests.

    Each test documents one aspect of the 'unknown = not risky' rule.
    """

    @pytest.mark.parametrize("key", _UNKNOWN_KEYS)
    def test_is_confirmed_risky_false_for_unknown_action(self, key: str):
        """Primary guard test: absence of a record never implies risk."""
        result = lookup_action(key, _CLASSIFICATION)
        assert result.is_confirmed_risky is False, (
            f"Action {key!r} has no classification record and must not be "
            f"auto-promoted to risky. is_confirmed_risky must be False."
        )

    def test_unknown_action_capabilities_is_empty_list(self):
        result = lookup_action("svc:Unknown", _CLASSIFICATION)
        assert result.capabilities == []

    def test_unknown_action_status_is_none(self):
        result = lookup_action("svc:Unknown", _CLASSIFICATION)
        assert result.status is None

    def test_unknown_action_confidence_is_none(self):
        result = lookup_action("svc:Unknown", _CLASSIFICATION)
        assert result.confidence is None

    def test_empty_classification_dict_all_results_are_safe(self):
        """With no classification records at all, every action is unknown and safe."""
        empty: dict = {}
        for key in ["iam:PassRole", "ec2:RunInstances", "kms:Decrypt", "svc:Anything"]:
            result = lookup_action(key, empty)
            assert result.found is False
            assert result.is_confirmed_risky is False, (
                f"{key!r} must not be risky when no classification data is loaded"
            )

    def test_lookup_never_raises_for_unknown_key(self):
        """The guard function must not raise for unrecognised action keys."""
        # Would raise KeyError if implemented as dict[key] instead of dict.get(key)
        result = lookup_action("completely:Unknown", _CLASSIFICATION)
        assert result is not None


# ---------------------------------------------------------------------------
# Known classified action: found=True, is_confirmed_risky=True
# ---------------------------------------------------------------------------

class TestKnownClassifiedAction:
    def test_found_is_true(self):
        result = lookup_action("iam:PassRole", _CLASSIFICATION)
        assert result.found is True

    def test_is_confirmed_risky_true(self):
        result = lookup_action("iam:PassRole", _CLASSIFICATION)
        assert result.is_confirmed_risky is True

    def test_capabilities_returned(self):
        result = lookup_action("iam:PassRole", _CLASSIFICATION)
        assert result.capabilities == ["privilege-delegation"]

    def test_status_is_classified(self):
        result = lookup_action("iam:PassRole", _CLASSIFICATION)
        assert result.status == "classified"

    def test_confidence_returned(self):
        result = lookup_action("iam:PassRole", _CLASSIFICATION)
        assert result.confidence == "high"

    def test_record_is_not_none(self):
        result = lookup_action("iam:PassRole", _CLASSIFICATION)
        assert result.record is not None


# ---------------------------------------------------------------------------
# Known not-applicable action: found=True, is_confirmed_risky=False
# ---------------------------------------------------------------------------

class TestKnownNotApplicableAction:
    def test_found_is_true(self):
        result = lookup_action("ec2:DescribeInstances", _CLASSIFICATION)
        assert result.found is True

    def test_is_confirmed_risky_false(self):
        """not-applicable status must not be treated as risky."""
        result = lookup_action("ec2:DescribeInstances", _CLASSIFICATION)
        assert result.is_confirmed_risky is False

    def test_capabilities_is_empty(self):
        result = lookup_action("ec2:DescribeInstances", _CLASSIFICATION)
        assert result.capabilities == []

    def test_status_is_not_applicable(self):
        result = lookup_action("ec2:DescribeInstances", _CLASSIFICATION)
        assert result.status == "not-applicable"


# ---------------------------------------------------------------------------
# is_confirmed_risky logic: edge cases
# ---------------------------------------------------------------------------

class TestIsConfirmedRiskyEdgeCases:
    def test_classified_with_empty_capabilities_is_not_risky(self):
        """A 'classified' status with no capabilities list must not be risky.

        This state is invalid per validate_record, but the guard must be
        defensive in case the record dict is constructed outside the loader.
        """
        record = {
            "status": "classified",
            "capabilities": [],     # empty — normally rejected by validate_record
            "confidence": "high",
            "notes": "",
        }
        result = ClassificationLookupResult(
            action="svc:EdgeCase", found=True, record=record
        )
        assert result.is_confirmed_risky is False

    def test_found_false_with_record_provided_is_not_risky(self):
        """If found=False the record content is irrelevant — result must be safe."""
        record = {
            "status": "classified",
            "capabilities": ["secret-read"],
            "confidence": "high",
            "notes": "",
        }
        # Constructing an inconsistent result to verify the guard checks found first
        result = ClassificationLookupResult(
            action="svc:Inconsistent", found=False, record=record
        )
        assert result.is_confirmed_risky is False

    def test_result_is_immutable(self):
        """ClassificationLookupResult is frozen; callers cannot mutate it."""
        result = lookup_action("svc:Unknown", _CLASSIFICATION)
        with pytest.raises((AttributeError, TypeError)):
            result.found = True  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Integration: guard works against the real classification file
# ---------------------------------------------------------------------------

class TestGuardAgainstRealFile:
    def test_real_known_action_is_confirmed_risky(self):
        actions = load_action_classification()
        result = lookup_action("iam:PassRole", actions)
        assert result.found is True
        assert result.is_confirmed_risky is True

    def test_real_unknown_action_is_not_promoted(self):
        actions = load_action_classification()
        result = lookup_action("svc:TotallyFictionalAction", actions)
        assert result.found is False
        assert result.is_confirmed_risky is False

    def test_many_fabricated_actions_all_safe(self):
        """No matter how many unknown keys are queried, none become risky."""
        actions = load_action_classification()
        fabricated = [f"svc{i}:Action{i}" for i in range(50)]
        for key in fabricated:
            result = lookup_action(key, actions)
            assert result.is_confirmed_risky is False, (
                f"Fabricated key {key!r} must not be auto-promoted"
            )
