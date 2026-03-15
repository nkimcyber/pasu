"""Tests for app/confidence.py — confidence derivation model.

Covers:
- All three confidence_logic strategies: all-high, weakest, majority
- Optional signal support: raises base by one step when all optional are high
- Optional evidence never lowers confidence below the required-only base
- Unknown actions excluded (structural guarantee documented via interface test)
- ConfidenceDerivation fields: final, base, raised_by_optional, explanation
- Determinism: same inputs always produce the same output
- Explanation strings: format and key content
"""

from __future__ import annotations

import pytest

from app.confidence import (
    CONFIDENCE_LEVELS,
    CONFIDENCE_ORDER,
    ConfidenceDerivation,
    derive_confidence,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_confidence_levels_contains_expected_values(self):
        assert CONFIDENCE_LEVELS == frozenset({"high", "medium", "low"})

    def test_confidence_levels_is_frozenset(self):
        assert isinstance(CONFIDENCE_LEVELS, frozenset)

    def test_confidence_order_is_ascending(self):
        assert CONFIDENCE_ORDER == ("low", "medium", "high")


# ---------------------------------------------------------------------------
# derive_confidence — all-high strategy
# ---------------------------------------------------------------------------

class TestAllHighStrategy:
    """Sprint minimum: two distinct confidence outcomes for all-high."""

    # Outcome 1: high
    def test_all_required_high_returns_high(self):
        result = derive_confidence("all-high", ["high", "high"])
        assert result.final == "high"

    # Outcome 2: medium (degraded)
    def test_one_medium_required_degrades_to_medium(self):
        result = derive_confidence("all-high", ["high", "high", "medium"])
        assert result.final == "medium"

    def test_one_low_required_degrades_to_low(self):
        result = derive_confidence("all-high", ["high", "low"])
        assert result.final == "low"

    def test_single_high_required_returns_high(self):
        assert derive_confidence("all-high", ["high"]).final == "high"

    def test_single_medium_required_returns_medium(self):
        assert derive_confidence("all-high", ["medium"]).final == "medium"

    def test_base_equals_final_when_no_optional(self):
        result = derive_confidence("all-high", ["high", "medium"])
        assert result.base == result.final

    def test_raised_by_optional_false_when_no_optional(self):
        result = derive_confidence("all-high", ["high"])
        assert result.raised_by_optional is False


# ---------------------------------------------------------------------------
# derive_confidence — weakest strategy
# ---------------------------------------------------------------------------

class TestWeakestStrategy:
    """Sprint minimum: two distinct confidence outcomes for weakest."""

    # Outcome 1: high
    def test_all_high_returns_high(self):
        result = derive_confidence("weakest", ["high", "high", "high"])
        assert result.final == "high"

    # Outcome 2: low (degraded)
    def test_any_low_returns_low(self):
        result = derive_confidence("weakest", ["high", "high", "low"])
        assert result.final == "low"

    def test_mix_high_medium_returns_medium(self):
        assert derive_confidence("weakest", ["high", "medium"]).final == "medium"

    def test_single_medium_returns_medium(self):
        assert derive_confidence("weakest", ["medium"]).final == "medium"

    def test_empty_required_returns_medium_fallback(self):
        result = derive_confidence("weakest", [])
        assert result.final == "medium"

    def test_base_equals_final_when_no_optional(self):
        result = derive_confidence("weakest", ["medium"])
        assert result.base == result.final


# ---------------------------------------------------------------------------
# derive_confidence — majority strategy
# ---------------------------------------------------------------------------

class TestMajorityStrategy:
    """Sprint minimum: two distinct confidence outcomes for majority."""

    # Outcome 1: high
    def test_strict_majority_high_returns_high(self):
        result = derive_confidence("majority", ["high", "high", "medium"])
        assert result.final == "high"

    # Outcome 2: medium (not a majority)
    def test_less_than_majority_high_returns_medium(self):
        result = derive_confidence("majority", ["high", "medium", "medium"])
        assert result.final == "medium"

    def test_exact_half_is_not_a_majority(self):
        # 1 of 2 = 50%, not strictly > 50%.
        result = derive_confidence("majority", ["high", "medium"])
        assert result.final == "medium"

    def test_all_medium_returns_medium(self):
        assert derive_confidence("majority", ["medium", "medium"]).final == "medium"

    def test_all_high_returns_high(self):
        assert derive_confidence("majority", ["high", "high"]).final == "high"

    def test_majority_never_returns_low(self):
        # The majority strategy always produces high or medium, never low.
        result = derive_confidence("majority", ["high", "low", "low"])
        assert result.final in {"high", "medium"}


# ---------------------------------------------------------------------------
# Optional signal support: raises, never lowers
# ---------------------------------------------------------------------------

class TestOptionalSignalSupport:
    def test_all_optional_high_raises_medium_base_to_high(self):
        """Sprint minimum: optional evidence raises base from medium to high."""
        result = derive_confidence("weakest", ["medium"], ["high"])
        assert result.base == "medium"
        assert result.final == "high"
        assert result.raised_by_optional is True

    def test_all_optional_high_raises_low_base_to_medium(self):
        """One-step raise: low → medium, not low → high."""
        result = derive_confidence("weakest", ["low"], ["high", "high"])
        assert result.base == "low"
        assert result.final == "medium"
        assert result.raised_by_optional is True

    def test_optional_high_does_not_change_high_base(self):
        """Sprint minimum: optional evidence does not change an already-high result."""
        result = derive_confidence("weakest", ["high"], ["high"])
        assert result.base == "high"
        assert result.final == "high"
        assert result.raised_by_optional is False

    def test_optional_medium_does_not_raise_medium_base(self):
        """Only ALL-high optional evidence provides a boost."""
        result = derive_confidence("weakest", ["medium"], ["medium"])
        assert result.final == "medium"
        assert result.raised_by_optional is False

    def test_optional_low_does_not_lower_high_base(self):
        """Core invariant: optional low evidence must never lower confidence."""
        result = derive_confidence("weakest", ["high"], ["low"])
        assert result.final == "high"
        assert result.raised_by_optional is False

    def test_optional_low_does_not_lower_medium_base(self):
        result = derive_confidence("weakest", ["medium"], ["low"])
        assert result.final == "medium"
        assert result.raised_by_optional is False

    def test_mixed_optional_does_not_boost(self):
        """A mix of optional confidences (not all high) provides no boost."""
        result = derive_confidence("weakest", ["medium"], ["high", "medium"])
        assert result.final == "medium"
        assert result.raised_by_optional is False

    def test_empty_optional_no_boost(self):
        result = derive_confidence("weakest", ["medium"], [])
        assert result.final == "medium"
        assert result.raised_by_optional is False

    def test_none_optional_treated_as_empty(self):
        result = derive_confidence("weakest", ["medium"], None)
        assert result.final == "medium"
        assert result.raised_by_optional is False

    def test_all_high_strategy_with_optional_raise(self):
        """Optional boost applies regardless of the logic strategy."""
        # all-high: required all high → base = high; optional can't raise above high.
        result = derive_confidence("all-high", ["high"], ["high"])
        assert result.final == "high"
        assert result.raised_by_optional is False  # was already high

    def test_majority_strategy_with_optional_raise(self):
        # majority: required not majority high → base = medium; all-optional-high → raise
        result = derive_confidence("majority", ["high", "medium"], ["high"])
        assert result.base == "medium"
        assert result.final == "high"
        assert result.raised_by_optional is True


# ---------------------------------------------------------------------------
# Unknown action exclusion (structural interface test)
# ---------------------------------------------------------------------------

class TestUnknownActionExclusion:
    """Confidence derivation accepts strings, not action results.

    The guarantee that unknown actions are excluded is structural: the
    function signature only accepts pre-extracted confidence strings.
    Callers (evaluate_composite_rules) are responsible for filtering to
    is_confirmed_risky=True before passing strings.  These tests document
    that the interface enforces the boundary.
    """

    def test_required_confidences_are_plain_strings(self):
        """Function accepts only strings — no ClassificationLookupResult objects."""
        result = derive_confidence("weakest", ["high"])
        assert isinstance(result.final, str)

    def test_confidence_strings_are_from_valid_scale(self):
        """All returned confidence values must be on the defined scale."""
        for logic in ("all-high", "weakest", "majority"):
            for conf in ("high", "medium", "low"):
                result = derive_confidence(logic, [conf])
                assert result.final in CONFIDENCE_LEVELS, (
                    f"Unexpected final confidence {result.final!r} for "
                    f"logic={logic!r}, input={conf!r}"
                )

    def test_adding_extra_string_cannot_raise_unilaterally(self):
        """An arbitrary extra 'high' in required_confidences does not change
        a conclusion that is already fully determined by the others."""
        base_result = derive_confidence("all-high", ["medium"])
        extra_result = derive_confidence("all-high", ["medium", "high"])
        # all-high: medium present → both must be medium (weakest of [medium, high])
        assert base_result.final == "medium"
        assert extra_result.final == "medium"


# ---------------------------------------------------------------------------
# ConfidenceDerivation dataclass contract
# ---------------------------------------------------------------------------

class TestConfidenceDerivationType:
    def test_returns_confidence_derivation_instance(self):
        result = derive_confidence("weakest", ["high"])
        assert isinstance(result, ConfidenceDerivation)

    def test_is_frozen(self):
        result = derive_confidence("weakest", ["high"])
        with pytest.raises((AttributeError, TypeError)):
            result.final = "low"  # type: ignore[misc]

    def test_required_confidences_is_tuple(self):
        result = derive_confidence("weakest", ["high", "medium"])
        assert isinstance(result.required_confidences, tuple)

    def test_optional_confidences_is_tuple(self):
        result = derive_confidence("weakest", ["high"], ["high"])
        assert isinstance(result.optional_confidences, tuple)

    def test_required_confidences_are_sorted_ascending(self):
        """Inputs are normalised to ascending order (low first) for determinism."""
        result = derive_confidence("weakest", ["high", "low", "medium"])
        assert list(result.required_confidences) == sorted(
            result.required_confidences,
            key=lambda c: {"low": 0, "medium": 1, "high": 2}.get(c, 1),
        )

    def test_base_is_always_a_valid_confidence(self):
        for conf_list in [["high"], ["medium"], ["low"], ["high", "low"]]:
            result = derive_confidence("weakest", conf_list)
            assert result.base in CONFIDENCE_LEVELS

    def test_final_is_always_a_valid_confidence(self):
        for conf_list in [["high"], ["medium"], ["low"]]:
            result = derive_confidence("weakest", conf_list)
            assert result.final in CONFIDENCE_LEVELS

    def test_logic_field_matches_input(self):
        for logic in ("all-high", "weakest", "majority"):
            result = derive_confidence(logic, ["high"])
            assert result.logic == logic

    def test_raised_by_optional_is_bool(self):
        result = derive_confidence("weakest", ["medium"], ["high"])
        assert isinstance(result.raised_by_optional, bool)


# ---------------------------------------------------------------------------
# Explanation strings
# ---------------------------------------------------------------------------

class TestExplanationStrings:
    def test_explanation_is_non_empty_string(self):
        result = derive_confidence("weakest", ["high"])
        assert isinstance(result.explanation, str)
        assert result.explanation.strip()

    def test_explanation_contains_logic_name(self):
        for logic in ("all-high", "weakest", "majority"):
            result = derive_confidence(logic, ["high"])
            assert logic in result.explanation, (
                f"Expected {logic!r} in explanation: {result.explanation!r}"
            )

    def test_explanation_contains_final_confidence(self):
        result = derive_confidence("weakest", ["medium"])
        assert "medium" in result.explanation

    def test_explanation_mentions_optional_boost_when_raised(self):
        result = derive_confidence("weakest", ["medium"], ["high"])
        assert "optional" in result.explanation.lower()

    def test_explanation_does_not_mention_optional_when_no_boost(self):
        result = derive_confidence("weakest", ["high"])
        assert "optional" not in result.explanation.lower()

    def test_explanation_arrow_format(self):
        """Explanation must end with '→ <confidence>' for CLI parsing."""
        result = derive_confidence("weakest", ["high"])
        assert "→" in result.explanation


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_same_inputs_same_output(self):
        r1 = derive_confidence("weakest", ["high", "medium"])
        r2 = derive_confidence("weakest", ["high", "medium"])
        assert r1 == r2

    def test_input_order_does_not_affect_final(self):
        """Confidence is commutative — order of input list should not matter."""
        r1 = derive_confidence("weakest", ["high", "low", "medium"])
        r2 = derive_confidence("weakest", ["medium", "high", "low"])
        assert r1.final == r2.final

    def test_input_order_does_not_affect_majority_result(self):
        r1 = derive_confidence("majority", ["high", "high", "medium"])
        r2 = derive_confidence("majority", ["medium", "high", "high"])
        assert r1.final == r2.final
