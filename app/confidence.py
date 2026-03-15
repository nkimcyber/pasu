"""Confidence derivation model for composite detection findings.

This module formalises *how* an overall finding confidence is computed from
the raw evidence available when a composite rule fires.  It is the single
authoritative source for that logic and is imported by the matching engine
(:mod:`app.composite_engine`) and by the CLI output layer.

Confidence inputs
-----------------
Three categories of evidence feed into the derivation:

**Classification confidence** (primary)
    Each reviewed action classification record carries a ``confidence``
    field (``"high"``, ``"medium"``, or ``"low"``).  This reflects how
    certain the human reviewer was that the action belongs to its assigned
    capability.  When multiple required-capability actions contribute to a
    finding, their individual confidence values are aggregated according to
    the rule's ``confidence_logic`` strategy.

**Required-capability completeness** (threshold gate)
    A rule fires only when *all* required capabilities are confirmed present.
    Completeness is therefore binary: either every required capability has at
    least one confirmed action, or the rule does not fire at all.  There is
    no partial-match score; completeness is not a continuous input.

**Optional signal support** (one-step boost)
    Optional capabilities provide supplementary evidence that the detected
    pattern is real.  When *all* matched optional capability actions carry
    ``confidence="high"``, the overall finding confidence is raised by one
    step on the output scale — but only one step, and only upward.  Optional
    evidence can never *lower* a finding below the required-capability
    baseline.

Confidence output scale
-----------------------
The output is one of three ordered values::

    low  <  medium  <  high

The mapping from strategies to outcomes:

``"all-high"``
    The final confidence is ``"high"`` only when every required-capability
    action has ``confidence="high"``.  If any required action has ``"medium"``
    or ``"low"`` confidence, the result is the weakest confidence seen among
    the required actions.  Rationale: this strategy flags patterns where the
    evidence quality must be unambiguous to avoid false positives.

``"weakest"``
    The final confidence equals the lowest individual confidence among the
    required-capability actions.  One ``"low"`` classification anywhere in
    the required evidence degrades the whole finding to ``"low"``.
    Rationale: chains are only as strong as their weakest link.

``"majority"``
    The final confidence is ``"high"`` when strictly more than half of the
    required-capability actions carry ``confidence="high"``; otherwise
    ``"medium"``.  (The result is never ``"low"`` from this strategy alone —
    a majority finding is either confident or inconclusive.)  Rationale: for
    broad patterns with several contributing actions, one weak entry should
    not invalidate otherwise strong evidence.

When confidence must be lowered
---------------------------------
- **Any required action classified at low confidence** causes the final
  result to be at most ``"low"`` under ``"all-high"`` and ``"weakest"``.
- **Fewer than a strict majority of required actions at high confidence**
  causes a ``"majority"`` rule to return ``"medium"``.
- **Missing optional evidence** never lowers confidence below what the
  required evidence alone yields.

Unknown-action exclusion guarantee
------------------------------------
:func:`derive_confidence` accepts confidence strings, not raw action keys or
classification records.  Its callers (:func:`~app.composite_engine.evaluate_composite_rules`)
are responsible for pre-filtering to only ``is_confirmed_risky=True`` results
before extracting confidence values.  This means:

- Unknown actions (``found=False``) contribute no confidence strings.
- Not-applicable actions (``status="not-applicable"``) contribute no strings.
- Neither category can appear in *required_confidences* or
  *optional_confidences*.  There is no code path through which an unknown
  action can raise, lower, or otherwise affect a finding's confidence.

CLI transparency
----------------
Every :class:`ConfidenceDerivation` carries a plain-English ``explanation``
string, e.g.::

    "all-high: all 2 required actions have high confidence → high"
    "weakest: lowest required confidence is medium → medium"
    "weakest: required confidence medium; raised by 1 high-confidence optional action → high"
    "majority: 2 of 3 required actions have high confidence → high"

This string is intended for direct use in ``--verbose`` CLI output and
human-readable reports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

# ---------------------------------------------------------------------------
# Scale constants
# ---------------------------------------------------------------------------

#: All valid confidence level strings, as a frozenset for O(1) membership.
CONFIDENCE_LEVELS: Final[frozenset[str]] = frozenset({"high", "medium", "low"})

#: Ordered from weakest to strongest.  Index is the numeric rank.
CONFIDENCE_ORDER: Final[tuple[str, ...]] = ("low", "medium", "high")

_RANK: Final[dict[str, int]] = {c: i for i, c in enumerate(CONFIDENCE_ORDER)}

# One-step raise table used by optional signal support.
_STEP_UP: Final[dict[str, str]] = {"low": "medium", "medium": "high", "high": "high"}


# ---------------------------------------------------------------------------
# Output type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConfidenceDerivation:
    """Fully traced confidence result for one composite detection finding.

    Carries both the final answer and enough intermediate state for the CLI
    (or any audit tool) to reproduce or explain the computation.

    Attributes:
        final:                   The derived confidence level: ``"high"``,
                                 ``"medium"``, or ``"low"``.
        base:                    Confidence derived from required-capability
                                 actions only, before optional signal boost.
                                 Equals ``final`` when no optional boost was
                                 applied.
        logic:                   The ``confidence_logic`` strategy used
                                 (``"all-high"``, ``"weakest"``, or
                                 ``"majority"``).
        raised_by_optional:      ``True`` when optional signal support raised
                                 ``final`` above ``base``.
        required_confidences:    Sorted tuple of confidence strings from the
                                 required-capability actions, in the order
                                 used for derivation.  May be empty only in
                                 the defensive fallback case.
        optional_confidences:    Sorted tuple of confidence strings from the
                                 matched optional-capability actions.  Empty
                                 tuple when no optional capabilities fired.
        explanation:             Single human-readable sentence describing the
                                 derivation.  Suitable for CLI ``--verbose``
                                 output and security reports.
    """

    final: str
    base: str
    logic: str
    raised_by_optional: bool
    required_confidences: tuple[str, ...]
    optional_confidences: tuple[str, ...]
    explanation: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _apply_logic(logic: str, confidences: list[str]) -> str:
    """Apply a ``confidence_logic`` strategy to a list of confidence strings.

    Args:
        logic:       One of ``"all-high"``, ``"weakest"``, ``"majority"``.
        confidences: Non-empty list of confidence strings.

    Returns:
        One of ``"high"``, ``"medium"``, or ``"low"``.
    """
    if not confidences:
        return "medium"

    if logic == "all-high":
        if all(c == "high" for c in confidences):
            return "high"
        return min(confidences, key=lambda c: _RANK.get(c, 1))

    if logic == "weakest":
        return min(confidences, key=lambda c: _RANK.get(c, 1))

    if logic == "majority":
        high_count = sum(1 for c in confidences if c == "high")
        return "high" if high_count > len(confidences) / 2 else "medium"

    return "medium"  # unreachable when confidence_logic has been validated


def _build_explanation(
    logic: str,
    base: str,
    final: str,
    required_confidences: tuple[str, ...],
    optional_confidences: tuple[str, ...],
    raised_by_optional: bool,
) -> str:
    """Construct a one-sentence explanation for a confidence derivation.

    Args:
        logic:                The strategy name.
        base:                 Confidence from required actions only.
        final:                The final confidence after optional boost.
        required_confidences: Sorted confidence values from required actions.
        optional_confidences: Sorted confidence values from optional actions.
        raised_by_optional:   Whether optional evidence raised the result.

    Returns:
        A human-readable string, e.g.
        ``"weakest: lowest required confidence is medium → medium"``
    """
    n_req = len(required_confidences)

    if not required_confidences:
        return f"{logic}: no required-action evidence available → {final} (fallback)"

    # ── Required-side phrase ──────────────────────────────────────────────────
    if logic == "all-high":
        if base == "high":
            req_phrase = f"all {n_req} required action(s) have high confidence"
        else:
            req_phrase = (
                f"required confidence degraded to {base!r} "
                f"(weakest of {sorted(set(required_confidences))})"
            )
    elif logic == "weakest":
        req_phrase = f"lowest required confidence is {base!r} (of {sorted(set(required_confidences))})"
    elif logic == "majority":
        high_count = sum(1 for c in required_confidences if c == "high")
        req_phrase = f"{high_count} of {n_req} required action(s) have high confidence"
    else:
        req_phrase = f"required evidence → {base!r}"

    # ── Optional-side phrase ──────────────────────────────────────────────────
    if raised_by_optional:
        n_opt = len(optional_confidences)
        opt_phrase = f"; raised by {n_opt} high-confidence optional action(s)"
        return f"{logic}: {req_phrase}{opt_phrase} → {final}"

    return f"{logic}: {req_phrase} → {final}"


# ---------------------------------------------------------------------------
# Public derivation function
# ---------------------------------------------------------------------------

def derive_confidence(
    logic: str,
    required_confidences: list[str],
    optional_confidences: list[str] | None = None,
) -> ConfidenceDerivation:
    """Derive overall finding confidence from classified action evidence.

    The derivation proceeds in two stages:

    1. **Base stage** — apply *logic* to *required_confidences* only.
    2. **Optional boost** — if every confidence in *optional_confidences* is
       ``"high"`` (and the list is non-empty), raise the base by one step.
       Optional evidence can never lower the result below the base.

    Unknown or unreviewed actions must not appear in either list.  Callers
    are responsible for filtering to confirmed-risky actions before extracting
    confidence strings (see :func:`~app.composite_engine.evaluate_composite_rules`).

    Args:
        logic:                 The rule's ``confidence_logic`` value.  One of
                               ``"all-high"``, ``"weakest"``, ``"majority"``.
        required_confidences:  Confidence strings from actions that provided
                               required capabilities.  Each string must be
                               ``"high"``, ``"medium"``, or ``"low"``.
        optional_confidences:  Confidence strings from actions that provided
                               matched optional capabilities.  May be empty
                               or ``None``.  These can only raise the base
                               confidence — never lower it.

    Returns:
        A :class:`ConfidenceDerivation` with the final confidence level,
        intermediate state, and a human-readable explanation.

    Examples::

        >>> derive_confidence("weakest", ["high", "high"]).final
        'high'
        >>> derive_confidence("weakest", ["high", "low"]).final
        'low'
        >>> derive_confidence("all-high", ["high", "high"], ["high"]).final
        'high'
        >>> derive_confidence("weakest", ["medium"], ["high"]).final
        'high'
        >>> derive_confidence("weakest", ["medium"], ["low"]).final
        'medium'
    """
    opt = list(optional_confidences) if optional_confidences else []

    # Sort both lists for deterministic behaviour independent of input order.
    sorted_req = tuple(sorted(required_confidences, key=lambda c: _RANK.get(c, 1)))
    sorted_opt = tuple(sorted(opt, key=lambda c: _RANK.get(c, 1)))

    # Stage 1: base from required evidence.
    base = _apply_logic(logic, list(sorted_req))

    # Stage 2: optional boost — raise by one step when ALL optional are high.
    raised_by_optional = False
    if sorted_opt and all(c == "high" for c in sorted_opt):
        boosted = _STEP_UP.get(base, base)
        if boosted != base:
            raised_by_optional = True
        final = boosted
    else:
        final = base

    explanation = _build_explanation(
        logic, base, final, sorted_req, sorted_opt, raised_by_optional
    )

    return ConfidenceDerivation(
        final=final,
        base=base,
        logic=logic,
        raised_by_optional=raised_by_optional,
        required_confidences=sorted_req,
        optional_confidences=sorted_opt,
        explanation=explanation,
    )
