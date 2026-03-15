"""Matching engine for composite detection rules.

Evaluates a sequence of reviewed action classification results against the
loaded composite detection rules and returns findings for every rule whose
required capabilities are fully satisfied.

Separation of concerns
-----------------------
This module is the **only** place where composite rule matching logic lives.
It does not load rules or classification records from disk — those concerns
belong to :mod:`app.composite_detections` and
:mod:`app.action_classification` respectively.  Confidence derivation logic
lives exclusively in :mod:`app.confidence`.

Input contract
--------------
The engine accepts a sequence of
:class:`~app.action_classification.ClassificationLookupResult` objects.
Only results where :attr:`~app.action_classification.ClassificationLookupResult.is_confirmed_risky`
is ``True`` contribute evidence.  Results for unknown actions
(``found=False``) or ``not-applicable`` actions are silently ignored,
enforcing the invariant that unreviewed actions can never satisfy a
capability requirement or affect finding confidence.

Output contract
---------------
Returns a list of :class:`CompositeFinding` objects sorted by ``rule_id``.
The sort is deterministic regardless of the order rules were loaded or the
order actions appear in the input.  An empty list is returned when no rules
fire.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from app.action_classification import ClassificationLookupResult
from app.composite_detections import CompositeRule
from app.confidence import derive_confidence


# ---------------------------------------------------------------------------
# Finding type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CompositeFinding:
    """A single triggered composite detection finding.

    Produced by :func:`evaluate_composite_rules` when a rule's required
    capabilities are all satisfied by confirmed action classifications.

    Attributes:
        rule_id:                Stable rule identifier (e.g. ``"COMP-001"``).
        title:                  Human-readable rule title.
        severity:               Rule severity level (``"critical"``, ``"high"``,
                                ``"medium"``, or ``"low"``).
        confidence:             Overall confidence derived from the rule's
                                ``confidence_logic`` and the individual
                                classification confidences of contributing
                                actions.
        matched_required:       Frozenset of required capability names that
                                were matched.  Always equal to the rule's
                                ``required_capabilities`` when a finding fires.
        matched_optional:       Frozenset of optional capability names from
                                the rule that were also present in the input.
                                Empty frozenset when no optional capabilities
                                matched.
        contributing_actions:   Sorted tuple of IAM action keys whose confirmed
                                classifications provided the evidence that
                                triggered this finding.
        confidence_explanation: Human-readable sentence describing how
                                ``confidence`` was derived.  Suitable for
                                ``--verbose`` CLI output.  Empty string when
                                the finding was constructed outside the engine.
    """

    rule_id: str
    title: str
    severity: str
    confidence: str
    matched_required: frozenset[str]
    matched_optional: frozenset[str]
    contributing_actions: tuple[str, ...]
    confidence_explanation: str = field(default="")
    rationale: str = field(default="")


# ---------------------------------------------------------------------------
# Matching engine
# ---------------------------------------------------------------------------

def evaluate_composite_rules(
    action_results: Sequence[ClassificationLookupResult],
    rules: Sequence[CompositeRule],
) -> list[CompositeFinding]:
    """Evaluate confirmed action classifications against composite rules.

    Only actions with ``is_confirmed_risky=True`` contribute evidence.
    Unknown, unreviewed, or ``not-applicable`` actions are silently discarded
    before matching begins, so they can never satisfy a capability requirement
    or influence confidence.

    When the same action key appears more than once in *action_results* the
    first occurrence with ``is_confirmed_risky=True`` is used; subsequent
    duplicates are ignored.

    Confidence derivation separates required-capability evidence from
    optional-capability evidence:

    - Required-capability actions feed the primary derivation via the rule's
      ``confidence_logic`` strategy.
    - Optional-capability actions provide a one-step boost only when every
      matched optional action has ``confidence="high"``; otherwise optional
      evidence has no effect on the final result.
    - An action that contributes only to required capabilities is counted in
      the required pool; an action that contributes only to optional
      capabilities is counted in the optional pool.  An action that provides
      capabilities in both pools (rare, because rules forbid capability
      overlap) is counted in the required pool only.

    Args:
        action_results: Sequence of
            :class:`~app.action_classification.ClassificationLookupResult`
            objects produced by looking up each IAM action in the
            classification file.  May include unknown and non-risky entries.
        rules:          Sequence of :class:`~app.composite_detections.CompositeRule`
                        objects to evaluate against.  Normally the output of
                        :func:`~app.composite_detections.load_composite_detections`.

    Returns:
        Sorted list of :class:`CompositeFinding` objects — one per triggered
        rule — in ascending ``rule_id`` order.  Returns an empty list when
        no rules fire.
    """
    # ── Build capability → evidence maps from confirmed actions only ──────────
    seen_action_keys: set[str] = set()
    cap_to_actions: dict[str, set[str]] = {}   # capability → action keys
    action_confidence: dict[str, str] = {}      # action key → confidence

    for result in action_results:
        if not result.is_confirmed_risky:
            continue
        if result.action in seen_action_keys:
            continue
        seen_action_keys.add(result.action)

        conf = result.confidence or "medium"
        action_confidence[result.action] = conf
        for cap in result.capabilities:
            cap_to_actions.setdefault(cap, set()).add(result.action)

    confirmed_caps: frozenset[str] = frozenset(cap_to_actions)

    # ── Evaluate each rule ────────────────────────────────────────────────────
    findings: list[CompositeFinding] = []

    for rule in rules:
        required = frozenset(rule.required_capabilities)

        if not required.issubset(confirmed_caps):
            continue  # at least one required capability is absent — rule does not fire

        matched_optional = frozenset(rule.optional_capabilities) & confirmed_caps

        # Partition contributing action keys into required vs optional pools.
        # Rule validation guarantees required ∩ optional = ∅ at the capability
        # level, so an action is required-pool if any of its caps are required,
        # optional-pool otherwise.
        required_action_keys: set[str] = set()
        for cap in required:
            required_action_keys |= cap_to_actions.get(cap, set())

        optional_action_keys: set[str] = set()
        for cap in matched_optional:
            optional_action_keys |= cap_to_actions.get(cap, set())
        # Remove any action already counted in the required pool.
        optional_action_keys -= required_action_keys

        req_confidences = [action_confidence[k] for k in sorted(required_action_keys)]
        opt_confidences = [action_confidence[k] for k in sorted(optional_action_keys)]

        derivation = derive_confidence(rule.confidence_logic, req_confidences, opt_confidences)

        all_contributing = tuple(sorted(required_action_keys | optional_action_keys))

        findings.append(CompositeFinding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=derivation.final,
            matched_required=required,
            matched_optional=matched_optional,
            contributing_actions=all_contributing,
            confidence_explanation=derivation.explanation,
            rationale=rule.rationale,
        ))

    return sorted(findings, key=lambda f: f.rule_id)
