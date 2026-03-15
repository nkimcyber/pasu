"""Review lifecycle status for IAM action classification records.

This module is the **single source of truth** for allowed status values.
All code that reads or writes ``status`` fields on review queue items or
action classification records must import from here.  Do not invent
ad-hoc synonyms such as ``"pending"``, ``"done"``, or ``"skipped"``.

Lifecycle overview
------------------
Every action that enters the review pipeline starts as ``unclassified``.
A reviewer inspects the action and moves it to one of the terminal or
holding states below.  The diagram shows legal forward transitions::

    unclassified ──► classified
         │       ──► deferred
         │       ──► needs-research
         └───────►   not-applicable

    classified   ──► needs-research   (re-opened: taxonomy changed)
                 ──► not-applicable   (downgraded: scope changed)

    deferred     ──► unclassified     (re-activated in later cycle)
                 ──► classified
                 ──► not-applicable

    needs-research ──► unclassified   (reset after new information found)
                   ──► classified
                   ──► not-applicable

    not-applicable ──► unclassified   (re-opened: scope expanded)

Status meanings
---------------
unclassified
    Default entry state.  The action exists in the catalog but has not yet
    been reviewed or mapped to any capability.

classified
    Review complete.  The action has been mapped to one or more named
    capabilities in the classification layer.

deferred
    Review intentionally postponed.  The action is known but deprioritised
    for a future review cycle.

needs-research
    Blocked.  Insufficient public documentation or context is available to
    classify the action; further investigation is required before a decision
    can be made.

not-applicable
    Out of scope.  The action is not relevant to the IAM risk model and will
    not be classified (e.g. read-only metadata calls with no
    privilege-escalation path).

Valid contexts
--------------
+------------------+---------------+----------------+
| Status           | review_queue  | classification |
+==================+===============+================+
| unclassified     | ✓             |                |
| classified       | ✓             | ✓              |
| deferred         | ✓             |                |
| needs-research   | ✓             |                |
| not-applicable   | ✓             | ✓              |
+------------------+---------------+----------------+
"""

from __future__ import annotations

from enum import Enum
from typing import Final


class ReviewStatus(str, Enum):
    """Allowed lifecycle statuses for a review queue item or classification record.

    The ``str`` mixin ensures each member compares equal to its string value,
    making JSON round-trips transparent::

        >>> ReviewStatus.UNCLASSIFIED == "unclassified"
        True
        >>> "classified" == ReviewStatus.CLASSIFIED
        True
    """

    UNCLASSIFIED = "unclassified"
    CLASSIFIED = "classified"
    DEFERRED = "deferred"
    NEEDS_RESEARCH = "needs-research"
    NOT_APPLICABLE = "not-applicable"


# ---------------------------------------------------------------------------
# Descriptions
# ---------------------------------------------------------------------------

DESCRIPTIONS: Final[dict[ReviewStatus, str]] = {
    ReviewStatus.UNCLASSIFIED: (
        "Default entry state: the action exists in the catalog but has not yet been "
        "reviewed or mapped to any capability."
    ),
    ReviewStatus.CLASSIFIED: (
        "Review complete: the action has been mapped to one or more named capabilities "
        "in the classification layer."
    ),
    ReviewStatus.DEFERRED: (
        "Review intentionally postponed: the action is known but deprioritised for "
        "a future review cycle."
    ),
    ReviewStatus.NEEDS_RESEARCH: (
        "Blocked: insufficient public documentation or context is available to classify "
        "the action; further investigation is required before a decision can be made."
    ),
    ReviewStatus.NOT_APPLICABLE: (
        "Out of scope: the action is not relevant to the IAM risk model and will not "
        "be classified (e.g. read-only metadata calls with no privilege-escalation path)."
    ),
}


# ---------------------------------------------------------------------------
# Valid contexts
# ---------------------------------------------------------------------------

#: Contexts in which each status may appear.
#:
#: ``"review_queue"``   – items in ``app/data/review_queue.json``
#: ``"classification"`` – records in the action classification layer
VALID_CONTEXTS: Final[dict[ReviewStatus, frozenset[str]]] = {
    ReviewStatus.UNCLASSIFIED:   frozenset({"review_queue"}),
    ReviewStatus.CLASSIFIED:     frozenset({"review_queue", "classification"}),
    ReviewStatus.DEFERRED:       frozenset({"review_queue"}),
    ReviewStatus.NEEDS_RESEARCH: frozenset({"review_queue"}),
    ReviewStatus.NOT_APPLICABLE: frozenset({"review_queue", "classification"}),
}


# ---------------------------------------------------------------------------
# Allowed transitions
# ---------------------------------------------------------------------------

#: Legal forward transitions between statuses.
#:
#: Keys are the *current* status; values are the set of statuses the item
#: may move to.  Transitions not listed here are disallowed by convention;
#: callers that need enforcement should use :func:`validate_transition`.
ALLOWED_TRANSITIONS: Final[dict[ReviewStatus, frozenset[ReviewStatus]]] = {
    ReviewStatus.UNCLASSIFIED: frozenset({
        ReviewStatus.CLASSIFIED,
        ReviewStatus.DEFERRED,
        ReviewStatus.NEEDS_RESEARCH,
        ReviewStatus.NOT_APPLICABLE,
    }),
    ReviewStatus.CLASSIFIED: frozenset({
        ReviewStatus.NEEDS_RESEARCH,   # re-opened: capability taxonomy changed
        ReviewStatus.NOT_APPLICABLE,   # downgraded: scope changed
    }),
    ReviewStatus.DEFERRED: frozenset({
        ReviewStatus.UNCLASSIFIED,     # re-activated in a later cycle
        ReviewStatus.CLASSIFIED,
        ReviewStatus.NOT_APPLICABLE,
    }),
    ReviewStatus.NEEDS_RESEARCH: frozenset({
        ReviewStatus.UNCLASSIFIED,     # reset after new information is found
        ReviewStatus.CLASSIFIED,
        ReviewStatus.NOT_APPLICABLE,
    }),
    ReviewStatus.NOT_APPLICABLE: frozenset({
        ReviewStatus.UNCLASSIFIED,     # re-opened: scope expanded
    }),
}


# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------

def validate_status(value: str) -> ReviewStatus:
    """Parse *value* into a :class:`ReviewStatus`, rejecting unknown labels.

    Args:
        value: Raw status string to validate (e.g. from a JSON payload).

    Returns:
        The corresponding :class:`ReviewStatus` member.

    Raises:
        ValueError: If *value* is not one of the five allowed status strings.

    Example::

        >>> validate_status("unclassified")
        <ReviewStatus.UNCLASSIFIED: 'unclassified'>
        >>> validate_status("pending")   # doctest: +ELLIPSIS
        Traceback (most recent call last):
            ...
        ValueError: 'pending' is not a valid ReviewStatus. ...
    """
    try:
        return ReviewStatus(value)
    except ValueError:
        allowed = ", ".join(f"'{s.value}'" for s in ReviewStatus)
        raise ValueError(
            f"{value!r} is not a valid ReviewStatus. "
            f"Allowed values: {allowed}."
        ) from None


def validate_transition(
    current: ReviewStatus | str,
    next_status: ReviewStatus | str,
) -> None:
    """Assert that moving from *current* to *next_status* is a legal transition.

    Both arguments are coerced through :func:`validate_status` first, so
    raw strings from JSON payloads are accepted.

    Args:
        current:     The item's current status.
        next_status: The proposed new status.

    Raises:
        ValueError: If either value is not a valid status, or if the
            transition is not listed in :data:`ALLOWED_TRANSITIONS`.

    Example::

        >>> validate_transition("unclassified", "classified")  # OK – returns None
        >>> validate_transition("not-applicable", "classified")  # doctest: +ELLIPSIS
        Traceback (most recent call last):
            ...
        ValueError: Transition from 'not-applicable' to 'classified' is not allowed. ...
    """
    from_status = current if isinstance(current, ReviewStatus) else validate_status(current)
    to_status = next_status if isinstance(next_status, ReviewStatus) else validate_status(next_status)
    if to_status not in ALLOWED_TRANSITIONS[from_status]:
        allowed = ", ".join(
            f"'{s.value}'" for s in sorted(ALLOWED_TRANSITIONS[from_status], key=lambda s: s.value)
        )
        raise ValueError(
            f"Transition from {from_status.value!r} to {to_status.value!r} is not allowed. "
            f"Permitted next states from {from_status.value!r}: {allowed}."
        )
