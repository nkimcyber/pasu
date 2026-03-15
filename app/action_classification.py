"""Loader, validator, and safe-lookup interface for the reviewed action
classification file.

This module owns the loading, structural validation, and field-level
enforcement for ``app/rules/action_classification.yaml``.

It is the **single programmatic interface** to the classification records.
All code that reads classification data must go through
:func:`load_action_classification` rather than parsing the YAML directly,
so that constraint violations are caught at load time.

Safe-handling rule for unknown actions
---------------------------------------
An AWS action that is absent from the classification file is **unknown**,
not risky.  Absence of a reviewed record must never be treated as implicit
confirmation that an action is safe *or* dangerous.

The rule is enforced through :func:`lookup_action`, which returns a
:class:`ClassificationLookupResult` for every query — including queries for
actions that have no classification record.  The result's
:attr:`~ClassificationLookupResult.is_confirmed_risky` property is
``False`` for any unknown action.  Code that consumes classification data
**must** use this function and **must not** infer risk from a missing record.

The review queue is the only promotion path.  An unreviewed action enters
the queue with ``status="unclassified"`` and only transitions to
``status="classified"`` after a human reviewer adds an entry to
``action_classification.yaml`` through a tracked change.

Constraints enforced on classification records
-----------------------------------------------
``status``
    Must be a :class:`~app.review_status.ReviewStatus` value that is valid
    in the ``"classification"`` context.  Currently: ``classified`` and
    ``not-applicable``.  Queue-only states (``unclassified``, ``deferred``,
    ``needs-research``) are rejected.

``capabilities``
    Every name must be present in :data:`~app.capabilities.CAPABILITY_NAMES`.
    The list must be non-empty when ``status`` is ``"classified"``.
    An empty list is permitted only when ``status`` is ``"not-applicable"``.

``confidence``
    Must be one of ``"high"``, ``"medium"``, ``"low"`` as defined in
    :data:`CONFIDENCE_LEVELS`.

``notes``
    Must be a string (may be empty).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from app.capabilities import CAPABILITY_NAMES, validate_capabilities
from app.review_status import VALID_CONTEXTS, ReviewStatus, validate_status

# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------

#: Allowed confidence values for a reviewed classification record.
#:
#: ``"high"``
#:     The action's risk behaviour is well-documented and unambiguous; the
#:     classification is considered stable.
#:
#: ``"medium"``
#:     The classification is context-dependent or based on partial evidence;
#:     a reviewer has made a best-effort call.
#:
#: ``"low"``
#:     The classification is speculative or based on sparse documentation;
#:     the entry should be re-examined when more information is available.
CONFIDENCE_LEVELS: Final[frozenset[str]] = frozenset({"high", "medium", "low"})

# ---------------------------------------------------------------------------
# Classification-context status constraint
# ---------------------------------------------------------------------------

#: The subset of :class:`~app.review_status.ReviewStatus` values that are
#: valid inside a classification record (i.e. valid in the
#: ``"classification"`` context per :data:`~app.review_status.VALID_CONTEXTS`).
CLASSIFICATION_STATUSES: Final[frozenset[ReviewStatus]] = frozenset(
    s for s, contexts in VALID_CONTEXTS.items() if "classification" in contexts
)

_CLASSIFICATION_STATUS_VALUES: Final[frozenset[str]] = frozenset(
    s.value for s in CLASSIFICATION_STATUSES
)

# ---------------------------------------------------------------------------
# File path
# ---------------------------------------------------------------------------

_CLASSIFICATION_FILE: Final[Path] = (
    Path(__file__).resolve().parent / "rules" / "action_classification.yaml"
)

# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------

def validate_confidence(value: str) -> str:
    """Validate that *value* is an allowed confidence level.

    Args:
        value: Raw confidence string to validate.

    Returns:
        *value* unchanged if valid.

    Raises:
        ValueError: If *value* is not in :data:`CONFIDENCE_LEVELS`.

    Example::

        >>> validate_confidence("high")
        'high'
        >>> validate_confidence("certain")   # doctest: +ELLIPSIS
        Traceback (most recent call last):
            ...
        ValueError: 'certain' is not a valid confidence level. ...
    """
    if value not in CONFIDENCE_LEVELS:
        allowed = ", ".join(f"'{v}'" for v in sorted(CONFIDENCE_LEVELS))
        raise ValueError(
            f"{value!r} is not a valid confidence level. "
            f"Allowed values: {allowed}."
        )
    return value


def validate_record(action_key: str, record: dict[str, Any]) -> dict[str, Any]:
    """Validate one classification record for *action_key*.

    Checks that all required fields are present and that every value satisfies
    its constraint.  Does **not** modify the record; raises on the first
    structural error found, then continues to collect field-level errors so
    the caller receives a complete picture.

    Args:
        action_key: The IAM action key the record is associated with
            (e.g. ``"iam:PassRole"``).  Used only for error messages.
        record:     The record dict to validate.

    Returns:
        *record* unchanged if all fields are valid.

    Raises:
        ValueError: If any field is missing, has the wrong type, or fails a
            constraint check.  The message names the action key and lists all
            violations found.
    """
    errors: list[str] = []

    # ── Required keys ────────────────────────────────────────────────────────
    required = {"status", "capabilities", "confidence", "notes"}
    missing = required - set(record.keys())
    if missing:
        errors.append(f"missing required fields: {sorted(missing)}")

    # ── status ───────────────────────────────────────────────────────────────
    raw_status = record.get("status")
    validated_status: ReviewStatus | None = None
    if raw_status is not None:
        try:
            validated_status = validate_status(raw_status)
        except ValueError as exc:
            errors.append(f"status: {exc}")
        else:
            if validated_status.value not in _CLASSIFICATION_STATUS_VALUES:
                allowed = ", ".join(f"'{v}'" for v in sorted(_CLASSIFICATION_STATUS_VALUES))
                errors.append(
                    f"status {validated_status.value!r} is not valid in the "
                    f"classification context. Allowed: {allowed}."
                )
                validated_status = None  # prevent downstream use

    # ── capabilities ─────────────────────────────────────────────────────────
    raw_caps = record.get("capabilities")
    if raw_caps is not None:
        if not isinstance(raw_caps, list):
            errors.append(
                f"capabilities must be a list, got {type(raw_caps).__name__!r}"
            )
        else:
            try:
                validate_capabilities(raw_caps)
            except ValueError as exc:
                errors.append(f"capabilities: {exc}")
            else:
                # Non-empty capabilities required when status is "classified"
                if (
                    validated_status is not None
                    and validated_status == ReviewStatus.CLASSIFIED
                    and len(raw_caps) == 0
                ):
                    errors.append(
                        "capabilities must not be empty when status is 'classified'. "
                        "Use status 'not-applicable' for actions with no capabilities."
                    )

    # ── confidence ───────────────────────────────────────────────────────────
    raw_confidence = record.get("confidence")
    if raw_confidence is not None:
        try:
            validate_confidence(raw_confidence)
        except ValueError as exc:
            errors.append(f"confidence: {exc}")

    # ── notes ────────────────────────────────────────────────────────────────
    raw_notes = record.get("notes")
    if raw_notes is not None and not isinstance(raw_notes, str):
        errors.append(f"notes must be a string, got {type(raw_notes).__name__!r}")

    if errors:
        bullet_list = "\n  - ".join(errors)
        raise ValueError(
            f"Invalid classification record for {action_key!r}:\n  - {bullet_list}"
        )
    return record


# ---------------------------------------------------------------------------
# File loader
# ---------------------------------------------------------------------------

def load_action_classification(
    path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Load and fully validate the action classification file.

    Reads ``app/rules/action_classification.yaml``, validates every record,
    and returns the ``actions`` dict.  The ``_governance`` and
    ``_field_reference`` metadata keys are consumed internally and not
    returned to callers.

    Args:
        path: Override the default file path.  Intended for testing only.

    Returns:
        Dict mapping action key strings to their validated record dicts.

    Raises:
        RuntimeError: If the file is missing, contains invalid JSON, or
            is structurally invalid (missing ``actions`` key).
        ValueError: If any individual record fails field-level validation.
            The error message identifies the offending action key(s).
    """
    resolved = path or _CLASSIFICATION_FILE

    try:
        text = resolved.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Action classification file not found: {resolved}"
        ) from exc

    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Action classification file contains invalid JSON: {resolved}. "
            f"Parse error: {exc}"
        ) from exc

    if not isinstance(raw.get("actions"), dict):
        raise RuntimeError(
            f"Action classification file must contain an 'actions' object: {resolved}"
        )

    actions: dict[str, dict[str, Any]] = raw["actions"]

    # Validate every record; accumulate errors so callers see all failures.
    all_errors: list[str] = []
    for action_key, record in actions.items():
        try:
            validate_record(action_key, record)
        except ValueError as exc:
            all_errors.append(str(exc))

    if all_errors:
        joined = "\n\n".join(all_errors)
        raise ValueError(
            f"Action classification file contains {len(all_errors)} invalid "
            f"record(s):\n\n{joined}"
        )

    return actions


# ---------------------------------------------------------------------------
# Safe-lookup guard
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClassificationLookupResult:
    """Result of a single action key lookup against the classification file.

    This type makes the **unknown = not risky** rule structurally
    unambiguous.  Consumers receive a well-typed result for every query,
    including queries for actions that have no reviewed record, and cannot
    accidentally treat a missing record as a risky finding.

    Attributes:
        action:  The action key that was looked up (e.g. ``"iam:PassRole"``).
        found:   ``True`` when the action key has a reviewed record in the
                 classification file; ``False`` when the action is unknown.
        record:  The raw classification record dict when ``found`` is
                 ``True``; ``None`` otherwise.
    """

    action: str
    found: bool
    record: dict[str, Any] | None

    @property
    def is_confirmed_risky(self) -> bool:
        """``True`` only when a reviewed record explicitly classifies the action.

        This is the core guard against auto-promotion of unknown actions.

        Returns ``True`` if and only if **all** of the following hold:

        1. The action has a reviewed record (``found`` is ``True``).
        2. The record's ``status`` is ``"classified"``.
        3. The record's ``capabilities`` list is non-empty.

        Returns ``False`` in every other case, including:

        - The action is absent from the classification file (unknown).
        - The action has ``status="not-applicable"``.
        - The record exists but has an empty capabilities list.

        **Unknown actions must never reach a risky finding through this
        property.**  The review queue is the only path from unknown to
        classified.
        """
        if not self.found or self.record is None:
            return False
        return (
            self.record.get("status") == "classified"
            and bool(self.record.get("capabilities"))
        )

    @property
    def capabilities(self) -> list[str]:
        """Capability names from the record, or an empty list when not found."""
        if self.record is None:
            return []
        return list(self.record.get("capabilities", []))

    @property
    def status(self) -> str | None:
        """Record status string, or ``None`` when the action is unknown."""
        if self.record is None:
            return None
        return self.record.get("status")

    @property
    def confidence(self) -> str | None:
        """Record confidence string, or ``None`` when the action is unknown."""
        if self.record is None:
            return None
        return self.record.get("confidence")


def lookup_action(
    action_key: str,
    classification: dict[str, dict[str, Any]],
) -> ClassificationLookupResult:
    """Look up a single action key in a loaded classification dict.

    This is the **only sanctioned way** to query classification data at
    runtime.  It enforces the safe-handling rule: an action absent from the
    classification file is returned as *unknown* (``found=False``) with
    :attr:`~ClassificationLookupResult.is_confirmed_risky` equal to
    ``False``.  The function never raises for unknown keys.

    Args:
        action_key:     The IAM action key to look up, in any case
                        (e.g. ``"iam:PassRole"``).  Lookup is
                        **case-sensitive** to match the canonical form used
                        in ``action_classification.yaml``.
        classification: A classification dict previously returned by
                        :func:`load_action_classification`.

    Returns:
        A :class:`ClassificationLookupResult`.  When the key is not present,
        ``found`` is ``False`` and ``is_confirmed_risky`` is ``False``.

    Example::

        >>> actions = load_action_classification()
        >>> result = lookup_action("iam:PassRole", actions)
        >>> result.found
        True
        >>> result.is_confirmed_risky
        True
        >>> unknown = lookup_action("svc:NewUndocumentedAction", actions)
        >>> unknown.found
        False
        >>> unknown.is_confirmed_risky   # guard: never auto-promoted
        False
    """
    record = classification.get(action_key)
    if record is None:
        return ClassificationLookupResult(action=action_key, found=False, record=None)
    return ClassificationLookupResult(action=action_key, found=True, record=record)
