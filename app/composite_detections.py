"""Loader and validator for composite detection rules.

This module owns the loading, structural validation, and field-level
enforcement for ``app/rules/composite_detections.yaml``.

Composite detection rules describe higher-level attack patterns that emerge
when a principal holds multiple reviewed capabilities simultaneously.  Each
rule is pure metadata — a stable identifier, a human-readable title,
capability references, severity, confidence logic, and rationale.

**Scope of this module**

This module is deliberately limited to schema definition and validation.
It does not contain:

- Matching logic (deciding whether a policy triggers a rule)
- Finding construction (producing output from a match)
- Scoring (weighting rules against each other)
- Any reference to specific AWS action keys

Those concerns belong to the detection engine, which is implemented
separately and consumes the rules returned by :func:`load_composite_detections`.

Confidence logic semantics
--------------------------
The ``confidence_logic`` field declares *how* a rule's overall confidence
should be derived when the matching engine evaluates it.  The three allowed
values and their intended meanings are:

``"all-high"``
    The rule fires at high overall confidence only when **every** contributing
    classified action has ``confidence="high"`` in the classification file.
    If any action has medium or low confidence, the rule's overall confidence
    is downgraded accordingly.

``"weakest"``
    The rule's overall confidence equals the **lowest** individual confidence
    level among all contributing actions.  One medium-confidence action in an
    otherwise high-confidence rule produces a medium overall result.

``"majority"``
    The rule's overall confidence is **high** when the majority of
    contributing actions carry high confidence; otherwise medium.

The matching engine (future task) is responsible for implementing these
semantics.  This module validates that the field value is one of the three
recognised strings; it does not compute confidence.

Capability references
---------------------
Every capability name in ``required_capabilities`` and
``optional_capabilities`` must be a member of the controlled vocabulary
defined in ``app/rules/capabilities.yaml`` and enforced by
:data:`~app.capabilities.CAPABILITY_NAMES`.  Unrecognised names are
rejected at load time.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from app.capabilities import CAPABILITY_NAMES, validate_capabilities

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

#: Allowed severity levels for a composite detection rule.
#:
#: ``"critical"``
#:     The pattern represents a complete, high-impact attack chain (e.g. full
#:     privilege escalation) that should be remediated immediately.
#:
#: ``"high"``
#:     The pattern indicates a serious risk with a clear exploitation path,
#:     but with slightly more limited blast radius than critical.
#:
#: ``"medium"``
#:     The pattern is noteworthy and warrants investigation, but exploitation
#:     requires additional context or steps not captured by the capabilities.
#:
#: ``"low"``
#:     The pattern is worth surfacing for awareness but is unlikely to
#:     represent an immediate threat in isolation.
SEVERITY_LEVELS: Final[frozenset[str]] = frozenset({"critical", "high", "medium", "low"})

#: Allowed confidence-derivation strategies for a composite detection rule.
#:
#: See the module docstring for the full semantics of each value.
CONFIDENCE_LOGIC_VALUES: Final[frozenset[str]] = frozenset({"all-high", "weakest", "majority"})

# ---------------------------------------------------------------------------
# Rule ID pattern
# ---------------------------------------------------------------------------

_RULE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^COMP-[0-9]{3}$")

# ---------------------------------------------------------------------------
# In-memory rule object
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CompositeRule:
    """Immutable, validated representation of one composite detection rule.

    Produced by :func:`load_composite_detections` after all field-level
    validation has passed.  Using a frozen dataclass rather than a plain dict
    makes the rule's schema explicit and prevents accidental mutation by
    consumer code.

    Attributes:
        id:                    Stable rule identifier in ``COMP-NNN`` form.
        title:                 Short human-readable name.
        required_capabilities: Capabilities that must *all* be present for
                               the rule to fire.  Stored as an immutable
                               tuple; order reflects the source file.
        optional_capabilities: Capabilities that raise confidence when
                               present but are not required.  Empty tuple
                               when the rule has no optional capabilities.
        severity:              One of ``"critical"``, ``"high"``,
                               ``"medium"``, ``"low"``.
        confidence_logic:      One of ``"all-high"``, ``"weakest"``,
                               ``"majority"``.
        rationale:             Human-readable explanation of why the
                               capability combination is dangerous.
    """

    id: str
    title: str
    required_capabilities: tuple[str, ...]
    optional_capabilities: tuple[str, ...]
    severity: str
    confidence_logic: str
    rationale: str


def _rule_from_dict(rule: dict[str, Any]) -> CompositeRule:
    """Convert a validated rule dict to a :class:`CompositeRule`.

    Callers must validate the dict with :func:`validate_rule` before calling
    this function.  No additional validation is performed here.
    """
    return CompositeRule(
        id=rule["id"],
        title=rule["title"],
        required_capabilities=tuple(rule["required_capabilities"]),
        optional_capabilities=tuple(rule["optional_capabilities"]),
        severity=rule["severity"],
        confidence_logic=rule["confidence_logic"],
        rationale=rule["rationale"],
    )


# ---------------------------------------------------------------------------
# File path
# ---------------------------------------------------------------------------

_COMPOSITE_DETECTIONS_FILE: Final[Path] = (
    Path(__file__).resolve().parent / "rules" / "composite_detections.yaml"
)

# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------

def validate_severity(value: str) -> str:
    """Validate that *value* is an allowed severity level.

    Args:
        value: Raw severity string to validate.

    Returns:
        *value* unchanged if valid.

    Raises:
        ValueError: If *value* is not in :data:`SEVERITY_LEVELS`.
    """
    if value not in SEVERITY_LEVELS:
        allowed = ", ".join(f"'{v}'" for v in sorted(SEVERITY_LEVELS))
        raise ValueError(
            f"{value!r} is not a valid severity level. "
            f"Allowed values: {allowed}."
        )
    return value


def validate_confidence_logic(value: str) -> str:
    """Validate that *value* is a recognised confidence-derivation strategy.

    Args:
        value: Raw confidence_logic string to validate.

    Returns:
        *value* unchanged if valid.

    Raises:
        ValueError: If *value* is not in :data:`CONFIDENCE_LOGIC_VALUES`.
    """
    if value not in CONFIDENCE_LOGIC_VALUES:
        allowed = ", ".join(f"'{v}'" for v in sorted(CONFIDENCE_LOGIC_VALUES))
        raise ValueError(
            f"{value!r} is not a valid confidence_logic value. "
            f"Allowed values: {allowed}."
        )
    return value


def validate_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """Validate one composite detection rule dict.

    Checks that all required fields are present and that every value satisfies
    its constraint.  Collects all violations before raising so callers receive
    a complete picture of every problem in the rule.

    Args:
        rule: The rule dict to validate.

    Returns:
        *rule* unchanged if all fields are valid.

    Raises:
        ValueError: If any field is missing, has the wrong type, or fails a
            constraint check.  The message includes the rule ``id`` (or
            ``"<unknown id>"`` if the id field itself is missing or invalid)
            and lists all violations found.
    """
    errors: list[str] = []

    # ── Required keys ────────────────────────────────────────────────────────
    required = {
        "id", "title", "required_capabilities",
        "optional_capabilities", "severity", "confidence_logic", "rationale",
    }
    missing = required - set(rule.keys())
    if missing:
        errors.append(f"missing required fields: {sorted(missing)}")

    # ── id ───────────────────────────────────────────────────────────────────
    raw_id = rule.get("id", "<unknown id>")
    if not isinstance(raw_id, str) or not _RULE_ID_PATTERN.match(raw_id):
        errors.append(
            f"id {raw_id!r} does not match the required pattern 'COMP-NNN' "
            f"(e.g. 'COMP-001')."
        )

    # ── title ────────────────────────────────────────────────────────────────
    raw_title = rule.get("title")
    if raw_title is not None:
        if not isinstance(raw_title, str) or not raw_title.strip():
            errors.append("title must be a non-empty string.")

    # ── required_capabilities ─────────────────────────────────────────────────
    raw_req = rule.get("required_capabilities")
    if raw_req is not None:
        if not isinstance(raw_req, list):
            errors.append(
                f"required_capabilities must be a list, "
                f"got {type(raw_req).__name__!r}."
            )
        elif len(raw_req) == 0:
            errors.append(
                "required_capabilities must contain at least one capability. "
                "A composite rule with no required capabilities is not meaningful."
            )
        else:
            try:
                validate_capabilities(raw_req)
            except ValueError as exc:
                errors.append(f"required_capabilities: {exc}")

    # ── optional_capabilities ─────────────────────────────────────────────────
    raw_opt = rule.get("optional_capabilities")
    if raw_opt is not None:
        if not isinstance(raw_opt, list):
            errors.append(
                f"optional_capabilities must be a list, "
                f"got {type(raw_opt).__name__!r}."
            )
        elif raw_opt:
            try:
                validate_capabilities(raw_opt)
            except ValueError as exc:
                errors.append(f"optional_capabilities: {exc}")

    # ── required ∩ optional must be empty ────────────────────────────────────
    if isinstance(raw_req, list) and isinstance(raw_opt, list):
        overlap = sorted(set(raw_req) & set(raw_opt))
        if overlap:
            errors.append(
                f"capabilities appear in both required_capabilities and "
                f"optional_capabilities: {overlap}. "
                f"A capability must be in exactly one list."
            )

    # ── severity ─────────────────────────────────────────────────────────────
    raw_severity = rule.get("severity")
    if raw_severity is not None:
        try:
            validate_severity(raw_severity)
        except ValueError as exc:
            errors.append(f"severity: {exc}")

    # ── confidence_logic ──────────────────────────────────────────────────────
    raw_cl = rule.get("confidence_logic")
    if raw_cl is not None:
        try:
            validate_confidence_logic(raw_cl)
        except ValueError as exc:
            errors.append(f"confidence_logic: {exc}")

    # ── rationale ────────────────────────────────────────────────────────────
    if "rationale" in rule:
        raw_rationale = rule["rationale"]
        if not isinstance(raw_rationale, str) or not raw_rationale.strip():
            errors.append("rationale must be a non-empty string.")

    if errors:
        rule_id = raw_id if isinstance(raw_id, str) else "<unknown id>"
        bullet_list = "\n  - ".join(errors)
        raise ValueError(
            f"Invalid composite detection rule {rule_id!r}:\n  - {bullet_list}"
        )
    return rule


# ---------------------------------------------------------------------------
# File loader
# ---------------------------------------------------------------------------

def load_composite_detections(
    path: Path | None = None,
) -> list[CompositeRule]:
    """Load and fully validate the composite detections rule file.

    Reads ``app/rules/composite_detections.yaml``, validates every rule,
    and returns the ``rules`` list.  The ``_governance`` and
    ``_field_reference`` metadata keys are consumed internally and not
    returned to callers.

    Also asserts that all rule IDs are unique within the file.

    Args:
        path: Override the default file path.  Intended for testing only.

    Returns:
        List of validated :class:`CompositeRule` objects sorted by rule ID.
        Sorting is deterministic regardless of the order rules appear in the
        file, so consumer code can rely on a stable traversal order.

    Raises:
        RuntimeError: If the file is missing, contains invalid JSON, or
            is structurally invalid (missing ``rules`` key or non-list value).
        ValueError: If any individual rule fails field-level validation, or if
            duplicate rule IDs are present.  The error message identifies all
            offending rules.
    """
    resolved = path or _COMPOSITE_DETECTIONS_FILE

    try:
        text = resolved.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Composite detections file not found: {resolved}"
        ) from exc

    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Composite detections file contains invalid JSON: {resolved}. "
            f"Parse error: {exc}"
        ) from exc

    if not isinstance(raw.get("rules"), list):
        raise RuntimeError(
            f"Composite detections file must contain a 'rules' array: {resolved}"
        )

    rules: list[dict[str, Any]] = raw["rules"]

    # Validate every rule; accumulate errors.
    all_errors: list[str] = []
    for rule in rules:
        try:
            validate_rule(rule)
        except ValueError as exc:
            all_errors.append(str(exc))

    # Assert unique IDs.
    ids = [r.get("id") for r in rules if isinstance(r.get("id"), str)]
    seen: set[str] = set()
    duplicates: list[str] = []
    for rule_id in ids:
        if rule_id in seen:
            duplicates.append(rule_id)
        seen.add(rule_id)
    if duplicates:
        all_errors.append(
            f"Duplicate rule IDs detected (IDs must be unique): "
            f"{sorted(set(duplicates))}"
        )

    if all_errors:
        joined = "\n\n".join(all_errors)
        raise ValueError(
            f"Composite detections file contains {len(all_errors)} error(s):"
            f"\n\n{joined}"
        )

    return sorted(
        (_rule_from_dict(r) for r in rules),
        key=lambda r: r.id,
    )
