"""Controlled capability vocabulary for IAM action classification.

This module is the **single programmatic source of truth** for the allowed
capability names used in:

- ``candidate_capabilities`` fields of review queue items
- Reviewed capability assignments in action classification records
- Detection rules that reference named capabilities

Do not hardcode capability name strings anywhere else in the codebase.
Import them from here so that typos and synonym drift are caught at load
time rather than silently producing incorrect classifications.

Vocabulary governance
---------------------
The authoritative list is defined in ``app/rules/capabilities.yaml``.
This module loads that file at import time and exposes the names as a
``frozenset``.  Any capability name that does not appear in that file is
**invalid** and will be rejected by :func:`validate_capability`.

To add a new capability:

1. Add the new entry to ``app/rules/capabilities.yaml`` under
   ``capabilities``, with a ``description`` and ``risk_note``.
2. Open a tracked review so the change is deliberate and auditable.
3. Do **not** invent names inline in classification records or detection
   rules first and backfill the YAML later.

Current vocabulary (10 capabilities)
-------------------------------------
privilege-delegation
    Allows passing or delegating an IAM role to a service or principal.

policy-modification
    Creates, attaches, modifies, or deletes IAM policies or inline policies.

credential-issuance
    Generates or rotates persistent or temporary credentials for a principal.

compute-with-role
    Launches EC2-style compute with an attached IAM role.

serverless-with-role
    Creates or modifies a serverless function / workflow with an execution role.

public-exposure
    Makes a resource publicly or broadly accessible outside the account.

cross-account-trust
    Modifies trust policies or sharing configurations granting cross-account access.

secret-read
    Retrieves plaintext secret material (Secrets Manager, SSM SecureString, KMS).

data-read-sensitive
    Reads records from general-purpose storage that may contain sensitive data.

data-write-sensitive
    Writes, overwrites, or deletes records in storage containing sensitive data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

# ---------------------------------------------------------------------------
# File loading
# ---------------------------------------------------------------------------

_CAPABILITIES_FILE: Final[Path] = Path(__file__).resolve().parent / "rules" / "capabilities.yaml"


def _load_capabilities_file(path: Path = _CAPABILITIES_FILE) -> dict:
    """Load and parse the capabilities YAML (JSON-encoded) file.

    The project stores rule files as JSON inside ``.yaml`` wrappers so that
    the existing ``_load_data_file`` loader in ``analyzer.py`` can read them
    without a PyYAML dependency.  This function follows the same convention
    and reads the file as JSON.

    Args:
        path: Override for the capabilities file path (used in tests).

    Returns:
        Parsed dict with ``_governance`` and ``capabilities`` keys.

    Raises:
        RuntimeError: If the file is missing or contains invalid JSON.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Capabilities vocabulary file not found: {path}. "
            "This file is required for capability name validation."
        ) from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Capabilities vocabulary file contains invalid JSON: {path}. "
            f"Parse error: {exc}"
        ) from exc


def _build_capability_index(raw: dict) -> dict[str, dict[str, str]]:
    """Extract and validate the capabilities dict from the raw file data.

    Args:
        raw: Parsed capabilities file dict.

    Returns:
        Dict mapping each capability name to its metadata fields.

    Raises:
        RuntimeError: If the ``capabilities`` key is missing or empty.
    """
    caps = raw.get("capabilities")
    if not isinstance(caps, dict) or not caps:
        raise RuntimeError(
            "capabilities.yaml must contain a non-empty 'capabilities' object. "
            "Check the file for corruption or accidental truncation."
        )
    return {name: dict(meta) for name, meta in caps.items()}


# ---------------------------------------------------------------------------
# Public constants (populated at module import time)
# ---------------------------------------------------------------------------

#: Full capability metadata, keyed by capability name.
#: Each value is a dict with at least ``description`` and ``risk_note`` keys.
CAPABILITIES: Final[dict[str, dict[str, str]]] = _build_capability_index(
    _load_capabilities_file()
)

#: Frozenset of every allowed capability name.  Use this for O(1) membership
#: tests and to iterate the vocabulary without depending on dict ordering.
CAPABILITY_NAMES: Final[frozenset[str]] = frozenset(CAPABILITIES.keys())


# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------

def validate_capability(name: str) -> str:
    """Validate that *name* is a member of the controlled capability vocabulary.

    Args:
        name: The capability name string to validate.

    Returns:
        *name* unchanged if it is valid.

    Raises:
        ValueError: If *name* is not in :data:`CAPABILITY_NAMES`.

    Example::

        >>> validate_capability("secret-read")
        'secret-read'
        >>> validate_capability("exfiltration")   # doctest: +ELLIPSIS
        Traceback (most recent call last):
            ...
        ValueError: 'exfiltration' is not a recognised capability name. ...
    """
    if name not in CAPABILITY_NAMES:
        allowed = ", ".join(f"'{n}'" for n in sorted(CAPABILITY_NAMES))
        raise ValueError(
            f"{name!r} is not a recognised capability name. "
            f"All names must come from app/rules/capabilities.yaml. "
            f"Allowed values: {allowed}."
        )
    return name


def validate_capabilities(names: list[str]) -> list[str]:
    """Validate every name in *names* against the controlled vocabulary.

    Validates the complete list before raising so callers receive all
    invalid names in a single error rather than one at a time.

    Args:
        names: List of capability name strings to validate.  An empty list
               is always valid (actions with no assigned capabilities).

    Returns:
        *names* unchanged if every entry is valid.

    Raises:
        ValueError: If one or more names are not in :data:`CAPABILITY_NAMES`.
            The error message lists all invalid names found.

    Example::

        >>> validate_capabilities(["secret-read", "public-exposure"])
        ['secret-read', 'public-exposure']
        >>> validate_capabilities(["secret-read", "bad-name"])  # doctest: +ELLIPSIS
        Traceback (most recent call last):
            ...
        ValueError: 1 unrecognised capability name(s): 'bad-name'. ...
    """
    invalid = sorted({n for n in names if n not in CAPABILITY_NAMES})
    if invalid:
        listed = ", ".join(f"'{n}'" for n in invalid)
        allowed = ", ".join(f"'{n}'" for n in sorted(CAPABILITY_NAMES))
        raise ValueError(
            f"{len(invalid)} unrecognised capability name(s): {listed}. "
            f"All names must come from app/rules/capabilities.yaml. "
            f"Allowed values: {allowed}."
        )
    return names
