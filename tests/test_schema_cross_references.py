"""Schema cross-reference consistency tests.

Verifies that the four schema/rule files agree on their shared vocabularies.
Each test targets one specific cross-file dependency so that failures identify
exactly which pairing is broken.

Cross-references under test
---------------------------
1. ``review_queue.schema.json`` status enum == ``ReviewStatus`` enum values.
2. Every capability in ``action_classification.yaml`` is defined in
   ``capabilities.yaml``.
3. Every capability referenced in ``composite_detections.yaml`` rule
   ``required_capabilities`` is defined in ``capabilities.yaml``.
4. Every capability referenced in ``composite_detections.yaml`` rule
   ``optional_capabilities`` is defined in ``capabilities.yaml``.
5. ``CAPABILITY_NAMES`` (runtime constant) matches the ``capabilities``
   block keys in ``capabilities.yaml`` (file matches code).
6. ``CLASSIFICATION_STATUSES`` (runtime constant) is a subset of
   ``ReviewStatus`` — no invented status strings.
7. Each rule in ``composite_detections.yaml`` uses at most the capability
   names in ``capabilities.yaml`` — no typo synonyms slip through at the
   file level.

These tests operate directly on the file content so they catch issues that
would arise if the validation code itself were bypassed or changed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# File paths
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parent.parent
_SCHEMA_FILE      = _ROOT / "app" / "data"  / "review_queue.schema.json"
_CAPABILITIES_FILE = _ROOT / "app" / "rules" / "capabilities.yaml"
_CLASSIFICATION_FILE = _ROOT / "app" / "rules" / "action_classification.yaml"
_COMPOSITE_FILE   = _ROOT / "app" / "rules" / "composite_detections.yaml"


# ---------------------------------------------------------------------------
# Helpers — load raw file content once per module
# ---------------------------------------------------------------------------

def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 1. review_queue.schema.json status enum == ReviewStatus enum
# ---------------------------------------------------------------------------

class TestReviewQueueSchemaStatusEnum:
    """The schema's status.enum must stay in sync with the ReviewStatus Python enum."""

    def test_schema_status_enum_matches_review_status_exactly(self):
        from app.review_status import ReviewStatus
        schema = _load(_SCHEMA_FILE)
        schema_values = set(
            schema["definitions"]["ReviewItem"]["properties"]["status"]["enum"]
        )
        python_values = {s.value for s in ReviewStatus}
        assert schema_values == python_values, (
            f"review_queue.schema.json status.enum {sorted(schema_values)!r} "
            f"differs from ReviewStatus {sorted(python_values)!r}"
        )

    def test_schema_has_no_extra_status_values_beyond_review_status(self):
        from app.review_status import ReviewStatus
        schema = _load(_SCHEMA_FILE)
        schema_values = set(
            schema["definitions"]["ReviewItem"]["properties"]["status"]["enum"]
        )
        python_values = {s.value for s in ReviewStatus}
        extra = schema_values - python_values
        assert not extra, (
            f"review_queue.schema.json has status values not in ReviewStatus: {sorted(extra)!r}"
        )

    def test_schema_has_no_missing_status_values_from_review_status(self):
        from app.review_status import ReviewStatus
        schema = _load(_SCHEMA_FILE)
        schema_values = set(
            schema["definitions"]["ReviewItem"]["properties"]["status"]["enum"]
        )
        python_values = {s.value for s in ReviewStatus}
        missing = python_values - schema_values
        assert not missing, (
            f"review_queue.schema.json is missing ReviewStatus values: {sorted(missing)!r}"
        )


# ---------------------------------------------------------------------------
# 2. action_classification.yaml capabilities ⊆ capabilities.yaml
# ---------------------------------------------------------------------------

class TestClassificationCapabilitiesInTaxonomy:
    """Every capability referenced in action_classification.yaml must exist in capabilities.yaml."""

    def _classification_capabilities(self) -> set[str]:
        data = _load(_CLASSIFICATION_FILE)
        caps: set[str] = set()
        for _action, record in data.get("actions", {}).items():
            caps.update(record.get("capabilities", []))
        return caps

    def _taxonomy_capabilities(self) -> set[str]:
        data = _load(_CAPABILITIES_FILE)
        return set(data.get("capabilities", {}).keys())

    def test_all_classification_capabilities_are_in_taxonomy(self):
        used = self._classification_capabilities()
        defined = self._taxonomy_capabilities()
        unknown = used - defined
        assert not unknown, (
            f"action_classification.yaml references capabilities not in capabilities.yaml: "
            f"{sorted(unknown)!r}"
        )

    def test_classification_uses_at_least_one_capability(self):
        used = self._classification_capabilities()
        assert used, "Expected at least one capability to be used in action_classification.yaml"


# ---------------------------------------------------------------------------
# 3 & 4. composite_detections.yaml capability references ⊆ capabilities.yaml
# ---------------------------------------------------------------------------

class TestCompositeCapabilitiesInTaxonomy:
    """Every capability referenced in composite rules must exist in capabilities.yaml."""

    def _taxonomy_capabilities(self) -> set[str]:
        data = _load(_CAPABILITIES_FILE)
        return set(data.get("capabilities", {}).keys())

    def _all_composite_caps(self) -> tuple[set[str], set[str]]:
        data = _load(_COMPOSITE_FILE)
        required: set[str] = set()
        optional: set[str] = set()
        for rule in data.get("rules", []):
            required.update(rule.get("required_capabilities", []))
            optional.update(rule.get("optional_capabilities", []))
        return required, optional

    def test_all_required_capabilities_are_in_taxonomy(self):
        required, _ = self._all_composite_caps()
        defined = self._taxonomy_capabilities()
        unknown = required - defined
        assert not unknown, (
            f"composite_detections.yaml required_capabilities not in capabilities.yaml: "
            f"{sorted(unknown)!r}"
        )

    def test_all_optional_capabilities_are_in_taxonomy(self):
        _, optional = self._all_composite_caps()
        defined = self._taxonomy_capabilities()
        unknown = optional - defined
        assert not unknown, (
            f"composite_detections.yaml optional_capabilities not in capabilities.yaml: "
            f"{sorted(unknown)!r}"
        )

    def test_no_capability_typo_in_required(self):
        """A rule-level typo in a capability name must be caught here before it reaches runtime."""
        required, _ = self._all_composite_caps()
        defined = self._taxonomy_capabilities()
        # If this fails, there is a capability name in a composite rule that is not in the taxonomy.
        # Fix: check the rule's required_capabilities spelling against capabilities.yaml.
        assert required <= defined

    def test_no_capability_typo_in_optional(self):
        _, optional = self._all_composite_caps()
        defined = self._taxonomy_capabilities()
        assert optional <= defined


# ---------------------------------------------------------------------------
# 5. CAPABILITY_NAMES runtime constant matches capabilities.yaml file
# ---------------------------------------------------------------------------

class TestCapabilityNamesMatchFile:
    """The runtime ``CAPABILITY_NAMES`` frozenset must mirror the file exactly."""

    def test_capability_names_equals_file_keys(self):
        from app.capabilities import CAPABILITY_NAMES
        data = _load(_CAPABILITIES_FILE)
        file_keys = frozenset(data.get("capabilities", {}).keys())
        assert CAPABILITY_NAMES == file_keys, (
            f"CAPABILITY_NAMES diverges from capabilities.yaml. "
            f"Only in code: {sorted(CAPABILITY_NAMES - file_keys)!r}. "
            f"Only in file: {sorted(file_keys - CAPABILITY_NAMES)!r}."
        )

    def test_no_capability_in_code_missing_from_file(self):
        from app.capabilities import CAPABILITY_NAMES
        data = _load(_CAPABILITIES_FILE)
        file_keys = frozenset(data.get("capabilities", {}).keys())
        extra_in_code = CAPABILITY_NAMES - file_keys
        assert not extra_in_code, (
            f"CAPABILITY_NAMES has names not in capabilities.yaml: {sorted(extra_in_code)!r}"
        )

    def test_no_capability_in_file_missing_from_code(self):
        from app.capabilities import CAPABILITY_NAMES
        data = _load(_CAPABILITIES_FILE)
        file_keys = frozenset(data.get("capabilities", {}).keys())
        extra_in_file = file_keys - CAPABILITY_NAMES
        assert not extra_in_file, (
            f"capabilities.yaml has names not in CAPABILITY_NAMES: {sorted(extra_in_file)!r}"
        )


# ---------------------------------------------------------------------------
# 6. CLASSIFICATION_STATUSES ⊆ ReviewStatus
# ---------------------------------------------------------------------------

class TestClassificationStatusesConsistency:
    """CLASSIFICATION_STATUSES must contain only valid ReviewStatus members."""

    def test_all_classification_statuses_are_review_status_members(self):
        from app.action_classification import CLASSIFICATION_STATUSES
        from app.review_status import ReviewStatus
        all_review_statuses = set(ReviewStatus)
        for s in CLASSIFICATION_STATUSES:
            assert s in all_review_statuses, (
                f"CLASSIFICATION_STATUSES contains {s!r} which is not a ReviewStatus member"
            )

    def test_classified_is_in_classification_statuses(self):
        from app.action_classification import CLASSIFICATION_STATUSES
        from app.review_status import ReviewStatus
        assert ReviewStatus.CLASSIFIED in CLASSIFICATION_STATUSES

    def test_not_applicable_is_in_classification_statuses(self):
        from app.action_classification import CLASSIFICATION_STATUSES
        from app.review_status import ReviewStatus
        assert ReviewStatus.NOT_APPLICABLE in CLASSIFICATION_STATUSES

    def test_queue_only_statuses_not_in_classification_statuses(self):
        """deferred, needs-research, unclassified must not be valid in classification context."""
        from app.action_classification import CLASSIFICATION_STATUSES
        from app.review_status import ReviewStatus
        queue_only = {
            ReviewStatus.UNCLASSIFIED,
            ReviewStatus.DEFERRED,
            ReviewStatus.NEEDS_RESEARCH,
        }
        overlap = queue_only & CLASSIFICATION_STATUSES
        assert not overlap, (
            f"Queue-only statuses must not appear in CLASSIFICATION_STATUSES: "
            f"{sorted(str(s) for s in overlap)!r}"
        )


# ---------------------------------------------------------------------------
# 7. Every capability name in the files is lowercase-kebab-case
# ---------------------------------------------------------------------------

class TestCapabilityNameFormat:
    """Capability names must follow lowercase-kebab-case across all files."""

    import re as _re
    _KEBAB = _re.compile(r"^[a-z][a-z0-9-]+$")

    def _check_caps(self, caps: set[str], source: str) -> None:
        import re
        bad = [c for c in caps if not re.match(r"^[a-z][a-z0-9-]+$", c)]
        assert not bad, (
            f"Non-lowercase-kebab capability names found in {source}: {sorted(bad)!r}"
        )

    def test_taxonomy_names_are_kebab_case(self):
        data = _load(_CAPABILITIES_FILE)
        self._check_caps(set(data.get("capabilities", {}).keys()), "capabilities.yaml")

    def test_classification_capability_values_are_kebab_case(self):
        data = _load(_CLASSIFICATION_FILE)
        caps: set[str] = set()
        for record in data.get("actions", {}).values():
            caps.update(record.get("capabilities", []))
        self._check_caps(caps, "action_classification.yaml")

    def test_composite_rule_capability_values_are_kebab_case(self):
        data = _load(_COMPOSITE_FILE)
        caps: set[str] = set()
        for rule in data.get("rules", []):
            caps.update(rule.get("required_capabilities", []))
            caps.update(rule.get("optional_capabilities", []))
        self._check_caps(caps, "composite_detections.yaml")
