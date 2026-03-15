"""Tests for app/data/review_queue.schema.json.

Covers
------
- File existence and parseable as JSON Schema
- Top-level structure: $schema, $id, required fields, additionalProperties
- Root document: required field enforcement, additionalProperties rejection
- ReviewItem: required field enforcement, additionalProperties rejection
- ReviewItem.status: only the five ReviewStatus values are accepted
- ReviewItem.access_level: only the five AWS access-level strings are accepted
- ReviewItem.action: pattern ``^[a-zA-Z0-9-]+:[A-Za-z0-9]+$`` is enforced
- ReviewItem.items: array types enforced (resource_types, condition_keys, etc.)
- Valid documents (empty and non-empty items arrays) validate without error

Each ``TestInvalid*`` class tests one specific constraint violation so that
failures are narrow and the reason is unambiguous.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest

_SCHEMA_FILE = (
    Path(__file__).resolve().parent.parent / "app" / "data" / "review_queue.schema.json"
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(_SCHEMA_FILE.read_text(encoding="utf-8"))


def _valid_item(**overrides) -> dict:
    """Return a minimal valid ReviewItem dict."""
    base: dict = {
        "action": "iam:CreateUser",
        "service": "iam",
        "name": "CreateUser",
        "access_level": "Write",
        "resource_types": [],
        "condition_keys": [],
        "dependent_actions": [],
        "status": "unclassified",
        "candidate_capabilities": [],
        "notes": "",
        "reason": "New action found in catalog version 2.",
    }
    base.update(overrides)
    return base


def _valid_doc(**overrides) -> dict:
    """Return a minimal valid root document dict."""
    base: dict = {
        "generated_at": "2026-03-14T17:22:09+00:00",
        "source_catalog_version": 1,
        "items": [],
    }
    base.update(overrides)
    return base


def _assert_valid(schema: dict, doc: dict) -> None:
    jsonschema.validate(instance=doc, schema=schema)


def _assert_invalid(schema: dict, doc: dict) -> None:
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=doc, schema=schema)


# ---------------------------------------------------------------------------
# Schema file structure
# ---------------------------------------------------------------------------

class TestSchemaFileStructure:
    """The schema file itself must be well-formed and contain expected metadata."""

    def test_file_exists(self):
        assert _SCHEMA_FILE.exists(), f"Schema file not found at {_SCHEMA_FILE}"

    def test_file_is_valid_json(self):
        content = _SCHEMA_FILE.read_text(encoding="utf-8")
        data = json.loads(content)
        assert isinstance(data, dict)

    def test_schema_version_field_present(self, schema):
        assert "$schema" in schema

    def test_id_field_present(self, schema):
        assert "$id" in schema

    def test_title_field_present(self, schema):
        assert "title" in schema

    def test_root_type_is_object(self, schema):
        assert schema.get("type") == "object"

    def test_root_has_required_array(self, schema):
        required = schema.get("required", [])
        assert "generated_at" in required
        assert "source_catalog_version" in required
        assert "items" in required

    def test_root_has_additional_properties_false(self, schema):
        assert schema.get("additionalProperties") is False

    def test_definitions_block_present(self, schema):
        assert "definitions" in schema

    def test_review_item_definition_present(self, schema):
        assert "ReviewItem" in schema["definitions"]

    def test_review_item_has_additional_properties_false(self, schema):
        review_item = schema["definitions"]["ReviewItem"]
        assert review_item.get("additionalProperties") is False

    def test_review_item_required_lists_all_expected_fields(self, schema):
        required = set(schema["definitions"]["ReviewItem"].get("required", []))
        expected = {
            "action", "service", "name", "access_level",
            "resource_types", "condition_keys", "dependent_actions",
            "status", "candidate_capabilities", "notes", "reason",
        }
        missing = expected - required
        assert not missing, f"ReviewItem.required is missing fields: {sorted(missing)}"

    def test_status_enum_has_five_values(self, schema):
        status_prop = schema["definitions"]["ReviewItem"]["properties"]["status"]
        assert len(status_prop["enum"]) == 5

    def test_status_enum_contains_all_review_status_values(self, schema):
        """Schema status enum must contain exactly the five ReviewStatus values."""
        from app.review_status import ReviewStatus
        schema_values = set(schema["definitions"]["ReviewItem"]["properties"]["status"]["enum"])
        enum_values = {s.value for s in ReviewStatus}
        assert schema_values == enum_values, (
            f"Schema status enum {sorted(schema_values)!r} differs from "
            f"ReviewStatus values {sorted(enum_values)!r}"
        )

    def test_access_level_enum_has_five_values(self, schema):
        al = schema["definitions"]["ReviewItem"]["properties"]["access_level"]
        assert len(al["enum"]) == 5

    def test_access_level_enum_values(self, schema):
        al = schema["definitions"]["ReviewItem"]["properties"]["access_level"]
        expected = {"List", "Read", "Write", "Tagging", "Permissions management"}
        assert set(al["enum"]) == expected

    def test_action_property_has_pattern(self, schema):
        action = schema["definitions"]["ReviewItem"]["properties"]["action"]
        assert "pattern" in action, "action property must have a regex pattern"


# ---------------------------------------------------------------------------
# Valid documents — must validate without error
# ---------------------------------------------------------------------------

class TestValidDocuments:
    """Happy-path: documents that fully conform to the schema must validate."""

    def test_empty_items_array_is_valid(self, schema):
        _assert_valid(schema, _valid_doc(items=[]))

    def test_document_with_one_item_is_valid(self, schema):
        _assert_valid(schema, _valid_doc(items=[_valid_item()]))

    def test_document_with_all_status_values_is_valid(self, schema):
        statuses = [
            "unclassified", "classified", "deferred",
            "needs-research", "not-applicable",
        ]
        items = [_valid_item(status=s, action=f"s3:Action{i}") for i, s in enumerate(statuses)]
        _assert_valid(schema, _valid_doc(items=items))

    def test_all_access_level_values_are_valid(self, schema):
        levels = ["List", "Read", "Write", "Tagging", "Permissions management"]
        for level in levels:
            item = _valid_item(access_level=level)
            _assert_valid(schema, _valid_doc(items=[item]))

    def test_item_with_non_empty_arrays_is_valid(self, schema):
        item = _valid_item(
            resource_types=["role"],
            condition_keys=["aws:RequestedRegion"],
            dependent_actions=["iam:PassRole"],
            candidate_capabilities=["privilege-delegation"],
            notes="Reviewer notes here.",
            reason="Action appeared in catalog diff.",
        )
        _assert_valid(schema, _valid_doc(items=[item]))

    def test_item_with_notes_string_is_valid(self, schema):
        _assert_valid(schema, _valid_doc(items=[_valid_item(notes="Any free-form text.")]))

    def test_large_catalog_version_is_valid(self, schema):
        _assert_valid(schema, _valid_doc(source_catalog_version=999))


# ---------------------------------------------------------------------------
# Invalid root document — missing required fields
# ---------------------------------------------------------------------------

class TestInvalidRootMissingFields:
    """Root document must have all three required fields."""

    @pytest.mark.parametrize("field", ["generated_at", "source_catalog_version", "items"])
    def test_missing_root_field_fails(self, schema, field):
        doc = _valid_doc()
        del doc[field]
        _assert_invalid(schema, doc)

    def test_extra_root_property_fails(self, schema):
        doc = _valid_doc(unknown_extra_field="surprise")
        _assert_invalid(schema, doc)


# ---------------------------------------------------------------------------
# Invalid ReviewItem — missing required fields
# ---------------------------------------------------------------------------

class TestInvalidItemMissingFields:
    """Every required field on ReviewItem must be present."""

    @pytest.mark.parametrize("field", [
        "action", "service", "name", "access_level",
        "resource_types", "condition_keys", "dependent_actions",
        "status", "candidate_capabilities", "notes", "reason",
    ])
    def test_missing_item_field_fails(self, schema, field):
        item = _valid_item()
        del item[field]
        doc = _valid_doc(items=[item])
        _assert_invalid(schema, doc)


# ---------------------------------------------------------------------------
# Invalid ReviewItem — additionalProperties
# ---------------------------------------------------------------------------

class TestInvalidItemExtraProperties:
    """Extra properties on a ReviewItem must be rejected."""

    def test_extra_item_property_fails(self, schema):
        item = _valid_item(reviewer="alice")
        _assert_invalid(schema, _valid_doc(items=[item]))

    def test_extra_item_property_fails_with_known_name(self, schema):
        """An extra property that looks like a real field name must still fail."""
        item = _valid_item(priority="high")
        _assert_invalid(schema, _valid_doc(items=[item]))


# ---------------------------------------------------------------------------
# Invalid ReviewItem — status enum enforcement
# ---------------------------------------------------------------------------

class TestInvalidItemStatus:
    """Status field must be one of the five ReviewStatus values exactly."""

    @pytest.mark.parametrize("bad_status", [
        "pending",
        "done",
        "approved",
        "skipped",
        "in-progress",
        "unknown",
        "",
        "UNCLASSIFIED",        # wrong case
        "Classified",          # wrong case
        "needs_research",      # underscore variant
        "not_applicable",      # underscore variant
    ])
    def test_unknown_status_fails(self, schema, bad_status):
        item = _valid_item(status=bad_status)
        _assert_invalid(schema, _valid_doc(items=[item]))

    def test_status_must_be_string(self, schema):
        item = _valid_item()
        item["status"] = 42
        _assert_invalid(schema, _valid_doc(items=[item]))

    def test_status_null_fails(self, schema):
        item = _valid_item()
        item["status"] = None
        _assert_invalid(schema, _valid_doc(items=[item]))


# ---------------------------------------------------------------------------
# Invalid ReviewItem — access_level enum enforcement
# ---------------------------------------------------------------------------

class TestInvalidItemAccessLevel:
    """access_level must be one of the five AWS-defined access level strings."""

    @pytest.mark.parametrize("bad_level", [
        "write",              # lowercase
        "READ",               # uppercase
        "Admin",
        "execute",
        "",
        "permissions management",  # lowercase
        "PermissionsManagement",   # camel case
    ])
    def test_unknown_access_level_fails(self, schema, bad_level):
        item = _valid_item(access_level=bad_level)
        _assert_invalid(schema, _valid_doc(items=[item]))


# ---------------------------------------------------------------------------
# Invalid ReviewItem — action pattern enforcement
# ---------------------------------------------------------------------------

class TestInvalidItemActionPattern:
    """action must match ``^[a-zA-Z0-9-]+:[A-Za-z0-9]+$``."""

    @pytest.mark.parametrize("bad_action", [
        "iam",                   # no colon
        ":CreateUser",           # empty service prefix
        "iam:",                  # empty action name
        "iam:Create User",       # space in name
        "iam:Create-User",       # hyphen in action name
        "iam:create_user",       # underscore in action name
        "iam:CreateUser:Extra",  # too many colons
        "",                      # empty string
    ])
    def test_invalid_action_pattern_fails(self, schema, bad_action):
        item = _valid_item(action=bad_action)
        _assert_invalid(schema, _valid_doc(items=[item]))

    @pytest.mark.parametrize("valid_action", [
        "iam:CreateUser",
        "s3:GetObject",
        "ec2:RunInstances",
        "lambda:CreateFunction",
        "secretsmanager:GetSecretValue",
        "kms:Decrypt",
    ])
    def test_valid_action_pattern_passes(self, schema, valid_action):
        item = _valid_item(action=valid_action)
        _assert_valid(schema, _valid_doc(items=[item]))


# ---------------------------------------------------------------------------
# Invalid ReviewItem — array field type enforcement
# ---------------------------------------------------------------------------

class TestInvalidItemArrayFields:
    """resource_types, condition_keys, dependent_actions, candidate_capabilities must be arrays."""

    @pytest.mark.parametrize("field", [
        "resource_types", "condition_keys", "dependent_actions", "candidate_capabilities",
    ])
    def test_string_instead_of_array_fails(self, schema, field):
        item = _valid_item(**{field: "not-a-list"})
        _assert_invalid(schema, _valid_doc(items=[item]))

    @pytest.mark.parametrize("field", [
        "resource_types", "condition_keys", "dependent_actions", "candidate_capabilities",
    ])
    def test_null_instead_of_array_fails(self, schema, field):
        item = _valid_item()
        item[field] = None
        _assert_invalid(schema, _valid_doc(items=[item]))


# ---------------------------------------------------------------------------
# Invalid ReviewItem — string field type enforcement
# ---------------------------------------------------------------------------

class TestInvalidItemStringFields:
    """notes and reason must be strings (empty string is allowed)."""

    @pytest.mark.parametrize("field", ["notes", "reason"])
    def test_integer_instead_of_string_fails(self, schema, field):
        item = _valid_item(**{field: 0})
        _assert_invalid(schema, _valid_doc(items=[item]))

    @pytest.mark.parametrize("field", ["notes", "reason"])
    def test_null_instead_of_string_fails(self, schema, field):
        item = _valid_item()
        item[field] = None
        _assert_invalid(schema, _valid_doc(items=[item]))

    @pytest.mark.parametrize("field", ["notes", "reason"])
    def test_empty_string_is_valid(self, schema, field):
        item = _valid_item(**{field: ""})
        _assert_valid(schema, _valid_doc(items=[item]))
