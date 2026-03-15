"""Unit tests for generate_review_queue() in scripts/sync_aws_catalog.py.

All tests are pure (no I/O, no network).  The generator is imported directly
from the script so coverage is attributed correctly.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Make the scripts/ directory importable without installing the package.
# ---------------------------------------------------------------------------
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from sync_aws_catalog import generate_review_queue  # noqa: E402

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "app" / "data" / "review_queue.schema.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _catalog(actions: dict, version: int = 1) -> dict:
    """Build a minimal catalog dict."""
    return {
        "version": version,
        "generated_at": "2026-03-14T17:22:09+00:00",
        "source": {"name": "AWS Service Authorization Reference"},
        "actions": actions,
    }


def _action(service: str, name: str, access_level: str = "Read") -> dict:
    """Build a minimal ActionMetadata-compatible dict."""
    return {
        "service": service,
        "name": name,
        "access_level": access_level,
        "resource_types": [],
        "condition_keys": [],
        "dependent_actions": [],
    }


# ---------------------------------------------------------------------------
# Top-level structure
# ---------------------------------------------------------------------------

class TestTopLevelStructure:
    def test_required_keys_present(self):
        result = generate_review_queue(_catalog({}), classified_actions=set())
        assert "generated_at" in result
        assert "source_catalog_version" in result
        assert "items" in result

    def test_no_extra_top_level_keys(self):
        result = generate_review_queue(_catalog({}), classified_actions=set())
        assert set(result.keys()) == {"generated_at", "source_catalog_version", "items"}

    def test_source_catalog_version_matches_catalog(self):
        result = generate_review_queue(_catalog({}, version=7), classified_actions=set())
        assert result["source_catalog_version"] == 7

    def test_generated_at_is_utc_iso8601(self):
        result = generate_review_queue(_catalog({}), classified_actions=set())
        dt = datetime.fromisoformat(result["generated_at"])
        assert dt.tzinfo is not None, "generated_at must include timezone offset"

    def test_items_is_list(self):
        result = generate_review_queue(_catalog({}), classified_actions=set())
        assert isinstance(result["items"], list)


# ---------------------------------------------------------------------------
# Inclusion / exclusion logic
# ---------------------------------------------------------------------------

class TestInclusionExclusion:
    def test_empty_catalog_produces_no_items(self):
        result = generate_review_queue(_catalog({}), classified_actions=set())
        assert result["items"] == []

    def test_all_classified_produces_no_items(self):
        actions = {
            "iam:PassRole": _action("iam", "PassRole", "Write"),
            "s3:GetObject": _action("s3", "GetObject", "Read"),
        }
        classified = {"iam:passrole", "s3:getobject"}
        result = generate_review_queue(_catalog(actions), classified)
        assert result["items"] == []

    def test_unclassified_action_is_included(self):
        actions = {"s3:ListBuckets": _action("s3", "ListBuckets", "List")}
        result = generate_review_queue(_catalog(actions), classified_actions=set())
        assert len(result["items"]) == 1
        assert result["items"][0]["action"] == "s3:ListBuckets"

    def test_classified_action_is_excluded(self):
        actions = {
            "iam:PassRole": _action("iam", "PassRole", "Write"),
            "s3:ListBuckets": _action("s3", "ListBuckets", "List"),
        }
        result = generate_review_queue(_catalog(actions), classified_actions={"iam:passrole"})
        keys = [item["action"] for item in result["items"]]
        assert "iam:PassRole" not in keys
        assert "s3:ListBuckets" in keys

    def test_mixed_catalog_only_unclassified_appear(self):
        actions = {
            "ec2:DescribeInstances": _action("ec2", "DescribeInstances", "List"),
            "iam:CreateUser": _action("iam", "CreateUser", "Write"),
            "iam:PassRole": _action("iam", "PassRole", "Write"),
            "s3:GetObject": _action("s3", "GetObject", "Read"),
        }
        classified = {"iam:passrole", "s3:getobject"}
        result = generate_review_queue(_catalog(actions), classified)
        keys = [item["action"] for item in result["items"]]
        assert sorted(keys) == ["ec2:DescribeInstances", "iam:CreateUser"]

    def test_classification_lookup_is_case_insensitive(self):
        """Catalog keys are mixed-case; classified_actions are lowercase (as
        load_risky_actions returns them).  The comparison must be insensitive."""
        actions = {"IAM:PassRole": _action("IAM", "PassRole", "Write")}
        classified = {"iam:passrole"}
        result = generate_review_queue(_catalog(actions), classified)
        assert result["items"] == []


# ---------------------------------------------------------------------------
# Deterministic ordering
# ---------------------------------------------------------------------------

class TestOrdering:
    def test_items_are_sorted_by_action_key(self):
        actions = {
            "s3:PutObject": _action("s3", "PutObject", "Write"),
            "ec2:RunInstances": _action("ec2", "RunInstances", "Write"),
            "iam:CreateUser": _action("iam", "CreateUser", "Write"),
            "a2c:StartJob": _action("a2c", "StartJob", "Write"),
        }
        result = generate_review_queue(_catalog(actions), classified_actions=set())
        keys = [item["action"] for item in result["items"]]
        assert keys == sorted(keys)

    def test_sort_is_stable_across_repeated_calls(self):
        actions = {
            "z:ZAction": _action("z", "ZAction"),
            "a:AAction": _action("a", "AAction"),
            "m:MAction": _action("m", "MAction"),
        }
        first = generate_review_queue(_catalog(actions), classified_actions=set())
        second = generate_review_queue(_catalog(actions), classified_actions=set())
        assert (
            [i["action"] for i in first["items"]]
            == [i["action"] for i in second["items"]]
        )


# ---------------------------------------------------------------------------
# Item field correctness
# ---------------------------------------------------------------------------

class TestItemFields:
    def test_all_required_item_fields_present(self):
        required = {
            "action", "service", "name", "access_level",
            "resource_types", "condition_keys", "dependent_actions",
            "status", "candidate_capabilities", "notes", "reason",
        }
        actions = {"iam:CreateUser": _action("iam", "CreateUser", "Write")}
        result = generate_review_queue(_catalog(actions), classified_actions=set())
        assert set(result["items"][0].keys()) == required

    def test_status_is_always_unclassified(self):
        actions = {
            "iam:CreateUser": _action("iam", "CreateUser", "Write"),
            "s3:ListBuckets": _action("s3", "ListBuckets", "List"),
        }
        result = generate_review_queue(_catalog(actions), classified_actions=set())
        for item in result["items"]:
            assert item["status"] == "unclassified"

    def test_candidate_capabilities_is_empty_list(self):
        actions = {"iam:CreateUser": _action("iam", "CreateUser", "Write")}
        result = generate_review_queue(_catalog(actions), classified_actions=set())
        assert result["items"][0]["candidate_capabilities"] == []

    def test_notes_is_empty_string(self):
        actions = {"iam:CreateUser": _action("iam", "CreateUser", "Write")}
        result = generate_review_queue(_catalog(actions), classified_actions=set())
        assert result["items"][0]["notes"] == ""

    def test_reason_references_catalog_version(self):
        actions = {"iam:CreateUser": _action("iam", "CreateUser", "Write")}
        result = generate_review_queue(_catalog(actions, version=5), classified_actions=set())
        assert "5" in result["items"][0]["reason"]

    def test_catalog_facts_are_preserved_verbatim(self):
        actions = {
            "kms:Decrypt": {
                "service": "kms",
                "name": "Decrypt",
                "access_level": "Write",
                "resource_types": ["key"],
                "condition_keys": ["kms:ViaService"],
                "dependent_actions": ["kms:DescribeKey"],
            }
        }
        result = generate_review_queue(_catalog(actions), classified_actions=set())
        item = result["items"][0]
        assert item["service"] == "kms"
        assert item["name"] == "Decrypt"
        assert item["access_level"] == "Write"
        assert item["resource_types"] == ["key"]
        assert item["condition_keys"] == ["kms:ViaService"]
        assert item["dependent_actions"] == ["kms:DescribeKey"]

    def test_empty_catalog_metadata_arrays_produce_empty_lists(self):
        actions = {"s3:ListBuckets": _action("s3", "ListBuckets", "List")}
        result = generate_review_queue(_catalog(actions), classified_actions=set())
        item = result["items"][0]
        assert item["resource_types"] == []
        assert item["condition_keys"] == []
        assert item["dependent_actions"] == []


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

class TestSchemaValidation:
    def test_output_validates_against_review_queue_schema(self):
        jsonschema = pytest.importorskip("jsonschema")

        with open(_SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)

        actions = {
            "iam:CreateUser": _action("iam", "CreateUser", "Write"),
            "kms:Decrypt": {
                "service": "kms",
                "name": "Decrypt",
                "access_level": "Write",
                "resource_types": ["key"],
                "condition_keys": ["kms:ViaService"],
                "dependent_actions": [],
            },
            "s3:ListBuckets": _action("s3", "ListBuckets", "List"),
        }
        result = generate_review_queue(
            _catalog(actions, version=2),
            classified_actions={"iam:createuser"},
        )

        jsonschema.validate(
            instance=result,
            schema=schema,
            format_checker=jsonschema.FormatChecker(),
        )
