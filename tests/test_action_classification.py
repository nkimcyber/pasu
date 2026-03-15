"""Tests for app/action_classification.py and app/rules/action_classification.yaml.

Covers:
- YAML file structure and governance
- CONFIDENCE_LEVELS and CLASSIFICATION_STATUSES constants
- validate_confidence: accepts/rejects
- validate_record: field presence, status constraint, capability constraint,
  confidence constraint, notes type, classified-requires-capabilities rule
- load_action_classification: happy path, missing file, bad JSON, missing actions key
- Required example entries (iam:PassRole, ec2:RunInstances)
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from app.action_classification import (
    CLASSIFICATION_STATUSES,
    CONFIDENCE_LEVELS,
    _CLASSIFICATION_FILE,
    load_action_classification,
    validate_confidence,
    validate_record,
)
from app.review_status import ReviewStatus

_YAML_PATH = Path(__file__).resolve().parent.parent / "app" / "rules" / "action_classification.yaml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_classified() -> dict:
    return {
        "status": "classified",
        "capabilities": ["secret-read"],
        "confidence": "high",
        "notes": "",
    }


def _valid_not_applicable() -> dict:
    return {
        "status": "not-applicable",
        "capabilities": [],
        "confidence": "high",
        "notes": "Read-only enumeration, no escalation path.",
    }


# ---------------------------------------------------------------------------
# YAML file structure
# ---------------------------------------------------------------------------

class TestYamlFileStructure:
    def test_file_exists(self):
        assert _YAML_PATH.exists(), f"Expected file at {_YAML_PATH}"

    def test_file_is_valid_json(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_governance_block_present(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        assert "_governance" in data

    def test_field_reference_block_present(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        assert "_field_reference" in data

    def test_field_reference_documents_all_required_fields(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        fr = data["_field_reference"]
        for field in ("status", "capabilities", "confidence", "notes"):
            assert field in fr, f"_field_reference missing documentation for '{field}'"

    def test_actions_block_present(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        assert "actions" in data and isinstance(data["actions"], dict)

    def test_actions_block_non_empty(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        assert len(data["actions"]) >= 2

    def test_governance_references_status_constraint(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        gov = data["_governance"]
        constraints = gov.get("field_constraints", {})
        status_note = constraints.get("status", "")
        assert "classified" in status_note, (
            "_governance.field_constraints.status must mention 'classified'"
        )

    def test_governance_references_capability_constraint(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        gov = data["_governance"]
        constraints = gov.get("field_constraints", {})
        caps_note = constraints.get("capabilities", "")
        assert "capabilities.yaml" in caps_note, (
            "_governance.field_constraints.capabilities must reference capabilities.yaml"
        )


# ---------------------------------------------------------------------------
# Required example entries
# ---------------------------------------------------------------------------

class TestRequiredExamples:
    def _actions(self) -> dict:
        return json.loads(_YAML_PATH.read_text(encoding="utf-8"))["actions"]

    def test_iam_pass_role_present(self):
        assert "iam:PassRole" in self._actions()

    def test_ec2_run_instances_present(self):
        assert "ec2:RunInstances" in self._actions()

    def test_iam_pass_role_is_classified(self):
        record = self._actions()["iam:PassRole"]
        assert record["status"] == "classified"

    def test_iam_pass_role_has_privilege_delegation(self):
        record = self._actions()["iam:PassRole"]
        assert "privilege-delegation" in record["capabilities"]

    def test_ec2_run_instances_is_classified(self):
        record = self._actions()["ec2:RunInstances"]
        assert record["status"] == "classified"

    def test_ec2_run_instances_has_compute_with_role(self):
        record = self._actions()["ec2:RunInstances"]
        assert "compute-with-role" in record["capabilities"]

    def test_all_example_entries_pass_validate_record(self):
        for key, record in self._actions().items():
            validate_record(key, record)   # must not raise


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_confidence_levels_contains_expected_values(self):
        assert CONFIDENCE_LEVELS == frozenset({"high", "medium", "low"})

    def test_confidence_levels_is_frozenset(self):
        assert isinstance(CONFIDENCE_LEVELS, frozenset)

    def test_classification_statuses_is_frozenset_of_review_status(self):
        assert isinstance(CLASSIFICATION_STATUSES, frozenset)
        for s in CLASSIFICATION_STATUSES:
            assert isinstance(s, ReviewStatus)

    def test_classified_in_classification_statuses(self):
        assert ReviewStatus.CLASSIFIED in CLASSIFICATION_STATUSES

    def test_not_applicable_in_classification_statuses(self):
        assert ReviewStatus.NOT_APPLICABLE in CLASSIFICATION_STATUSES

    def test_queue_only_statuses_not_in_classification_statuses(self):
        queue_only = {
            ReviewStatus.UNCLASSIFIED,
            ReviewStatus.DEFERRED,
            ReviewStatus.NEEDS_RESEARCH,
        }
        assert not (queue_only & CLASSIFICATION_STATUSES)


# ---------------------------------------------------------------------------
# validate_confidence
# ---------------------------------------------------------------------------

class TestValidateConfidenceAccepts:
    @pytest.mark.parametrize("level", ["high", "medium", "low"])
    def test_accepts_each_valid_level(self, level: str):
        assert validate_confidence(level) == level

    def test_returns_value_unchanged(self):
        assert validate_confidence("medium") == "medium"


class TestValidateConfidenceRejects:
    @pytest.mark.parametrize("bad", [
        "certain", "very-high", "none", "unknown", "HIGH", "Medium", "", "1",
    ])
    def test_rejects_invalid_level(self, bad: str):
        with pytest.raises(ValueError):
            validate_confidence(bad)

    def test_error_names_rejected_value(self):
        with pytest.raises(ValueError, match="certain"):
            validate_confidence("certain")

    def test_error_lists_allowed_values(self):
        with pytest.raises(ValueError, match="high"):
            validate_confidence("bogus")


# ---------------------------------------------------------------------------
# validate_record — field presence
# ---------------------------------------------------------------------------

class TestValidateRecordFieldPresence:
    def test_valid_classified_record_passes(self):
        validate_record("kms:Decrypt", _valid_classified())

    def test_valid_not_applicable_record_passes(self):
        validate_record("ec2:DescribeInstances", _valid_not_applicable())

    @pytest.mark.parametrize("field", ["status", "capabilities", "confidence", "notes"])
    def test_missing_required_field_raises(self, field: str):
        record = _valid_classified()
        del record[field]
        with pytest.raises(ValueError, match="missing required fields"):
            validate_record("kms:Decrypt", record)


# ---------------------------------------------------------------------------
# validate_record — status field
# ---------------------------------------------------------------------------

class TestValidateRecordStatus:
    def test_classified_is_accepted(self):
        record = _valid_classified()
        record["status"] = "classified"
        validate_record("kms:Decrypt", record)

    def test_not_applicable_is_accepted(self):
        validate_record("ec2:DescribeInstances", _valid_not_applicable())

    @pytest.mark.parametrize("queue_only", [
        "unclassified", "deferred", "needs-research",
    ])
    def test_queue_only_status_is_rejected(self, queue_only: str):
        record = _valid_classified()
        record["status"] = queue_only
        with pytest.raises(ValueError):
            validate_record("iam:CreateUser", record)

    def test_unknown_status_string_is_rejected(self):
        record = _valid_classified()
        record["status"] = "pending"
        with pytest.raises(ValueError):
            validate_record("iam:CreateUser", record)

    def test_error_names_the_action_key(self):
        record = _valid_classified()
        record["status"] = "unclassified"
        with pytest.raises(ValueError, match="iam:CreateUser"):
            validate_record("iam:CreateUser", record)


# ---------------------------------------------------------------------------
# validate_record — capabilities field
# ---------------------------------------------------------------------------

class TestValidateRecordCapabilities:
    def test_valid_capability_list_passes(self):
        record = _valid_classified()
        record["capabilities"] = ["secret-read", "public-exposure"]
        validate_record("kms:Decrypt", record)

    def test_empty_capabilities_allowed_for_not_applicable(self):
        record = _valid_not_applicable()
        record["capabilities"] = []
        validate_record("ec2:DescribeInstances", record)

    def test_empty_capabilities_rejected_for_classified(self):
        record = _valid_classified()
        record["capabilities"] = []
        with pytest.raises(ValueError, match="capabilities must not be empty"):
            validate_record("kms:Decrypt", record)

    def test_unknown_capability_is_rejected(self):
        record = _valid_classified()
        record["capabilities"] = ["exfiltration"]
        with pytest.raises(ValueError):
            validate_record("kms:Decrypt", record)

    def test_non_list_capabilities_is_rejected(self):
        record = _valid_classified()
        record["capabilities"] = "secret-read"   # string, not list
        with pytest.raises(ValueError, match="list"):
            validate_record("kms:Decrypt", record)

    def test_all_invalid_capabilities_reported_together(self):
        record = _valid_classified()
        record["capabilities"] = ["bad-one", "bad-two"]
        with pytest.raises(ValueError) as exc_info:
            validate_record("kms:Decrypt", record)
        msg = str(exc_info.value)
        assert "bad-one" in msg
        assert "bad-two" in msg


# ---------------------------------------------------------------------------
# validate_record — confidence field
# ---------------------------------------------------------------------------

class TestValidateRecordConfidence:
    @pytest.mark.parametrize("level", ["high", "medium", "low"])
    def test_valid_confidence_passes(self, level: str):
        record = _valid_classified()
        record["confidence"] = level
        validate_record("kms:Decrypt", record)

    def test_unknown_confidence_is_rejected(self):
        record = _valid_classified()
        record["confidence"] = "certain"
        with pytest.raises(ValueError):
            validate_record("kms:Decrypt", record)


# ---------------------------------------------------------------------------
# validate_record — notes field
# ---------------------------------------------------------------------------

class TestValidateRecordNotes:
    def test_empty_string_notes_passes(self):
        record = _valid_classified()
        record["notes"] = ""
        validate_record("kms:Decrypt", record)

    def test_non_empty_string_notes_passes(self):
        record = _valid_classified()
        record["notes"] = "Reviewed 2026-03-14."
        validate_record("kms:Decrypt", record)

    def test_non_string_notes_is_rejected(self):
        record = _valid_classified()
        record["notes"] = 42
        with pytest.raises(ValueError, match="notes must be a string"):
            validate_record("kms:Decrypt", record)


# ---------------------------------------------------------------------------
# load_action_classification
# ---------------------------------------------------------------------------

class TestLoadActionClassification:
    def test_loads_default_file_without_error(self):
        actions = load_action_classification()
        assert isinstance(actions, dict)
        assert len(actions) >= 2

    def test_returns_only_actions_dict(self):
        actions = load_action_classification()
        # _governance and _field_reference must not bleed through
        assert "_governance" not in actions
        assert "_field_reference" not in actions

    def test_iam_pass_role_in_loaded_actions(self):
        actions = load_action_classification()
        assert "iam:PassRole" in actions

    def test_ec2_run_instances_in_loaded_actions(self):
        actions = load_action_classification()
        assert "ec2:RunInstances" in actions

    def test_missing_file_raises_runtime_error(self, tmp_path: Path):
        with pytest.raises(RuntimeError, match="not found"):
            load_action_classification(tmp_path / "nonexistent.yaml")

    def test_invalid_json_raises_runtime_error(self, tmp_path: Path):
        bad = tmp_path / "action_classification.yaml"
        bad.write_text("{ not valid json }", encoding="utf-8")
        with pytest.raises(RuntimeError, match="invalid JSON"):
            load_action_classification(bad)

    def test_missing_actions_key_raises_runtime_error(self, tmp_path: Path):
        f = tmp_path / "action_classification.yaml"
        f.write_text(json.dumps({"_governance": {}}), encoding="utf-8")
        with pytest.raises(RuntimeError, match="'actions'"):
            load_action_classification(f)

    def test_invalid_record_raises_value_error(self, tmp_path: Path):
        f = tmp_path / "action_classification.yaml"
        f.write_text(json.dumps({
            "actions": {
                "iam:CreateUser": {
                    "status": "unclassified",   # invalid in classification context
                    "capabilities": [],
                    "confidence": "high",
                    "notes": "",
                }
            }
        }), encoding="utf-8")
        with pytest.raises(ValueError):
            load_action_classification(f)

    def test_multiple_invalid_records_all_reported(self, tmp_path: Path):
        f = tmp_path / "action_classification.yaml"
        f.write_text(json.dumps({
            "actions": {
                "iam:CreateUser": {
                    "status": "unclassified",
                    "capabilities": [],
                    "confidence": "high",
                    "notes": "",
                },
                "s3:GetObject": {
                    "status": "classified",
                    "capabilities": ["not-a-real-cap"],
                    "confidence": "medium",
                    "notes": "",
                },
            }
        }), encoding="utf-8")
        with pytest.raises(ValueError, match="2 invalid"):
            load_action_classification(f)

    def test_custom_path_with_valid_records_loads_cleanly(self, tmp_path: Path):
        f = tmp_path / "action_classification.yaml"
        f.write_text(json.dumps({
            "actions": {
                "iam:PassRole": {
                    "status": "classified",
                    "capabilities": ["privilege-delegation"],
                    "confidence": "high",
                    "notes": "Test entry.",
                }
            }
        }), encoding="utf-8")
        actions = load_action_classification(f)
        assert "iam:PassRole" in actions
