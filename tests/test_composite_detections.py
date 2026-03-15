"""Tests for app/composite_detections.py and app/rules/composite_detections.yaml.

Covers:
- YAML file structure and governance blocks
- SEVERITY_LEVELS and CONFIDENCE_LOGIC_VALUES constants
- validate_severity and validate_confidence_logic
- validate_rule: field presence, id pattern, capability constraints,
  overlap guard, severity/confidence_logic/rationale validation
- load_composite_detections: happy path, missing file, bad JSON,
  missing rules key, duplicate IDs, invalid rules
- Seed rules: all six expected rules present and valid
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from app.composite_detections import (
    CONFIDENCE_LOGIC_VALUES,
    SEVERITY_LEVELS,
    CompositeRule,
    _COMPOSITE_DETECTIONS_FILE,
    load_composite_detections,
    validate_confidence_logic,
    validate_rule,
    validate_severity,
)

_YAML_PATH = (
    Path(__file__).resolve().parent.parent / "app" / "rules" / "composite_detections.yaml"
)

# IDs that must be present in the seed file.
# COMP-001 to COMP-006: original seed rules
# COMP-007 to COMP-010: rules added in the roadmap extension
_REQUIRED_IDS = {
    "COMP-001", "COMP-002", "COMP-003", "COMP-004", "COMP-005",
    "COMP-006", "COMP-007", "COMP-008", "COMP-009", "COMP-010",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_rule(**overrides) -> dict:
    base = {
        "id": "COMP-099",
        "title": "Test Composite Rule",
        "required_capabilities": ["privilege-delegation"],
        "optional_capabilities": [],
        "severity": "high",
        "confidence_logic": "weakest",
        "rationale": "A non-empty rationale string for testing.",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# YAML file structure
# ---------------------------------------------------------------------------

class TestYamlFileStructure:
    def test_file_exists(self):
        assert _YAML_PATH.exists()

    def test_file_is_valid_json(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_governance_block_present(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        assert "_governance" in data

    def test_governance_references_separation_of_concerns(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        sep = data["_governance"].get("separation_of_concerns", "")
        assert len(sep) > 20

    def test_field_reference_block_present(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        assert "_field_reference" in data

    def test_field_reference_documents_all_required_fields(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        fr = data["_field_reference"]
        required = {
            "id", "title", "required_capabilities",
            "optional_capabilities", "severity", "confidence_logic", "rationale",
        }
        for field in required:
            assert field in fr, f"_field_reference missing '{field}'"

    def test_rules_array_present(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        assert "rules" in data
        assert isinstance(data["rules"], list)

    def test_rules_array_non_empty(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        assert len(data["rules"]) >= 6


# ---------------------------------------------------------------------------
# Seed rules presence and validity
# ---------------------------------------------------------------------------

class TestSeedRules:
    def _rules_by_id(self) -> dict:
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        return {r["id"]: r for r in data["rules"] if "id" in r}

    def test_all_required_ids_present(self):
        by_id = self._rules_by_id()
        missing = _REQUIRED_IDS - set(by_id.keys())
        assert not missing, f"Missing rule IDs: {sorted(missing)}"

    def test_all_seed_rules_pass_validate_rule(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        for rule in data["rules"]:
            validate_rule(rule)   # must not raise

    def test_comp001_requires_privilege_delegation_and_compute(self):
        rule = self._rules_by_id()["COMP-001"]
        caps = set(rule["required_capabilities"])
        assert "privilege-delegation" in caps
        assert "compute-with-role" in caps

    def test_comp002_requires_privilege_delegation_and_serverless(self):
        rule = self._rules_by_id()["COMP-002"]
        caps = set(rule["required_capabilities"])
        assert "privilege-delegation" in caps
        assert "serverless-with-role" in caps

    def test_comp003_requires_policy_modification(self):
        rule = self._rules_by_id()["COMP-003"]
        assert "policy-modification" in rule["required_capabilities"]

    def test_comp004_requires_credential_issuance(self):
        rule = self._rules_by_id()["COMP-004"]
        assert "credential-issuance" in rule["required_capabilities"]

    def test_comp005_requires_cross_account_trust_and_data_read(self):
        rule = self._rules_by_id()["COMP-005"]
        caps = set(rule["required_capabilities"])
        assert "cross-account-trust" in caps
        assert "data-read-sensitive" in caps

    def test_comp006_requires_public_exposure(self):
        rule = self._rules_by_id()["COMP-006"]
        assert "public-exposure" in rule["required_capabilities"]

    def test_critical_rules_exist(self):
        by_id = self._rules_by_id()
        critical = [r for r in by_id.values() if r.get("severity") == "critical"]
        assert len(critical) >= 2, "Expected at least two critical-severity rules"

    def test_all_rationales_are_non_empty(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        for rule in data["rules"]:
            assert rule.get("rationale", "").strip(), (
                f"Rule {rule.get('id')!r} has an empty rationale"
            )

    def test_ids_are_unique_in_file(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        ids = [r["id"] for r in data["rules"] if "id" in r]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs detected in file"

    def test_no_capability_overlap_in_any_seed_rule(self):
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        for rule in data["rules"]:
            req = set(rule.get("required_capabilities", []))
            opt = set(rule.get("optional_capabilities", []))
            overlap = req & opt
            assert not overlap, (
                f"Rule {rule.get('id')!r} has capabilities in both lists: {overlap}"
            )

    # ── COMP-007 to COMP-010: roadmap extension rules ────────────────────────

    def test_comp007_requires_policy_modification_and_credential_issuance(self):
        """COMP-007: Persistent Backdoor via Policy Rewrite and Credential Establishment."""
        rule = self._rules_by_id()["COMP-007"]
        caps = set(rule["required_capabilities"])
        assert "policy-modification" in caps
        assert "credential-issuance" in caps

    def test_comp007_is_critical_severity(self):
        rule = self._rules_by_id()["COMP-007"]
        assert rule["severity"] == "critical"

    def test_comp008_requires_cross_account_trust_and_policy_modification(self):
        """COMP-008: Shadow Admin via External Trust and Policy Grant."""
        rule = self._rules_by_id()["COMP-008"]
        caps = set(rule["required_capabilities"])
        assert "cross-account-trust" in caps
        assert "policy-modification" in caps

    def test_comp008_is_critical_severity(self):
        rule = self._rules_by_id()["COMP-008"]
        assert rule["severity"] == "critical"

    def test_comp009_requires_secret_read_and_data_read_sensitive(self):
        """COMP-009: Coordinated Intelligence Harvest."""
        rule = self._rules_by_id()["COMP-009"]
        caps = set(rule["required_capabilities"])
        assert "secret-read" in caps
        assert "data-read-sensitive" in caps

    def test_comp009_has_no_optional_capabilities(self):
        """COMP-009 is intentionally a pure required-capabilities rule."""
        rule = self._rules_by_id()["COMP-009"]
        assert rule.get("optional_capabilities", []) == []

    def test_comp010_requires_data_read_and_data_write_sensitive(self):
        """COMP-010: Ransomware and Double-Extortion Positioning."""
        rule = self._rules_by_id()["COMP-010"]
        caps = set(rule["required_capabilities"])
        assert "data-read-sensitive" in caps
        assert "data-write-sensitive" in caps

    def test_comp010_optional_includes_public_exposure(self):
        """COMP-010 with public-exposure optional raises to double-extortion scenario."""
        rule = self._rules_by_id()["COMP-010"]
        assert "public-exposure" in rule.get("optional_capabilities", [])

    def test_total_seed_rules_count(self):
        """Exactly ten seed rules must be present (COMP-001 through COMP-010)."""
        data = json.loads(_YAML_PATH.read_text(encoding="utf-8"))
        ids = {r["id"] for r in data["rules"] if "id" in r}
        assert len(ids) >= 10, f"Expected at least 10 seed rules, found {len(ids)}"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_severity_levels_contains_expected_values(self):
        assert SEVERITY_LEVELS == frozenset({"critical", "high", "medium", "low"})

    def test_severity_levels_is_frozenset(self):
        assert isinstance(SEVERITY_LEVELS, frozenset)

    def test_confidence_logic_values_contains_expected_values(self):
        assert CONFIDENCE_LOGIC_VALUES == frozenset({"all-high", "weakest", "majority"})

    def test_confidence_logic_values_is_frozenset(self):
        assert isinstance(CONFIDENCE_LOGIC_VALUES, frozenset)


# ---------------------------------------------------------------------------
# validate_severity
# ---------------------------------------------------------------------------

class TestValidateSeverityAccepts:
    @pytest.mark.parametrize("level", ["critical", "high", "medium", "low"])
    def test_accepts_each_valid_level(self, level: str):
        assert validate_severity(level) == level


class TestValidateSeverityRejects:
    @pytest.mark.parametrize("bad", [
        "CRITICAL", "High", "info", "warning", "none", "", "urgent",
    ])
    def test_rejects_invalid_level(self, bad: str):
        with pytest.raises(ValueError):
            validate_severity(bad)

    def test_error_names_rejected_value(self):
        with pytest.raises(ValueError, match="urgent"):
            validate_severity("urgent")

    def test_error_lists_allowed_values(self):
        with pytest.raises(ValueError, match="critical"):
            validate_severity("bogus")


# ---------------------------------------------------------------------------
# validate_confidence_logic
# ---------------------------------------------------------------------------

class TestValidateConfidenceLogicAccepts:
    @pytest.mark.parametrize("value", ["all-high", "weakest", "majority"])
    def test_accepts_each_valid_value(self, value: str):
        assert validate_confidence_logic(value) == value


class TestValidateConfidenceLogicRejects:
    @pytest.mark.parametrize("bad", [
        "ALL-HIGH", "Weakest", "average", "min", "", "strict", "weighted",
    ])
    def test_rejects_invalid_value(self, bad: str):
        with pytest.raises(ValueError):
            validate_confidence_logic(bad)

    def test_error_names_rejected_value(self):
        with pytest.raises(ValueError, match="average"):
            validate_confidence_logic("average")


# ---------------------------------------------------------------------------
# validate_rule — field presence
# ---------------------------------------------------------------------------

class TestValidateRuleFieldPresence:
    def test_valid_rule_passes(self):
        validate_rule(_valid_rule())

    @pytest.mark.parametrize("field", [
        "id", "title", "required_capabilities",
        "optional_capabilities", "severity", "confidence_logic", "rationale",
    ])
    def test_missing_field_raises(self, field: str):
        rule = _valid_rule()
        del rule[field]
        with pytest.raises(ValueError, match="missing required fields"):
            validate_rule(rule)


# ---------------------------------------------------------------------------
# validate_rule — id field
# ---------------------------------------------------------------------------

class TestValidateRuleId:
    @pytest.mark.parametrize("valid_id", ["COMP-001", "COMP-099", "COMP-123"])
    def test_valid_id_passes(self, valid_id: str):
        validate_rule(_valid_rule(id=valid_id))

    @pytest.mark.parametrize("bad_id", [
        "comp-001",        # lowercase prefix
        "COMP-01",         # too few digits
        "COMP-1234",       # too many digits
        "COMP001",         # missing hyphen
        "DET-001",         # wrong prefix
        "COMP-00A",        # non-digit suffix
        "",
        "001",
    ])
    def test_invalid_id_raises(self, bad_id: str):
        with pytest.raises(ValueError):
            validate_rule(_valid_rule(id=bad_id))


# ---------------------------------------------------------------------------
# validate_rule — title field
# ---------------------------------------------------------------------------

class TestValidateRuleTitle:
    def test_non_empty_title_passes(self):
        validate_rule(_valid_rule(title="Some Valid Title"))

    @pytest.mark.parametrize("bad_title", ["", "   "])
    def test_empty_or_whitespace_title_raises(self, bad_title: str):
        with pytest.raises(ValueError):
            validate_rule(_valid_rule(title=bad_title))

    def test_non_string_title_raises(self):
        with pytest.raises(ValueError):
            validate_rule(_valid_rule(title=42))


# ---------------------------------------------------------------------------
# validate_rule — required_capabilities
# ---------------------------------------------------------------------------

class TestValidateRuleRequiredCapabilities:
    def test_valid_single_capability_passes(self):
        validate_rule(_valid_rule(required_capabilities=["secret-read"]))

    def test_valid_multiple_capabilities_passes(self):
        validate_rule(_valid_rule(
            required_capabilities=["privilege-delegation", "compute-with-role"]
        ))

    def test_empty_list_raises(self):
        with pytest.raises(ValueError, match="at least one"):
            validate_rule(_valid_rule(required_capabilities=[]))

    def test_unknown_capability_raises(self):
        with pytest.raises(ValueError):
            validate_rule(_valid_rule(required_capabilities=["exfiltration"]))

    def test_non_list_raises(self):
        with pytest.raises(ValueError, match="list"):
            validate_rule(_valid_rule(required_capabilities="privilege-delegation"))

    def test_all_unknown_capabilities_reported_together(self):
        with pytest.raises(ValueError) as exc_info:
            validate_rule(_valid_rule(required_capabilities=["bad-one", "bad-two"]))
        msg = str(exc_info.value)
        assert "bad-one" in msg
        assert "bad-two" in msg


# ---------------------------------------------------------------------------
# validate_rule — optional_capabilities
# ---------------------------------------------------------------------------

class TestValidateRuleOptionalCapabilities:
    def test_empty_list_passes(self):
        validate_rule(_valid_rule(optional_capabilities=[]))

    def test_valid_capability_passes(self):
        validate_rule(_valid_rule(optional_capabilities=["secret-read"]))

    def test_unknown_capability_raises(self):
        with pytest.raises(ValueError):
            validate_rule(_valid_rule(optional_capabilities=["bogus-cap"]))

    def test_non_list_raises(self):
        with pytest.raises(ValueError, match="list"):
            validate_rule(_valid_rule(optional_capabilities="secret-read"))


# ---------------------------------------------------------------------------
# validate_rule — overlap guard
# ---------------------------------------------------------------------------

class TestValidateRuleCapabilityOverlap:
    def test_no_overlap_passes(self):
        validate_rule(_valid_rule(
            required_capabilities=["privilege-delegation"],
            optional_capabilities=["secret-read"],
        ))

    def test_same_capability_in_both_lists_raises(self):
        with pytest.raises(ValueError, match="both required_capabilities and optional_capabilities"):
            validate_rule(_valid_rule(
                required_capabilities=["privilege-delegation", "secret-read"],
                optional_capabilities=["secret-read"],
            ))

    def test_error_names_overlapping_capability(self):
        with pytest.raises(ValueError, match="secret-read"):
            validate_rule(_valid_rule(
                required_capabilities=["privilege-delegation", "secret-read"],
                optional_capabilities=["secret-read"],
            ))


# ---------------------------------------------------------------------------
# validate_rule — severity and confidence_logic
# ---------------------------------------------------------------------------

class TestValidateRuleSeverityAndConfidenceLogic:
    @pytest.mark.parametrize("sev", ["critical", "high", "medium", "low"])
    def test_valid_severity_passes(self, sev: str):
        validate_rule(_valid_rule(severity=sev))

    def test_invalid_severity_raises(self):
        with pytest.raises(ValueError):
            validate_rule(_valid_rule(severity="urgent"))

    @pytest.mark.parametrize("cl", ["all-high", "weakest", "majority"])
    def test_valid_confidence_logic_passes(self, cl: str):
        validate_rule(_valid_rule(confidence_logic=cl))

    def test_invalid_confidence_logic_raises(self):
        with pytest.raises(ValueError):
            validate_rule(_valid_rule(confidence_logic="average"))


# ---------------------------------------------------------------------------
# validate_rule — rationale
# ---------------------------------------------------------------------------

class TestValidateRuleRationale:
    def test_non_empty_rationale_passes(self):
        validate_rule(_valid_rule(rationale="Why this pattern is dangerous."))

    @pytest.mark.parametrize("bad", ["", "   "])
    def test_empty_or_whitespace_rationale_raises(self, bad: str):
        with pytest.raises(ValueError):
            validate_rule(_valid_rule(rationale=bad))

    def test_non_string_rationale_raises(self):
        with pytest.raises(ValueError):
            validate_rule(_valid_rule(rationale=None))


# ---------------------------------------------------------------------------
# load_composite_detections
# ---------------------------------------------------------------------------

class TestLoadCompositeDetections:
    def test_loads_default_file_without_error(self):
        rules = load_composite_detections()
        assert isinstance(rules, list)
        assert len(rules) >= 6

    def test_returns_only_rules_list(self):
        rules = load_composite_detections()
        # Metadata keys must not bleed through
        assert not any(isinstance(r, str) and r.startswith("_") for r in rules)

    def test_all_required_ids_present_after_load(self):
        rules = load_composite_detections()
        loaded_ids = {r.id for r in rules}
        assert _REQUIRED_IDS <= loaded_ids

    def test_missing_file_raises_runtime_error(self, tmp_path: Path):
        with pytest.raises(RuntimeError, match="not found"):
            load_composite_detections(tmp_path / "nonexistent.yaml")

    def test_invalid_json_raises_runtime_error(self, tmp_path: Path):
        f = tmp_path / "composite_detections.yaml"
        f.write_text("{ not valid json }", encoding="utf-8")
        with pytest.raises(RuntimeError, match="invalid JSON"):
            load_composite_detections(f)

    def test_missing_rules_key_raises_runtime_error(self, tmp_path: Path):
        f = tmp_path / "composite_detections.yaml"
        f.write_text(json.dumps({"_governance": {}}), encoding="utf-8")
        with pytest.raises(RuntimeError, match="'rules'"):
            load_composite_detections(f)

    def test_non_list_rules_raises_runtime_error(self, tmp_path: Path):
        f = tmp_path / "composite_detections.yaml"
        f.write_text(json.dumps({"rules": {}}), encoding="utf-8")
        with pytest.raises(RuntimeError, match="'rules'"):
            load_composite_detections(f)

    def test_invalid_rule_raises_value_error(self, tmp_path: Path):
        f = tmp_path / "composite_detections.yaml"
        f.write_text(json.dumps({"rules": [
            {
                "id": "comp-001",           # wrong case
                "title": "Bad Rule",
                "required_capabilities": [],    # empty — invalid
                "optional_capabilities": [],
                "severity": "critical",
                "confidence_logic": "weakest",
                "rationale": "Test.",
            }
        ]}), encoding="utf-8")
        with pytest.raises(ValueError):
            load_composite_detections(f)

    def test_duplicate_ids_raises_value_error(self, tmp_path: Path):
        rule_a = _valid_rule(id="COMP-001")
        rule_b = _valid_rule(id="COMP-001")   # same ID
        rule_b["title"] = "Duplicate Rule"
        f = tmp_path / "composite_detections.yaml"
        f.write_text(json.dumps({"rules": [rule_a, rule_b]}), encoding="utf-8")
        with pytest.raises(ValueError, match="[Dd]uplicate"):
            load_composite_detections(f)

    def test_custom_path_with_valid_rule_loads_cleanly(self, tmp_path: Path):
        f = tmp_path / "composite_detections.yaml"
        f.write_text(json.dumps({"rules": [_valid_rule(id="COMP-001")]}), encoding="utf-8")
        rules = load_composite_detections(f)
        assert len(rules) == 1
        assert rules[0].id == "COMP-001"

    def test_multiple_invalid_rules_all_reported(self, tmp_path: Path):
        bad_a = _valid_rule(id="comp-001", required_capabilities=[])
        bad_b = _valid_rule(id="COMP-002", severity="urgent")
        f = tmp_path / "composite_detections.yaml"
        f.write_text(json.dumps({"rules": [bad_a, bad_b]}), encoding="utf-8")
        with pytest.raises(ValueError, match="2 error"):
            load_composite_detections(f)

    def test_rules_sorted_by_id(self):
        rules = load_composite_detections()
        ids = [r.id for r in rules]
        assert ids == sorted(ids), "Loader must return rules sorted by ID"

    def test_returns_composite_rule_instances(self):
        rules = load_composite_detections()
        for rule in rules:
            assert isinstance(rule, CompositeRule)

    def test_loader_output_is_sorted_regardless_of_file_order(self, tmp_path: Path):
        """Rules written in reverse order must come back sorted by ID."""
        rule_z = _valid_rule(id="COMP-099")
        rule_a = _valid_rule(id="COMP-001")
        f = tmp_path / "composite_detections.yaml"
        f.write_text(json.dumps({"rules": [rule_z, rule_a]}), encoding="utf-8")
        rules = load_composite_detections(f)
        assert rules[0].id == "COMP-001"
        assert rules[1].id == "COMP-099"


# ---------------------------------------------------------------------------
# CompositeRule dataclass
# ---------------------------------------------------------------------------

class TestCompositeRule:
    """Contract tests for the CompositeRule typed object."""

    def _load_first(self) -> CompositeRule:
        return load_composite_detections()[0]

    # ── positive: attributes are accessible ──────────────────────────────────

    def test_id_attribute(self):
        rule = self._load_first()
        assert isinstance(rule.id, str)
        assert rule.id.startswith("COMP-")

    def test_title_attribute(self):
        rule = self._load_first()
        assert isinstance(rule.title, str)
        assert rule.title.strip()

    def test_required_capabilities_is_tuple(self):
        rule = self._load_first()
        assert isinstance(rule.required_capabilities, tuple)
        assert len(rule.required_capabilities) >= 1

    def test_optional_capabilities_is_tuple(self):
        rule = self._load_first()
        assert isinstance(rule.optional_capabilities, tuple)

    def test_severity_is_valid(self):
        rule = self._load_first()
        from app.composite_detections import SEVERITY_LEVELS
        assert rule.severity in SEVERITY_LEVELS

    def test_confidence_logic_is_valid(self):
        rule = self._load_first()
        from app.composite_detections import CONFIDENCE_LOGIC_VALUES
        assert rule.confidence_logic in CONFIDENCE_LOGIC_VALUES

    def test_rationale_is_non_empty_string(self):
        rule = self._load_first()
        assert isinstance(rule.rationale, str)
        assert rule.rationale.strip()

    # ── positive: immutability and equality ──────────────────────────────────

    def test_rule_is_frozen(self):
        rule = self._load_first()
        with pytest.raises((AttributeError, TypeError)):
            rule.severity = "low"  # type: ignore[misc]

    def test_two_rules_with_same_data_are_equal(self):
        r1 = CompositeRule(
            id="COMP-001",
            title="T",
            required_capabilities=("privilege-delegation",),
            optional_capabilities=(),
            severity="high",
            confidence_logic="weakest",
            rationale="R",
        )
        r2 = CompositeRule(
            id="COMP-001",
            title="T",
            required_capabilities=("privilege-delegation",),
            optional_capabilities=(),
            severity="high",
            confidence_logic="weakest",
            rationale="R",
        )
        assert r1 == r2

    # ── negative: loader rejects invalid rules ────────────────────────────────

    def test_unknown_capability_in_required_is_rejected(self, tmp_path: Path):
        """Capability names not in capabilities.yaml must be rejected at load time."""
        bad = _valid_rule(required_capabilities=["nonexistent-capability"])
        f = tmp_path / "composite_detections.yaml"
        f.write_text(json.dumps({"rules": [bad]}), encoding="utf-8")
        with pytest.raises(ValueError, match="nonexistent-capability"):
            load_composite_detections(f)

    def test_unknown_capability_in_optional_is_rejected(self, tmp_path: Path):
        """Unknown optional capability references must also be rejected."""
        bad = _valid_rule(optional_capabilities=["totally-invented"])
        f = tmp_path / "composite_detections.yaml"
        f.write_text(json.dumps({"rules": [bad]}), encoding="utf-8")
        with pytest.raises(ValueError, match="totally-invented"):
            load_composite_detections(f)

    def test_invalid_confidence_logic_is_rejected(self, tmp_path: Path):
        bad = _valid_rule(confidence_logic="random")
        f = tmp_path / "composite_detections.yaml"
        f.write_text(json.dumps({"rules": [bad]}), encoding="utf-8")
        with pytest.raises(ValueError):
            load_composite_detections(f)
