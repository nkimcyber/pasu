"""Tests for app/capabilities.py and app/rules/capabilities.yaml.

Covers:
- YAML file structure and completeness
- CAPABILITY_NAMES frozenset membership
- validate_capability: accepts all valid names, rejects unknown labels
- validate_capabilities: list validation, multi-error reporting
- Loader resilience: missing file, invalid JSON
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from app.capabilities import (
    CAPABILITIES,
    CAPABILITY_NAMES,
    _build_capability_index,
    _load_capabilities_file,
    validate_capability,
    validate_capabilities,
)

_CAPABILITIES_FILE = Path(__file__).resolve().parent.parent / "app" / "rules" / "capabilities.yaml"

# The canonical 10 names the task mandates.
_REQUIRED_NAMES = {
    "privilege-delegation",
    "policy-modification",
    "credential-issuance",
    "compute-with-role",
    "serverless-with-role",
    "public-exposure",
    "cross-account-trust",
    "secret-read",
    "data-read-sensitive",
    "data-write-sensitive",
}


# ---------------------------------------------------------------------------
# YAML file structure
# ---------------------------------------------------------------------------

class TestCapabilitiesFile:
    def test_file_exists(self):
        assert _CAPABILITIES_FILE.exists(), (
            f"capabilities.yaml not found at {_CAPABILITIES_FILE}"
        )

    def test_file_is_valid_json(self):
        content = _CAPABILITIES_FILE.read_text(encoding="utf-8")
        data = json.loads(content)   # must not raise
        assert isinstance(data, dict)

    def test_governance_block_present(self):
        data = json.loads(_CAPABILITIES_FILE.read_text(encoding="utf-8"))
        assert "_governance" in data, "File must contain a _governance block"

    def test_governance_contains_adding_new_capabilities_note(self):
        data = json.loads(_CAPABILITIES_FILE.read_text(encoding="utf-8"))
        gov = data["_governance"]
        note = gov.get("adding_new_capabilities", "")
        assert len(note) > 20, "_governance.adding_new_capabilities must be a non-trivial instruction"

    def test_capabilities_block_present(self):
        data = json.loads(_CAPABILITIES_FILE.read_text(encoding="utf-8"))
        assert "capabilities" in data

    def test_all_required_names_in_file(self):
        data = json.loads(_CAPABILITIES_FILE.read_text(encoding="utf-8"))
        present = set(data["capabilities"].keys())
        missing = _REQUIRED_NAMES - present
        assert not missing, f"Required capabilities missing from file: {sorted(missing)}"

    def test_each_entry_has_description(self):
        data = json.loads(_CAPABILITIES_FILE.read_text(encoding="utf-8"))
        for name, meta in data["capabilities"].items():
            assert "description" in meta and meta["description"], (
                f"Capability '{name}' is missing a non-empty description"
            )

    def test_each_entry_has_risk_note(self):
        data = json.loads(_CAPABILITIES_FILE.read_text(encoding="utf-8"))
        for name, meta in data["capabilities"].items():
            assert "risk_note" in meta and meta["risk_note"], (
                f"Capability '{name}' is missing a non-empty risk_note"
            )

    def test_names_are_lowercase_kebab_case(self):
        import re
        data = json.loads(_CAPABILITIES_FILE.read_text(encoding="utf-8"))
        bad = [n for n in data["capabilities"] if not re.match(r"^[a-z][a-z0-9-]+$", n)]
        assert not bad, f"Capability names must be lowercase kebab-case: {bad}"


# ---------------------------------------------------------------------------
# CAPABILITY_NAMES frozenset
# ---------------------------------------------------------------------------

class TestCapabilityNames:
    def test_is_frozenset(self):
        assert isinstance(CAPABILITY_NAMES, frozenset)

    def test_contains_all_required_names(self):
        missing = _REQUIRED_NAMES - CAPABILITY_NAMES
        assert not missing, f"Missing from CAPABILITY_NAMES: {sorted(missing)}"

    def test_has_exactly_ten_entries(self):
        assert len(CAPABILITY_NAMES) == 10

    def test_names_match_capabilities_dict_keys(self):
        assert CAPABILITY_NAMES == frozenset(CAPABILITIES.keys())


# ---------------------------------------------------------------------------
# CAPABILITIES metadata dict
# ---------------------------------------------------------------------------

class TestCapabilitiesDict:
    def test_all_entries_have_description(self):
        for name, meta in CAPABILITIES.items():
            assert meta.get("description"), f"'{name}' missing description"

    def test_all_entries_have_risk_note(self):
        for name, meta in CAPABILITIES.items():
            assert meta.get("risk_note"), f"'{name}' missing risk_note"

    def test_descriptions_are_meaningful_length(self):
        for name, meta in CAPABILITIES.items():
            assert len(meta["description"]) >= 30, (
                f"Description for '{name}' is suspiciously short"
            )


# ---------------------------------------------------------------------------
# validate_capability — valid inputs
# ---------------------------------------------------------------------------

class TestValidateCapabilityAccepts:
    @pytest.mark.parametrize("name", sorted(_REQUIRED_NAMES))
    def test_accepts_each_required_name(self, name: str):
        assert validate_capability(name) == name

    def test_returns_the_name_unchanged(self):
        result = validate_capability("secret-read")
        assert result == "secret-read"
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# validate_capability — invalid inputs (enforcement)
# ---------------------------------------------------------------------------

class TestValidateCapabilityRejects:
    @pytest.mark.parametrize("bad", [
        "exfiltration",
        "privilege-escalation",       # plausible synonym — must still be rejected
        "data-exfiltration",
        "lateral-movement",
        "credential-theft",
        "iam-manipulation",
        "secret_read",                # underscore instead of hyphen
        "SecretRead",                 # wrong case
        "SECRET-READ",                # wrong case
        "public_exposure",            # underscore
        "",                           # empty string
        "data-read",                  # truncated name
        "compute",                    # missing suffix
    ])
    def test_rejects_unknown_name(self, bad: str):
        with pytest.raises(ValueError):
            validate_capability(bad)

    def test_error_names_the_rejected_value(self):
        with pytest.raises(ValueError, match="exfiltration"):
            validate_capability("exfiltration")

    def test_error_lists_allowed_values(self):
        with pytest.raises(ValueError, match="secret-read"):
            validate_capability("bogus")

    def test_error_references_capabilities_file(self):
        with pytest.raises(ValueError, match="capabilities.yaml"):
            validate_capability("bogus")


# ---------------------------------------------------------------------------
# validate_capabilities — list validation
# ---------------------------------------------------------------------------

class TestValidateCapabilitiesAccepts:
    def test_empty_list_is_valid(self):
        assert validate_capabilities([]) == []

    def test_single_valid_name(self):
        assert validate_capabilities(["secret-read"]) == ["secret-read"]

    def test_multiple_valid_names(self):
        names = ["secret-read", "public-exposure", "credential-issuance"]
        assert validate_capabilities(names) == names

    def test_all_ten_names_together(self):
        all_names = sorted(CAPABILITY_NAMES)
        assert validate_capabilities(all_names) == all_names

    def test_returns_original_list_object_values(self):
        names = ["privilege-delegation", "policy-modification"]
        result = validate_capabilities(names)
        assert result == names


class TestValidateCapabilitiesRejects:
    def test_single_invalid_name_raises(self):
        with pytest.raises(ValueError):
            validate_capabilities(["bogus"])

    def test_mixed_valid_and_invalid_raises(self):
        with pytest.raises(ValueError):
            validate_capabilities(["secret-read", "bogus"])

    def test_error_reports_all_invalid_names(self):
        """All invalid names appear in one error, not just the first."""
        with pytest.raises(ValueError) as exc_info:
            validate_capabilities(["bad-one", "secret-read", "bad-two"])
        msg = str(exc_info.value)
        assert "bad-one" in msg
        assert "bad-two" in msg

    def test_error_count_matches_number_of_invalid(self):
        with pytest.raises(ValueError, match="2 unrecognised"):
            validate_capabilities(["bad-one", "bad-two"])

    def test_error_references_capabilities_file(self):
        with pytest.raises(ValueError, match="capabilities.yaml"):
            validate_capabilities(["bogus"])

    def test_duplicate_invalid_name_counted_once(self):
        """Deduplication: the same bad name listed twice counts as one invalid."""
        with pytest.raises(ValueError, match="1 unrecognised"):
            validate_capabilities(["bogus", "bogus"])


# ---------------------------------------------------------------------------
# Loader resilience
# ---------------------------------------------------------------------------

class TestLoaderResilience:
    def test_missing_file_raises_runtime_error(self, tmp_path: Path):
        missing = tmp_path / "nonexistent.yaml"
        with pytest.raises(RuntimeError, match="not found"):
            _load_capabilities_file(missing)

    def test_invalid_json_raises_runtime_error(self, tmp_path: Path):
        bad_file = tmp_path / "capabilities.yaml"
        bad_file.write_text("{ this is not json }", encoding="utf-8")
        with pytest.raises(RuntimeError, match="invalid JSON"):
            _load_capabilities_file(bad_file)

    def test_missing_capabilities_key_raises_runtime_error(self, tmp_path: Path):
        f = tmp_path / "capabilities.yaml"
        f.write_text(json.dumps({"_governance": {}}), encoding="utf-8")
        raw = _load_capabilities_file(f)
        with pytest.raises(RuntimeError, match="non-empty 'capabilities'"):
            _build_capability_index(raw)

    def test_empty_capabilities_block_raises_runtime_error(self, tmp_path: Path):
        f = tmp_path / "capabilities.yaml"
        f.write_text(json.dumps({"capabilities": {}}), encoding="utf-8")
        raw = _load_capabilities_file(f)
        with pytest.raises(RuntimeError, match="non-empty 'capabilities'"):
            _build_capability_index(raw)

    def test_custom_file_path_is_loaded(self, tmp_path: Path):
        custom = tmp_path / "custom_caps.yaml"
        custom.write_text(json.dumps({
            "capabilities": {
                "test-cap": {
                    "description": "A test capability.",
                    "risk_note": "Test risk.",
                }
            }
        }), encoding="utf-8")
        raw = _load_capabilities_file(custom)
        index = _build_capability_index(raw)
        assert "test-cap" in index
