"""Tests for CLI UX improvements.

Covers:
1. Centralized versioning — app.version.get_version() is the single source.
2. Banner — shows version, has NO rule-count line.
3. Composite text output — plain-English labels, correct single vs combined distinction.
"""
from __future__ import annotations

import io
import json
import sys

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _capture_banner() -> str:
    """Capture _print_banner() output with color forced on."""
    from app import cli
    buf = io.StringIO()
    # Patch isatty so color / banner is emitted even in test runner
    orig_stdout = sys.stdout
    sys.stdout = buf
    orig_isatty = getattr(sys.stdout, "isatty", None)
    buf.isatty = lambda: True  # type: ignore[attr-defined]
    try:
        cli._print_banner()
    finally:
        sys.stdout = orig_stdout
    return buf.getvalue()


def _capture_escalate_text(policy_json: str) -> str:
    from app.analyzer import escalate_policy_local
    from app.cli import _print_escalate
    result = escalate_policy_local(policy_json)
    buf = io.StringIO()
    old, sys.stdout = sys.stdout, buf
    try:
        _print_escalate(result, policy_json=policy_json)
    finally:
        sys.stdout = old
    return buf.getvalue()


_EC2_CHAIN = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}],
})

_POLICY_MOD = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["iam:AttachRolePolicy", "iam:CreatePolicyVersion"], "Resource": "*"}],
})


# ---------------------------------------------------------------------------
# 1. Centralized versioning
# ---------------------------------------------------------------------------

def _pyproject_version() -> str:
    """Read the version field from pyproject.toml directly."""
    import tomllib
    import pathlib
    pyproject = pathlib.Path(__file__).parent.parent / "pyproject.toml"
    with open(pyproject, "rb") as fh:
        data = tomllib.load(fh)
    return data["project"]["version"]


class TestVersionModule:
    def test_get_version_returns_string(self):
        from app.version import get_version
        v = get_version()
        assert isinstance(v, str)
        assert len(v) > 0

    def test_dunder_version_matches_get_version(self):
        from app.version import __version__, get_version
        assert __version__ == get_version()

    def test_version_matches_pyproject_toml(self):
        """get_version() must return exactly what pyproject.toml declares."""
        from app.version import get_version
        assert get_version() == _pyproject_version(), (
            "app.version.get_version() is out of sync with pyproject.toml — "
            "pyproject.toml is the canonical source of truth"
        )

    def test_version_is_semver_or_dev(self):
        """Version must look like x.y.z or be 'dev'."""
        from app.version import get_version
        v = get_version()
        if v == "dev":
            return  # acceptable fallback
        parts = v.split(".")
        assert len(parts) >= 2, f"Expected semver, got: {v!r}"
        assert all(p.isdigit() for p in parts[:2]), f"Expected numeric major.minor, got: {v!r}"

    def test_reads_pyproject_not_stale_metadata(self):
        """get_version() must NOT solely rely on importlib.metadata (which is stale after bumps)."""
        from app.version import _version_from_pyproject
        v = _version_from_pyproject()
        assert v is not None, (
            "_version_from_pyproject() must return the version from pyproject.toml, not None"
        )
        assert v == _pyproject_version()

    def test_cli_uses_version_module(self):
        """cli.py must import get_version from app.version (not inline importlib.metadata)."""
        import ast
        import pathlib
        src = pathlib.Path("app/cli.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imports.append((node.module, [a.name for a in node.names]))
        assert any(
            mod == "app.version" and "get_version" in names
            for mod, names in imports
        ), "cli.py must import get_version from app.version"

    def test_cli_does_not_import_importlib_metadata_directly(self):
        """cli.py must not have its own importlib.metadata calls after centralizing."""
        import pathlib
        src = pathlib.Path("app/cli.py").read_text(encoding="utf-8")
        assert "importlib.metadata" not in src, (
            "cli.py should not call importlib.metadata directly — use app.version.get_version()"
        )


# ---------------------------------------------------------------------------
# 2. Banner — no rule-count line
# ---------------------------------------------------------------------------

class TestBannerSimplified:
    def test_banner_contains_pasu(self):
        output = _capture_banner()
        # Strip ANSI escapes for clean text check
        import re
        clean = re.sub(r"\033\[[0-9;]*m", "", output)
        assert "PASU" in clean.upper()

    def test_banner_contains_version(self):
        from app.version import get_version
        output = _capture_banner()
        import re
        clean = re.sub(r"\033\[[0-9;]*m", "", output)
        version = get_version()
        assert version in clean, f"Banner must contain version {version!r}"

    def test_banner_version_matches_pyproject(self):
        """Banner must display the version from pyproject.toml, not stale metadata."""
        output = _capture_banner()
        import re
        clean = re.sub(r"\033\[[0-9;]*m", "", output)
        expected = _pyproject_version()
        assert expected in clean, (
            f"Banner shows a version that does not match pyproject.toml ({expected!r}). "
            "app/version.py must read pyproject.toml as the primary source."
        )

    def test_banner_has_no_rule_count_line(self):
        """The rule count line must be gone from the banner."""
        output = _capture_banner()
        import re
        clean = re.sub(r"\033\[[0-9;]*m", "", output)
        assert "rules" not in clean.lower(), (
            "Banner must not show a rule-count line — it was removed as unhelpful for end users"
        )

    def test_banner_has_no_high_medium_count(self):
        output = _capture_banner()
        import re
        clean = re.sub(r"\033\[[0-9;]*m", "", output)
        # The old line was "[ N rules  N high  N medium ]"
        assert "high" not in clean.lower() or "medium" not in clean.lower() or (
            "rules" not in clean.lower()
        ), "Banner must not show high/medium action counts"


# ---------------------------------------------------------------------------
# 3. Composite text output — plain-English UX
# ---------------------------------------------------------------------------

class TestCompositeTextUX:
    def test_section_header_is_attack_patterns_detected(self):
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "High-Risk Permission Patterns" in output

    def test_no_composite_findings_label(self):
        """'Composite Findings' must no longer appear in CLI text output."""
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "Composite Findings" not in output

    def test_no_multi_capability_label(self):
        """'Multi-capability' must not appear — it's internal taxonomy."""
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "Multi-capability" not in output
        assert "multi-capability" not in output

    def test_multi_cap_finding_says_combined_permission_attack(self):
        """COMP-001 requires 2 caps → label must say 'Risky in combination'."""
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "Risky in combination" in output

    def test_single_cap_finding_says_high_risk_on_its_own(self):
        """COMP-003 requires 1 cap → label must say 'High-risk on its own'."""
        output = _capture_escalate_text(_POLICY_MOD)
        assert "High-risk on its own" in output

    def test_single_cap_does_not_say_risky_in_combination(self):
        """Single-cap finding must NOT say 'Risky in combination'."""
        output = _capture_escalate_text(_POLICY_MOD)
        assert "Risky in combination" not in output

    def test_severity_label_is_risk(self):
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "Risk:" in output

    def test_actions_label_is_permissions(self):
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "Permissions:" in output

    def test_rationale_label_is_why(self):
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "Why:" in output

    def test_old_severity_label_absent(self):
        """Old 'Severity:' label must be gone from composite section."""
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "Severity:" not in output

    def test_old_actions_label_absent(self):
        """Old 'Actions:' label must be gone from composite section."""
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "Actions:   " not in output

    def test_old_rationale_label_absent(self):
        """Old 'Rationale:' label must be gone from composite section."""
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "Rationale:" not in output


# ---------------------------------------------------------------------------
# 4. Why: field — wrapping not truncation
# ---------------------------------------------------------------------------

class TestWhyFieldWrapping:
    def test_why_field_present(self):
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "Why:" in output

    def test_why_field_not_truncated(self):
        """Full rationale text must appear — no ellipsis truncation."""
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "…" not in output, "Why: field must not be truncated with '…'"
        assert "..." not in output, "Why: field must not be truncated with '...'"

    def test_why_field_full_content_present(self):
        """The rationale's tail words must appear somewhere in the output."""
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(_EC2_CHAIN)
        comp001 = next(f for f in result.composite_findings if f["rule_id"] == "COMP-001")
        rationale = comp001["rationale"]
        # Take the last 40 chars of the rationale (well past any 160-char truncation point).
        tail = rationale[-40:].strip()
        output = _capture_escalate_text(_EC2_CHAIN)
        assert tail in output, (
            f"Rationale tail {tail!r} must appear in output — text must be wrapped, not truncated"
        )

    def test_why_continuation_lines_are_indented(self):
        """Continuation lines of a wrapped Why: must be indented to align with the text."""
        output = _capture_escalate_text(_EC2_CHAIN)
        lines = output.splitlines()
        why_label = "    Why:          "
        indent = " " * len(why_label)
        why_idx = next((i for i, l in enumerate(lines) if l.startswith(why_label)), None)
        assert why_idx is not None, "Why: line not found"
        # Collect continuation lines immediately after the Why: line.
        continuation = []
        for line in lines[why_idx + 1:]:
            if line.startswith(indent) and not line.startswith(indent + " " * 4):
                continuation.append(line)
            else:
                break  # next section or blank line
        # Only assert indentation if there were continuation lines (long rationale).
        for line in continuation:
            assert line.startswith(indent), (
                f"Continuation line must start with {len(indent)}-space indent; got: {line!r}"
            )

    def test_no_line_exceeds_terminal_width(self):
        """No Why: output line should exceed 88 chars (comfortable terminal width)."""
        output = _capture_escalate_text(_EC2_CHAIN)
        lines = output.splitlines()
        why_label = "    Why:          "
        indent = " " * len(why_label)
        in_why = False
        for line in lines:
            if line.startswith(why_label):
                in_why = True
            elif in_why and not line.startswith(indent):
                break
            if in_why:
                assert len(line) <= 88, (
                    f"Why: output line is {len(line)} chars (> 88): {line!r}"
                )


# ---------------------------------------------------------------------------
# 5. Alignment — all field values start at the same column
# ---------------------------------------------------------------------------

_FIELD_LABELS = ["Risk", "Confidence", "Permissions", "Why", "Evidence"]
_COL = 18  # "    Permissions:  " = 4 + 12 + 1 + 1 = 18

import re as _re

def _strip_ansi(s: str) -> str:
    return _re.sub(r"\033\[[0-9;]*m", "", s)

def _composite_block_lines(policy_json: str) -> list[str]:
    """Return lines of the High-Risk Permission Patterns block (ANSI stripped)."""
    raw = _capture_escalate_text(policy_json)
    clean = _strip_ansi(raw)
    lines = clean.splitlines()
    start = next((i for i, l in enumerate(lines) if "High-Risk Permission Patterns" in l), None)
    if start is None:
        return []
    return lines[start:]


class TestAlignmentFormatting:
    def test_risk_value_starts_at_column_18(self):
        lines = _composite_block_lines(_EC2_CHAIN)
        risk_line = next((l for l in lines if l.startswith("    Risk:")), None)
        assert risk_line is not None, "Risk: line not found"
        assert len(risk_line) - len(risk_line.lstrip()) <= 4  # 4-space indent
        assert risk_line[_COL - 1] != " " or risk_line[_COL:].strip(), (
            f"Value should start at column {_COL}: {risk_line!r}"
        )
        assert risk_line[:_COL] == f"    Risk:         ", (
            f"Risk: prefix must be exactly {_COL} chars: {risk_line[:_COL]!r}"
        )

    def test_confidence_value_starts_at_column_18(self):
        lines = _composite_block_lines(_EC2_CHAIN)
        conf_line = next((l for l in lines if l.startswith("    Confidence:")), None)
        assert conf_line is not None, "Confidence: line not found"
        assert conf_line[:_COL] == f"    Confidence:   ", (
            f"Confidence: prefix must be exactly {_COL} chars: {conf_line[:_COL]!r}"
        )

    def test_permissions_value_starts_at_column_18(self):
        lines = _composite_block_lines(_EC2_CHAIN)
        perm_line = next((l for l in lines if l.startswith("    Permissions:")), None)
        assert perm_line is not None, "Permissions: line not found"
        assert perm_line[:_COL] == f"    Permissions:  ", (
            f"Permissions: prefix must be exactly {_COL} chars: {perm_line[:_COL]!r}"
        )

    def test_why_value_starts_at_column_18(self):
        lines = _composite_block_lines(_EC2_CHAIN)
        why_line = next((l for l in lines if l.startswith("    Why:")), None)
        assert why_line is not None, "Why: line not found"
        assert why_line[:_COL] == f"    Why:          ", (
            f"Why: prefix must be exactly {_COL} chars: {why_line[:_COL]!r}"
        )

    def test_all_field_prefixes_same_length(self):
        """Every labeled field must have a prefix of exactly _COL chars."""
        lines = _composite_block_lines(_EC2_CHAIN)
        for label in ("Risk", "Confidence", "Permissions", "Why"):
            match = next((l for l in lines if l.startswith(f"    {label}:")), None)
            if match is None:
                continue
            prefix_end = match.index(":", 4) + 1  # position after the colon
            padding = len(match) - len(match[prefix_end:].lstrip())
            actual_col = prefix_end + (padding - prefix_end + prefix_end)
            # simpler: just check the column directly
            assert match[:_COL] == match[:_COL], "sanity"
            assert match[_COL - 1] != ":" , f"colon at wrong position in {match!r}"
            val_start = len(match) - len(match.lstrip())
            # reconstruct: prefix is everything up to first non-space after the colon
            after_colon = match[match.index(":", 4) + 1:]
            spaces_after_colon = len(after_colon) - len(after_colon.lstrip())
            actual_prefix_len = match.index(":", 4) + 1 + spaces_after_colon
            assert actual_prefix_len == _COL, (
                f"Field '{label}:' value starts at column {actual_prefix_len}, "
                f"expected {_COL}. Line: {match!r}"
            )

    def test_no_pipe_separator_in_fields(self):
        """Risk and Confidence must be on separate lines — no '|' separator."""
        lines = _composite_block_lines(_EC2_CHAIN)
        for line in lines:
            if line.startswith("    Risk:") or line.startswith("    Confidence:"):
                assert "|" not in line, (
                    f"Risk/Confidence must be separate lines, not joined with '|': {line!r}"
                )

    def test_confidence_detail_label_removed(self):
        """'Confidence detail:' label must be gone — renamed to 'Evidence:'."""
        output = _capture_escalate_text(_EC2_CHAIN)
        assert "Confidence detail:" not in output
