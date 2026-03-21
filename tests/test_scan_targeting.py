"""
test_scan_targeting.py — Tests for --role and --user targeting flags on scan command.

Covers:
- --role and --user are mutually exclusive (error if both provided)
- --role / --user require --profile (error if used with --file)
- --role / --user require --profile (error if neither --profile nor --file)
- Role not found: prints the expected message and exits non-zero
- User not found: prints the expected message and exits non-zero
- Successful --role scan returns inline policies from the targeted role
- Successful --user scan returns inline policies from the targeted user
- collect_targeted_policies delegates correctly for 'role' vs 'user'
- collect_targeted_policies raises ValueError for unknown resource_type
- collect_role_policies_targeted raises ResourceNotFoundError on NoSuchEntity
- collect_user_policies_targeted raises ResourceNotFoundError on NoSuchEntity
"""

from __future__ import annotations

import json
import sys
from typing import Any
from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_SIMPLE_POLICY_DOC: dict = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "*",
        }
    ],
}


def _make_args(**kwargs: Any) -> Any:
    """Return a minimal argparse.Namespace-like object for cmd_scan."""
    import argparse

    defaults = {
        "format": "text",
        "all": False,
        "profile": None,
        "assume_role": None,
        "target_role": None,
        "target_user": None,
        "file": None,
        "quiet": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _run_cmd_scan_capture(args: Any) -> tuple[str, str, int]:
    """Run cmd_scan and capture stdout, stderr, and sys.exit code.

    Returns:
        (stdout_text, stderr_text, exit_code) — exit_code is 0 if no
        SystemExit was raised, otherwise the exit code from SystemExit.
    """
    import io

    from app.cli import cmd_scan

    buf_out = io.StringIO()
    buf_err = io.StringIO()
    exit_code = 0
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout = buf_out
    sys.stderr = buf_err
    try:
        cmd_scan(args)
    except SystemExit as exc:
        exit_code = int(exc.code) if exc.code is not None else 1
    finally:
        sys.stdout = old_out
        sys.stderr = old_err

    return buf_out.getvalue(), buf_err.getvalue(), exit_code


# ---------------------------------------------------------------------------
# Mutual-exclusion and argument-validation tests (no AWS calls)
# ---------------------------------------------------------------------------


def test_role_and_user_mutually_exclusive() -> None:
    """--role and --user together must print an error and exit non-zero."""
    args = _make_args(
        profile="default",
        target_role="MyRole",
        target_user="alice",
    )
    stdout, stderr, code = _run_cmd_scan_capture(args)
    assert code == 1
    assert "--role and --user are mutually exclusive" in stderr


def test_role_requires_profile_not_file() -> None:
    """--role with --file must print an error and exit non-zero."""
    args = _make_args(
        file="policy.json",
        target_role="MyRole",
    )
    stdout, stderr, code = _run_cmd_scan_capture(args)
    assert code == 1
    assert "--role and --user require --profile" in stderr


def test_user_requires_profile_not_file() -> None:
    """--user with --file must print an error and exit non-zero."""
    args = _make_args(
        file="policy.json",
        target_user="alice",
    )
    stdout, stderr, code = _run_cmd_scan_capture(args)
    assert code == 1
    assert "--role and --user require --profile" in stderr


def test_role_without_profile_errors() -> None:
    """--role without --profile (and without --file) must print an error."""
    args = _make_args(target_role="MyRole")
    stdout, stderr, code = _run_cmd_scan_capture(args)
    assert code == 1
    assert "--role and --user require --profile" in stderr


def test_user_without_profile_errors() -> None:
    """--user without --profile (and without --file) must print an error."""
    args = _make_args(target_user="alice")
    stdout, stderr, code = _run_cmd_scan_capture(args)
    assert code == 1
    assert "--role and --user require --profile" in stderr


# ---------------------------------------------------------------------------
# Not-found error tests
# ---------------------------------------------------------------------------


def test_role_not_found_prints_expected_message() -> None:
    """When the role doesn't exist, the error message matches the spec and exits non-zero."""
    from app.aws_collector import ResourceNotFoundError

    args = _make_args(profile="default", target_role="GhostRole")
    with patch(
        "app.aws_collector.collect_targeted_policies",
        side_effect=ResourceNotFoundError("role", "GhostRole"),
    ):
        stdout, stderr, code = _run_cmd_scan_capture(args)

    assert code == 1
    assert "Role 'GhostRole' not found in profile 'default'" in stderr


def test_user_not_found_prints_expected_message() -> None:
    """When the user doesn't exist, the error message matches the spec and exits non-zero."""
    from app.aws_collector import ResourceNotFoundError

    args = _make_args(profile="prod", target_user="ghost")
    with patch(
        "app.aws_collector.collect_targeted_policies",
        side_effect=ResourceNotFoundError("user", "ghost"),
    ):
        stdout, stderr, code = _run_cmd_scan_capture(args)

    assert code == 1
    assert "User 'ghost' not found in profile 'prod'" in stderr


# ---------------------------------------------------------------------------
# Successful targeted scan tests
# ---------------------------------------------------------------------------


def test_role_scan_with_inline_policy_produces_output() -> None:
    """--role with a matching role that has inline policies produces scan output."""
    from app.aws_collector import CollectedPolicy

    fake_policy = CollectedPolicy(
        name="role/MyRole [inline: AdminPolicy]",
        source="inline:role",
        arn="",
        policy_json=json.dumps(_SIMPLE_POLICY_DOC),
        policy_arn="",
    )
    args = _make_args(profile="default", target_role="MyRole")
    with patch("app.aws_collector.collect_targeted_policies", return_value=[fake_policy]):
        stdout, stderr, code = _run_cmd_scan_capture(args)

    assert code == 0
    # Summary line must always be printed
    assert "Scanned" in stdout


def test_user_scan_with_inline_policy_produces_output() -> None:
    """--user with a matching user that has inline policies produces scan output."""
    from app.aws_collector import CollectedPolicy

    fake_policy = CollectedPolicy(
        name="user/alice [inline: ReadPolicy]",
        source="inline:user",
        arn="",
        policy_json=json.dumps(_SIMPLE_POLICY_DOC),
        policy_arn="",
    )
    args = _make_args(profile="default", target_user="alice")
    with patch("app.aws_collector.collect_targeted_policies", return_value=[fake_policy]):
        stdout, stderr, code = _run_cmd_scan_capture(args)

    assert code == 0
    assert "Scanned" in stdout


def test_role_with_no_inline_policies_prints_info_message() -> None:
    """--role matching a role with no inline policies prints an informational message."""
    args = _make_args(profile="default", target_role="EmptyRole")
    with patch("app.aws_collector.collect_targeted_policies", return_value=[]):
        stdout, stderr, code = _run_cmd_scan_capture(args)

    assert code == 0
    assert "No inline policies" in stdout
    assert "EmptyRole" in stdout


def test_user_with_no_inline_policies_prints_info_message() -> None:
    """--user matching a user with no inline policies prints an informational message."""
    args = _make_args(profile="default", target_user="emptyuser")
    with patch("app.aws_collector.collect_targeted_policies", return_value=[]):
        stdout, stderr, code = _run_cmd_scan_capture(args)

    assert code == 0
    assert "No inline policies" in stdout
    assert "emptyuser" in stdout


def test_targeted_scan_json_format() -> None:
    """--role with --format json emits valid JSON with the expected structure."""
    from app.aws_collector import CollectedPolicy

    fake_policy = CollectedPolicy(
        name="role/MyRole [inline: Policy]",
        source="inline:role",
        arn="",
        policy_json=json.dumps(_SIMPLE_POLICY_DOC),
        policy_arn="",
    )
    args = _make_args(profile="default", target_role="MyRole", format="json")
    with patch("app.aws_collector.collect_targeted_policies", return_value=[fake_policy]):
        stdout, stderr, code = _run_cmd_scan_capture(args)

    assert code == 0
    result = json.loads(stdout)
    assert result["status"] == "success"
    assert "summary" in result
    assert result["summary"]["resources"] == 1


# ---------------------------------------------------------------------------
# collect_targeted_policies unit tests (aws_collector layer)
# ---------------------------------------------------------------------------


def test_collect_targeted_policies_role_delegates_to_role_collector() -> None:
    """collect_targeted_policies('role', ...) calls collect_role_policies_targeted."""
    mock_session = MagicMock()

    with (
        patch("app.aws_collector._make_session", return_value=mock_session),
        patch("app.aws_collector._get_account_id", return_value="123456789012"),
        patch(
            "app.aws_collector.collect_role_policies_targeted", return_value=[]
        ) as mock_role,
        patch(
            "app.aws_collector.collect_user_policies_targeted", return_value=[]
        ) as mock_user,
    ):
        from app.aws_collector import collect_targeted_policies

        collect_targeted_policies("my-profile", "role", "MyRole")

    mock_role.assert_called_once_with(mock_session, "MyRole", "123456789012")
    mock_user.assert_not_called()


def test_collect_targeted_policies_user_delegates_to_user_collector() -> None:
    """collect_targeted_policies('user', ...) calls collect_user_policies_targeted."""
    mock_session = MagicMock()

    with (
        patch("app.aws_collector._make_session", return_value=mock_session),
        patch("app.aws_collector._get_account_id", return_value="123456789012"),
        patch(
            "app.aws_collector.collect_role_policies_targeted", return_value=[]
        ) as mock_role,
        patch(
            "app.aws_collector.collect_user_policies_targeted", return_value=[]
        ) as mock_user,
    ):
        from app.aws_collector import collect_targeted_policies

        collect_targeted_policies("my-profile", "user", "alice")

    mock_user.assert_called_once_with(mock_session, "alice", "123456789012")
    mock_role.assert_not_called()


def test_collect_targeted_policies_invalid_type_raises_value_error() -> None:
    """collect_targeted_policies raises ValueError for unknown resource_type."""
    from app.aws_collector import collect_targeted_policies

    with pytest.raises(ValueError, match="resource_type must be"):
        collect_targeted_policies("my-profile", "group", "DevGroup")


# ---------------------------------------------------------------------------
# collect_role_policies_targeted / collect_user_policies_targeted unit tests
# ---------------------------------------------------------------------------


def test_collect_role_policies_targeted_not_found_raises() -> None:
    """collect_role_policies_targeted raises ResourceNotFoundError on NoSuchEntity."""
    from app.aws_collector import ResourceNotFoundError, collect_role_policies_targeted

    mock_session = MagicMock()
    mock_iam = MagicMock()
    mock_session.client.return_value = mock_iam

    error_response = {"Error": {"Code": "NoSuchEntity", "Message": "Role not found"}}
    mock_iam.get_role.side_effect = botocore.exceptions.ClientError(
        error_response, "GetRole"
    )

    with pytest.raises(ResourceNotFoundError) as exc_info:
        collect_role_policies_targeted(mock_session, "GhostRole")

    assert exc_info.value.resource_type == "role"
    assert exc_info.value.resource_name == "GhostRole"


def test_collect_user_policies_targeted_not_found_raises() -> None:
    """collect_user_policies_targeted raises ResourceNotFoundError on NoSuchEntity."""
    from app.aws_collector import ResourceNotFoundError, collect_user_policies_targeted

    mock_session = MagicMock()
    mock_iam = MagicMock()
    mock_session.client.return_value = mock_iam

    error_response = {"Error": {"Code": "NoSuchEntity", "Message": "User not found"}}
    mock_iam.get_user.side_effect = botocore.exceptions.ClientError(
        error_response, "GetUser"
    )

    with pytest.raises(ResourceNotFoundError) as exc_info:
        collect_user_policies_targeted(mock_session, "ghost")

    assert exc_info.value.resource_type == "user"
    assert exc_info.value.resource_name == "ghost"


def test_collect_role_policies_targeted_other_error_raises_runtime() -> None:
    """collect_role_policies_targeted raises RuntimeError on non-NoSuchEntity errors."""
    from app.aws_collector import collect_role_policies_targeted

    mock_session = MagicMock()
    mock_iam = MagicMock()
    mock_session.client.return_value = mock_iam

    error_response = {"Error": {"Code": "AccessDenied", "Message": "Denied"}}
    mock_iam.get_role.side_effect = botocore.exceptions.ClientError(
        error_response, "GetRole"
    )

    with pytest.raises(RuntimeError, match="IAM GetRole failed"):
        collect_role_policies_targeted(mock_session, "LockedRole")


def test_collect_user_policies_targeted_other_error_raises_runtime() -> None:
    """collect_user_policies_targeted raises RuntimeError on non-NoSuchEntity errors."""
    from app.aws_collector import collect_user_policies_targeted

    mock_session = MagicMock()
    mock_iam = MagicMock()
    mock_session.client.return_value = mock_iam

    error_response = {"Error": {"Code": "AccessDenied", "Message": "Denied"}}
    mock_iam.get_user.side_effect = botocore.exceptions.ClientError(
        error_response, "GetUser"
    )

    with pytest.raises(RuntimeError, match="IAM GetUser failed"):
        collect_user_policies_targeted(mock_session, "lockeduser")


def test_collect_role_policies_targeted_existing_role_returns_policies() -> None:
    """collect_role_policies_targeted returns inline policies for an existing role."""
    from app.aws_collector import collect_role_policies_targeted

    mock_session = MagicMock()
    mock_iam = MagicMock()
    mock_session.client.return_value = mock_iam

    # get_role succeeds (role exists)
    mock_iam.get_role.return_value = {"Role": {"RoleName": "ExistingRole"}}
    # _fetch_role_inline_policies now uses get_paginator("list_role_policies").paginate()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = iter([{"PolicyNames": ["InlinePolicy"]}])
    mock_iam.get_paginator.return_value = mock_paginator
    mock_iam.get_role_policy.return_value = {
        "PolicyDocument": _SIMPLE_POLICY_DOC
    }

    results = collect_role_policies_targeted(mock_session, "ExistingRole", "123456789012")

    assert len(results) == 1
    assert results[0].source == "inline:role"
    assert "ExistingRole" in results[0].name
    assert "InlinePolicy" in results[0].name


def test_collect_user_policies_targeted_existing_user_returns_policies() -> None:
    """collect_user_policies_targeted returns inline policies for an existing user."""
    from app.aws_collector import collect_user_policies_targeted

    mock_session = MagicMock()
    mock_iam = MagicMock()
    mock_session.client.return_value = mock_iam

    mock_iam.get_user.return_value = {"User": {"UserName": "alice"}}
    # _fetch_user_inline_policies now uses get_paginator("list_user_policies").paginate()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = iter([{"PolicyNames": ["UserReadPolicy"]}])
    mock_iam.get_paginator.return_value = mock_paginator
    mock_iam.get_user_policy.return_value = {
        "PolicyDocument": _SIMPLE_POLICY_DOC
    }

    results = collect_user_policies_targeted(mock_session, "alice", "123456789012")

    assert len(results) == 1
    assert results[0].source == "inline:user"
    assert "alice" in results[0].name


# ---------------------------------------------------------------------------
# ResourceNotFoundError string representation test
# ---------------------------------------------------------------------------


def test_resource_not_found_error_str() -> None:
    """ResourceNotFoundError str representation includes type and name."""
    from app.aws_collector import ResourceNotFoundError

    err = ResourceNotFoundError("role", "MyRole")
    assert "role" in str(err)
    assert "MyRole" in str(err)
    assert err.resource_type == "role"
    assert err.resource_name == "MyRole"
