"""
aws_client.py — boto3 IAM client wrapper for the IAM Analyzer Project.
"""

import logging
import botocore.exceptions
import boto3

from app.models import IAMPolicyResponse

logger = logging.getLogger(__name__)


def get_iam_client():
    """Return a boto3 IAM client using environment credentials or IAM role."""
    return boto3.client("iam")


def get_policy(policy_arn: str) -> dict:
    """Retrieve metadata for a single IAM policy by ARN.

    Args:
        policy_arn: Full ARN of the IAM policy.

    Returns:
        Raw AWS policy dict.

    Raises:
        RuntimeError: On boto3 ClientError.
    """
    client = get_iam_client()
    try:
        response = client.get_policy(PolicyArn=policy_arn)
        return response["Policy"]
    except botocore.exceptions.ClientError as exc:
        logger.error("Failed to get policy '%s': %s", policy_arn, exc)
        raise RuntimeError("IAM get_policy failed") from exc


def get_policy_document(policy_arn: str, version_id: str) -> dict:
    """Retrieve the JSON document of a specific policy version.

    Args:
        policy_arn: Full ARN of the IAM policy.
        version_id: The version ID (e.g. 'v1').

    Returns:
        Policy document dict.

    Raises:
        RuntimeError: On boto3 ClientError.
    """
    client = get_iam_client()
    try:
        response = client.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )
        return response["PolicyVersion"]["Document"]
    except botocore.exceptions.ClientError as exc:
        logger.error(
            "Failed to get policy document for '%s' v%s: %s",
            policy_arn,
            version_id,
            exc,
        )
        raise RuntimeError("IAM get_policy_version failed") from exc


def list_policies() -> list[IAMPolicyResponse]:
    """List all customer-managed IAM policies in the account.

    Returns:
        List of IAMPolicyResponse objects.

    Raises:
        RuntimeError: On boto3 ClientError.
    """
    client = get_iam_client()
    try:
        response = client.list_policies(Scope="Local")
        return [IAMPolicyResponse(**p) for p in response["Policies"]]
    except botocore.exceptions.ClientError as exc:
        logger.error("Failed to list IAM policies: %s", exc)
        raise RuntimeError("IAM list_policies failed") from exc