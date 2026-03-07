"""
analyzer.py — Core IAM analysis logic: fetches policy documents and sends
them to Claude for security analysis.
"""

import json
import logging
import os

import anthropic

from app import aws_client
from app.models import AnalysisResult

logger = logging.getLogger(__name__)

MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 1024

ANALYSIS_SYSTEM_PROMPT = (
    "You are an AWS IAM security expert. "
    "Given an IAM policy document in JSON format, identify: "
    "1) over-permissive actions (e.g. wildcard '*' usage), "
    "2) missing condition keys that should restrict access, "
    "3) resources that are too broadly scoped. "
    "Be concise, structured, and actionable."
)


def analyze_policy(policy_arn: str, account_id: str) -> AnalysisResult:
    """Fetch an IAM policy and return a Claude-generated security analysis.

    Args:
        policy_arn: Full ARN of the IAM policy.
        account_id: AWS account ID (used for logging context).

    Returns:
        AnalysisResult containing Claude's findings.

    Raises:
        RuntimeError: If AWS retrieval or Claude API call fails.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set.")

    # 1. Fetch policy metadata and document from AWS
    policy_meta = aws_client.get_policy(policy_arn)
    version_id = policy_meta["DefaultVersionId"]
    policy_document = aws_client.get_policy_document(policy_arn, version_id)
    policy_json = json.dumps(policy_document, indent=2)

    logger.info(
        "Analyzing policy '%s' (account: %s, version: %s).",
        policy_arn,
        account_id,
        version_id,
    )

    # 2. Send to Claude for analysis
    client = anthropic.Anthropic(api_key=api_key)
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=ANALYSIS_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Analyze the following IAM policy document:\n\n"
                        f"```json\n{policy_json}\n```"
                    ),
                }
            ],
        )
    except anthropic.APIError as exc:
        logger.error("Claude API call failed for policy '%s': %s", policy_arn, exc)
        raise RuntimeError("Claude analysis failed") from exc

    findings = response.content[0].text
    return AnalysisResult(policy_arn=policy_arn, findings=findings)