"""
models.py — Pydantic request/response models for the IAM Analyzer Project.
"""

from pydantic import BaseModel, ConfigDict, Field


class AnalyzeRequest(BaseModel):
    """Request body for the /analyze endpoint."""

    policy_arn: str = Field(..., description="Full ARN of the IAM policy to analyze.")
    account_id: str = Field(..., description="AWS account ID owning the policy.")


class IAMPolicyResponse(BaseModel):
    """Parsed representation of an AWS IAM policy list entry."""

    PolicyName: str
    PolicyId: str
    Arn: str
    Path: str
    DefaultVersionId: str
    AttachmentCount: int
    IsAttachable: bool


class AnalysisResult(BaseModel):
    """Response model returned by the /analyze endpoint."""

    policy_arn: str
    findings: str = Field(..., description="Claude's security analysis of the policy.")
    status: str = Field(default="ok")


class ExplainRequest(BaseModel):
    """Request body for the /explain endpoint."""

    policy_json: str = Field(
        ..., description="Raw IAM policy JSON string pasted by the user."
    )


class ExplainResult(BaseModel):
    """Response model returned by the /explain endpoint."""

    summary: str = Field(..., description="One-sentence plain English summary.")
    details: list[str] = Field(
        ..., description="Bullet point list of what each statement does."
    )
    status: str = Field(default="ok")


class RuleFinding(BaseModel):
    """A single finding produced by the local rule engine (analyze_policy_rules)."""

    rule_id: str = Field(..., description="Identifier for the rule that fired (e.g. R001).")
    severity: str = Field(..., description="Severity level: 'high', 'medium', or 'low'.")
    title: str = Field(..., description="Short description of the finding.")
    description: str = Field(..., description="Detailed explanation and remediation hint.")
    statement_index: int = Field(..., description="Zero-based index of the offending Statement.")


class EscalationFinding(BaseModel):
    """A single detected privilege escalation finding."""

    action: str = Field(..., description="The risky IAM action detected.")
    explanation: str = Field(..., description="What the action allows and why it is risky.")
    escalation_path: str = Field(..., description="Simplified escalation path string.")


class EscalationResult(BaseModel):
    """Response model returned by the /escalate endpoint."""

    risk_level: str = Field(..., description="Overall risk level: High, Medium, or Low.")
    detected_actions: list[str] = Field(
        ..., description="List of risky actions found in the policy."
    )
    findings: list[EscalationFinding] = Field(
        ..., description="Detailed finding for each detected risky action."
    )
    summary: str = Field(..., description="One-sentence overall risk summary.")
    status: str = Field(default="ok")


class FixChange(BaseModel):
    """A single transformation applied by fix_policy_local()."""

    model_config = ConfigDict(populate_by_name=True)

    type: str = Field(..., description=(
        "Change type: 'removed_action', 'scoped_wildcard', "
        "'replaced_wildcard', or 'resource_wildcard_warning'."
    ))
    statement_index: int = Field(..., description="Zero-based index of the affected Statement.")
    reason: str = Field(..., description="Human-readable explanation of the change.")
    action: str | None = Field(default=None, description="Removed action (removed_action type).")
    from_: str | None = Field(
        default=None,
        serialization_alias="from",
        description="Original wildcard action (scoped_wildcard / replaced_wildcard types).",
    )
    to: list[str] | None = Field(
        default=None,
        description="Replacement actions (scoped_wildcard / replaced_wildcard types).",
    )


class FixResult(BaseModel):
    """Response model returned by fix_policy_local()."""

    original_risk_level: str = Field(..., description="Risk level of the original policy.")
    fixed_risk_level: str = Field(..., description="Risk level of the fixed policy.")
    fixed_policy: dict = Field(..., description="The transformed IAM policy document.")
    changes: list[FixChange] = Field(..., description="All transformations applied.")
    manual_review_needed: list[str] = Field(
        ..., description="Statements that could not be auto-fixed."
    )
    status: str = Field(default="success")