"""
models.py — Pydantic request/response models for the IAM Analyzer Project.
"""

from pydantic import BaseModel, Field


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