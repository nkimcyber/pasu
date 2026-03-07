"""
main.py — FastAPI application entry point for the IAM Analyzer Project.
"""

import logging

from fastapi import APIRouter, FastAPI, HTTPException

from app.analyzer import analyze_policy
from app.models import AnalysisResult, AnalyzeRequest

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="IAM Analyzer",
    description="Analyzes AWS IAM policies for security risks using Claude AI.",
    version="0.1.0",
)

router = APIRouter(prefix="/api/v1", tags=["iam"])


@router.post("/analyze", response_model=AnalysisResult)
def analyze(request: AnalyzeRequest) -> AnalysisResult:
    """Analyze a single IAM policy and return Claude's security findings.

    Args:
        request: AnalyzeRequest containing policy_arn and account_id.

    Returns:
        AnalysisResult with Claude's findings.

    Raises:
        HTTPException 500: On AWS or Claude API failure.
    """
    try:
        return analyze_policy(
            policy_arn=request.policy_arn,
            account_id=request.account_id,
        )
    except RuntimeError as exc:
        logger.error("Analysis failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/health")
def health() -> dict:
    """Health check endpoint.

    Returns:
        JSON dict with status 'ok'.
    """
    return {"status": "ok"}


app.include_router(router)