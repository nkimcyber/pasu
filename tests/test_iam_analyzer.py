"""
test_iam_analyzer.py — pytest test suite for the IAM Analyzer Project.

Covers:
- Pydantic model validation
- aws_client helpers (mocked boto3)
- analyzer.analyze_policy (mocked boto3 + Claude)
- FastAPI endpoints via TestClient
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import AnalysisResult, AnalyzeRequest, IAMPolicyResponse

# ── Fixtures ──────────────────────────────────────────────────────────────────

VALID_POLICY_ARN = "arn:aws:iam::123456789012:policy/TestPolicy"
VALID_ACCOUNT_ID = "123456789012"

MOCK_POLICY_META = {
    "PolicyName": "TestPolicy",
    "PolicyId": "ANPA000000000000EXAMPLE",
    "Arn": VALID_POLICY_ARN,
    "Path": "/",
    "DefaultVersionId": "v1",
    "AttachmentCount": 1,
    "IsAttachable": True,
}

MOCK_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
    ],
}

MOCK_CLAUDE_FINDINGS = (
    "1) Over-permissive: wildcard '*' on Action and Resource grants unrestricted access.\n"
    "2) No condition keys present — add aws:RequestedRegion or aws:PrincipalAccount.\n"
    "3) Resource scope is '*' — restrict to specific ARNs."
)


# ── Model Tests ───────────────────────────────────────────────────────────────

class TestAnalyzeRequest:
    def test_valid_request(self):
        req = AnalyzeRequest(policy_arn=VALID_POLICY_ARN, account_id=VALID_ACCOUNT_ID)
        assert req.policy_arn == VALID_POLICY_ARN
        assert req.account_id == VALID_ACCOUNT_ID

    def test_missing_policy_arn_raises(self):
        with pytest.raises(Exception):
            AnalyzeRequest(account_id=VALID_ACCOUNT_ID)

    def test_missing_account_id_raises(self):
        with pytest.raises(Exception):
            AnalyzeRequest(policy_arn=VALID_POLICY_ARN)


class TestIAMPolicyResponse:
    def test_valid_model(self):
        policy = IAMPolicyResponse(**MOCK_POLICY_META)
        assert policy.Arn == VALID_POLICY_ARN
        assert policy.DefaultVersionId == "v1"
        assert policy.AttachmentCount == 1

    def test_missing_required_field_raises(self):
        incomplete = {k: v for k, v in MOCK_POLICY_META.items() if k != "PolicyName"}
        with pytest.raises(Exception):
            IAMPolicyResponse(**incomplete)


class TestAnalysisResult:
    def test_valid_result(self):
        result = AnalysisResult(
            policy_arn=VALID_POLICY_ARN,
            findings=MOCK_CLAUDE_FINDINGS,
        )
        assert result.status == "ok"
        assert "wildcard" in result.findings

    def test_default_status_is_ok(self):
        result = AnalysisResult(
            policy_arn=VALID_POLICY_ARN,
            findings="some findings",
        )
        assert result.status == "ok"


# ── aws_client Tests ──────────────────────────────────────────────────────────

class TestGetPolicy:
    @patch("app.aws_client.get_iam_client")
    def test_returns_policy_meta(self, mock_client_fn):
        mock_iam = MagicMock()
        mock_iam.get_policy.return_value = {"Policy": MOCK_POLICY_META}
        mock_client_fn.return_value = mock_iam

        from app.aws_client import get_policy
        result = get_policy(VALID_POLICY_ARN)
        assert result["Arn"] == VALID_POLICY_ARN

    @patch("app.aws_client.get_iam_client")
    def test_raises_runtime_error_on_client_error(self, mock_client_fn):
        import botocore.exceptions
        mock_iam = MagicMock()
        mock_iam.get_policy.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Not found"}},
            "GetPolicy",
        )
        mock_client_fn.return_value = mock_iam

        from app.aws_client import get_policy
        with pytest.raises(RuntimeError, match="IAM get_policy failed"):
            get_policy(VALID_POLICY_ARN)


class TestGetPolicyDocument:
    @patch("app.aws_client.get_iam_client")
    def test_returns_policy_document(self, mock_client_fn):
        mock_iam = MagicMock()
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {"Document": MOCK_POLICY_DOCUMENT}
        }
        mock_client_fn.return_value = mock_iam

        from app.aws_client import get_policy_document
        doc = get_policy_document(VALID_POLICY_ARN, "v1")
        assert doc["Version"] == "2012-10-17"

    @patch("app.aws_client.get_iam_client")
    def test_raises_runtime_error_on_client_error(self, mock_client_fn):
        import botocore.exceptions
        mock_iam = MagicMock()
        mock_iam.get_policy_version.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Not found"}},
            "GetPolicyVersion",
        )
        mock_client_fn.return_value = mock_iam

        from app.aws_client import get_policy_document
        with pytest.raises(RuntimeError, match="IAM get_policy_version failed"):
            get_policy_document(VALID_POLICY_ARN, "v1")


class TestListPolicies:
    @patch("app.aws_client.get_iam_client")
    def test_returns_list_of_models(self, mock_client_fn):
        mock_iam = MagicMock()
        mock_iam.list_policies.return_value = {"Policies": [MOCK_POLICY_META]}
        mock_client_fn.return_value = mock_iam

        from app.aws_client import list_policies
        policies = list_policies()
        assert len(policies) == 1
        assert isinstance(policies[0], IAMPolicyResponse)

    @patch("app.aws_client.get_iam_client")
    def test_raises_runtime_error_on_client_error(self, mock_client_fn):
        import botocore.exceptions
        mock_iam = MagicMock()
        mock_iam.list_policies.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "ListPolicies",
        )
        mock_client_fn.return_value = mock_iam

        from app.aws_client import list_policies
        with pytest.raises(RuntimeError, match="IAM list_policies failed"):
            list_policies()


# ── analyzer Tests ────────────────────────────────────────────────────────────

class TestAnalyzePolicy:
    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("app.analyzer.aws_client.get_policy_document")
    @patch("app.analyzer.aws_client.get_policy")
    @patch("app.analyzer.anthropic.Anthropic")
    def test_returns_analysis_result(
        self, mock_anthropic_cls, mock_get_policy, mock_get_doc
    ):
        mock_get_policy.return_value = MOCK_POLICY_META
        mock_get_doc.return_value = MOCK_POLICY_DOCUMENT

        mock_content = MagicMock()
        mock_content.text = MOCK_CLAUDE_FINDINGS
        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_anthropic_cls.return_value.messages.create.return_value = mock_response

        from app.analyzer import analyze_policy
        result = analyze_policy(VALID_POLICY_ARN, VALID_ACCOUNT_ID)

        assert isinstance(result, AnalysisResult)
        assert result.policy_arn == VALID_POLICY_ARN
        assert "wildcard" in result.findings

    @patch.dict("os.environ", {}, clear=True)
    def test_raises_if_api_key_missing(self):
        from app.analyzer import analyze_policy
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            analyze_policy(VALID_POLICY_ARN, VALID_ACCOUNT_ID)

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("app.analyzer.aws_client.get_policy")
    def test_raises_on_aws_failure(self, mock_get_policy):
        mock_get_policy.side_effect = RuntimeError("IAM get_policy failed")

        from app.analyzer import analyze_policy
        with pytest.raises(RuntimeError, match="IAM get_policy failed"):
            analyze_policy(VALID_POLICY_ARN, VALID_ACCOUNT_ID)

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("app.analyzer.aws_client.get_policy_document")
    @patch("app.analyzer.aws_client.get_policy")
    @patch("app.analyzer.anthropic.Anthropic")
    def test_raises_on_claude_api_failure(
        self, mock_anthropic_cls, mock_get_policy, mock_get_doc
    ):
        import anthropic as anthropic_lib
        mock_get_policy.return_value = MOCK_POLICY_META
        mock_get_doc.return_value = MOCK_POLICY_DOCUMENT
        mock_anthropic_cls.return_value.messages.create.side_effect = (
            anthropic_lib.APIError(
                message="API error",
                request=MagicMock(),
                body=None,
            )
        )

        from app.analyzer import analyze_policy
        with pytest.raises(RuntimeError, match="Claude analysis failed"):
            analyze_policy(VALID_POLICY_ARN, VALID_ACCOUNT_ID)


# ── FastAPI Endpoint Tests ────────────────────────────────────────────────────

@pytest.fixture
def client():
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestAnalyzeEndpoint:
    @patch("app.main.analyze_policy")
    def test_analyze_returns_200_with_valid_input(self, mock_analyze, client):
        mock_analyze.return_value = AnalysisResult(
            policy_arn=VALID_POLICY_ARN,
            findings=MOCK_CLAUDE_FINDINGS,
        )
        payload = {"policy_arn": VALID_POLICY_ARN, "account_id": VALID_ACCOUNT_ID}
        response = client.post("/api/v1/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["policy_arn"] == VALID_POLICY_ARN
        assert "wildcard" in data["findings"]

    def test_analyze_returns_422_on_missing_field(self, client):
        response = client.post("/api/v1/analyze", json={"policy_arn": VALID_POLICY_ARN})
        assert response.status_code == 422

    @patch("app.main.analyze_policy")
    def test_analyze_returns_500_on_runtime_error(self, mock_analyze, client):
        mock_analyze.side_effect = RuntimeError("IAM get_policy failed")
        payload = {"policy_arn": VALID_POLICY_ARN, "account_id": VALID_ACCOUNT_ID}
        response = client.post("/api/v1/analyze", json=payload)
        assert response.status_code == 500
        assert "IAM get_policy failed" in response.json()["detail"]