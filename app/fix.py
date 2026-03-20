"""fix.py — Safe alternative mappings for dangerous IAM actions."""

from __future__ import annotations

SAFE_ALTERNATIVES: dict[str, tuple[list[str], str]] = {
    "iam:PassRole": ([], "No safe alternative. Restrict with Condition if absolutely needed."),
    "iam:CreateUser": (["iam:GetUser", "iam:ListUsers"], "read-only alternative"),
    "iam:CreatePolicy": (["iam:GetPolicy", "iam:ListPolicies"], "read-only alternative"),
    "iam:AttachUserPolicy": ([], "No safe alternative. Use permission boundaries instead."),
    "iam:AttachRolePolicy": ([], "No safe alternative. Use permission boundaries instead."),
    "iam:PutUserPolicy": ([], "No safe alternative."),
    "iam:PutRolePolicy": ([], "No safe alternative."),
    "iam:CreateAccessKey": (["iam:ListAccessKeys"], "read-only alternative"),
    "iam:UpdateAssumeRolePolicy": ([], "No safe alternative."),
    "iam:CreateLoginProfile": ([], "No safe alternative."),
    "lambda:CreateFunction": (["lambda:GetFunction", "lambda:ListFunctions"], "read-only alternative"),
    "lambda:UpdateFunctionCode": (["lambda:GetFunction"], "read-only alternative"),
    "lambda:AddPermission": (["lambda:GetPolicy"], "read-only alternative"),
    "lambda:CreateEventSourceMapping": (["lambda:ListEventSourceMappings"], "read-only alternative"),
    "ec2:RunInstances": (["ec2:DescribeInstances"], "read-only alternative"),
    "ec2:AuthorizeSecurityGroupIngress": (["ec2:DescribeSecurityGroups"], "read-only alternative"),
    "s3:PutBucketPolicy": (["s3:GetBucketPolicy"], "read-only alternative"),
    "s3:PutBucketAcl": (["s3:GetBucketAcl"], "read-only alternative"),
    "s3:DeleteBucket": (["s3:ListBucket"], "read-only alternative"),
    "sts:AssumeRole": ([], "Restrict with Condition (aws:SourceIp, etc.) if needed."),
    "kms:Decrypt": (["kms:DescribeKey", "kms:ListKeys"], "read-only alternative"),
    "kms:CreateGrant": (["kms:ListGrants"], "read-only alternative"),
    "organizations:LeaveOrganization": (["organizations:DescribeOrganization"], "read-only alternative"),
    "glue:CreateDevEndpoint": (["glue:GetDevEndpoints"], "read-only alternative"),
    "glue:UpdateDevEndpoint": (["glue:GetDevEndpoints"], "read-only alternative"),
}
