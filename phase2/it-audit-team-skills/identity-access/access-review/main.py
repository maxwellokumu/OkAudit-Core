"""IAM Access Review — analyse IAM policies for excessive permissions.

Supports local file analysis, live AWS IAM via boto3, and Azure role
assignments via MSAL. Flags wildcards, admin-equivalent actions, broad
resource scopes, missing conditions, and inline policies.
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ADMIN_ACTION_PREFIXES = (
    "*:*", "iam:*", "s3:Delete", "ec2:Terminate", "ec2:Stop",
    "organizations:*", "sts:AssumeRole", "lambda:*", "cloudtrail:Delete",
    "cloudtrail:Stop", "logs:Delete", "kms:*", "secretsmanager:Delete",
)

SENSITIVE_ACTIONS = {
    "iam:CreateUser", "iam:DeleteUser", "iam:AttachUserPolicy",
    "iam:PutUserPolicy", "iam:CreateAccessKey", "iam:UpdateLoginProfile",
    "iam:PassRole", "s3:DeleteBucket", "s3:PutBucketAcl",
    "s3:PutBucketPolicy", "ec2:TerminateInstances", "ec2:DeleteVpc",
    "cloudtrail:DeleteTrail", "cloudtrail:StopLogging",
}

# ---------------------------------------------------------------------------
# Sample data for --dry-run
# ---------------------------------------------------------------------------

SAMPLE_AWS_POLICIES = [
    {
        "PolicyName": "AdminWildcardPolicy",
        "PolicyType": "managed",
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ],
        },
    },
    {
        "PolicyName": "S3FullAccessNoCondition",
        "PolicyType": "managed",
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:*"],
                    "Resource": "*",
                },
            ],
        },
    },
    {
        "PolicyName": "InlineEC2Policy",
        "PolicyType": "inline",
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ec2:TerminateInstances", "ec2:StopInstances"],
                    "Resource": "*",
                },
            ],
        },
    },
    {
        "PolicyName": "GoodLeastPrivilegePolicy",
        "PolicyType": "managed",
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                },
            ],
        },
    },
]

SAMPLE_AZURE_ROLES = [
    {
        "RoleName": "Owner",
        "PrincipalName": "john.doe@contoso.com",
        "Scope": "/subscriptions/sub-123",
        "PolicyType": "builtin",
    },
    {
        "RoleName": "Contributor",
        "PrincipalName": "svc-deploy@contoso.com",
        "Scope": "/subscriptions/sub-123",
        "PolicyType": "builtin",
    },
    {
        "RoleName": "Reader",
        "PrincipalName": "audit-team@contoso.com",
        "Scope": "/subscriptions/sub-123",
        "PolicyType": "builtin",
    },
]

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Review IAM policies for excessive permissions and security issues."
    )
    parser.add_argument(
        "--input",
        help="Path to IAM policy JSON file or raw JSON string (required for local mode)",
    )
    parser.add_argument(
        "--mode",
        choices=["local", "aws", "azure"],
        default="local",
        help="Execution mode (default: local)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use bundled sample data instead of live API calls",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------


def load_local_policies(input_arg: Optional[str]) -> List[Dict[str, Any]]:
    """Load IAM policies from a file path or raw JSON string.

    Args:
        input_arg: File path or raw JSON string.

    Returns:
        List of policy dicts with keys: PolicyName, PolicyType, Document.

    Raises:
        SystemExit: On missing input, file not found, or invalid JSON.
    """
    if not input_arg:
        print("ERROR: --input is required for local mode.", file=sys.stderr)
        sys.exit(1)

    # Try as file path first
    raw: str
    try:
        with open(input_arg, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except FileNotFoundError:
        # Maybe it is a raw JSON string
        raw = input_arg
    except OSError as exc:
        print(f"ERROR: Cannot read file '{input_arg}': {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON — {exc}", file=sys.stderr)
        sys.exit(1)

    # Normalise to list of policies
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Single policy document (AWS format) — wrap it
        if "Statement" in data or "Version" in data:
            return [{"PolicyName": "InputPolicy", "PolicyType": "managed", "Document": data}]
        # Already wrapped format
        if "policies" in data:
            return data["policies"]
        return [data]

    print("ERROR: Unexpected JSON structure. Expected a policy document or list.", file=sys.stderr)
    sys.exit(1)


def load_aws_policies(dry_run: bool) -> List[Dict[str, Any]]:
    """Fetch IAM policies from AWS via boto3.

    Args:
        dry_run: If True, return bundled sample data.

    Returns:
        List of policy dicts.
    """
    if dry_run:
        print("INFO: --dry-run enabled — using sample AWS policy data.\n", file=sys.stderr)
        return SAMPLE_AWS_POLICIES

    try:
        import boto3  # type: ignore
    except ImportError:
        print("ERROR: boto3 is not installed. Run: pip install boto3", file=sys.stderr)
        sys.exit(1)

    try:
        iam = boto3.client("iam")
        policies: List[Dict[str, Any]] = []

        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for p in page["Policies"]:
                version = iam.get_policy_version(
                    PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"]
                )
                policies.append(
                    {
                        "PolicyName": p["PolicyName"],
                        "PolicyArn": p["Arn"],
                        "PolicyType": "managed",
                        "Document": version["PolicyVersion"]["Document"],
                    }
                )
        return policies
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: AWS API call failed — {exc}", file=sys.stderr)
        sys.exit(1)


def load_azure_roles(dry_run: bool) -> List[Dict[str, Any]]:
    """Fetch role assignments from Azure via MSAL.

    Args:
        dry_run: If True, return bundled sample data.

    Returns:
        List of role assignment dicts.
    """
    if dry_run:
        print("INFO: --dry-run enabled — using sample Azure role data.\n", file=sys.stderr)
        return SAMPLE_AZURE_ROLES

    import os

    try:
        import msal  # type: ignore
        import urllib.request
    except ImportError:
        print("ERROR: msal is not installed. Run: pip install msal", file=sys.stderr)
        sys.exit(1)

    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

    if not all([tenant_id, client_id, client_secret, subscription_id]):
        print(
            "ERROR: Azure credentials not set. "
            "Ensure AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, "
            "and AZURE_SUBSCRIPTION_ID are in your .env file.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        token_result = app.acquire_token_for_client(
            scopes=["https://management.azure.com/.default"]
        )
        if "access_token" not in token_result:
            raise ValueError(token_result.get("error_description", "Token acquisition failed"))

        token = token_result["access_token"]
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/providers/Microsoft.Authorization/roleAssignments"
            f"?api-version=2022-04-01"
        )
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())

        roles = []
        for item in data.get("value", []):
            props = item.get("properties", {})
            roles.append(
                {
                    "RoleName": props.get("roleDefinitionId", "").split("/")[-1],
                    "PrincipalName": props.get("principalId", ""),
                    "Scope": props.get("scope", ""),
                    "PolicyType": "builtin",
                }
            )
        return roles
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: Azure API call failed — {exc}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def analyse_statement(
    statement: Dict[str, Any], policy_name: str, policy_type: str
) -> List[Dict[str, Any]]:
    """Analyse a single IAM statement for issues.

    Args:
        statement: IAM policy statement dict.
        policy_name: Name of the parent policy.
        policy_type: 'managed' or 'inline'.

    Returns:
        List of finding dicts.
    """
    findings: List[Dict[str, Any]] = []

    if statement.get("Effect") != "Allow":
        return findings

    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]

    resources = statement.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]

    conditions = statement.get("Condition", {})
    has_condition = bool(conditions)

    for action in actions:
        # Wildcard action
        if action == "*" or action.endswith(":*"):
            findings.append(
                {
                    "policy": policy_name,
                    "issue": f"Wildcard action '{action}' grants unrestricted permissions",
                    "severity": "Critical",
                    "recommendation": (
                        "Replace wildcard with explicit action list using least-privilege principle. "
                        "Use IAM Access Analyzer to generate minimal required actions."
                    ),
                }
            )

        # Admin-equivalent action prefixes
        for prefix in ADMIN_ACTION_PREFIXES:
            if action.startswith(prefix.rstrip("*")) and action != action.replace("*", ""):
                if action not in [f["policy"] for f in findings]:
                    findings.append(
                        {
                            "policy": policy_name,
                            "issue": f"Admin-equivalent action '{action}' detected",
                            "severity": "High",
                            "recommendation": (
                                f"Restrict '{action}' to specific resources and add "
                                "MFA or IP condition. Review if this privilege is necessary."
                            ),
                        }
                    )
                break

    # Resource wildcard with write/delete actions
    if "*" in resources:
        write_actions = [
            a for a in actions
            if any(kw in a.lower() for kw in ("write", "put", "delete", "create", "update",
                                               "modify", "attach", "terminate", "stop", "pass"))
        ]
        if write_actions:
            findings.append(
                {
                    "policy": policy_name,
                    "issue": (
                        f"Resource wildcard '*' combined with write/delete actions: "
                        f"{', '.join(write_actions[:3])}"
                    ),
                    "severity": "High",
                    "recommendation": (
                        "Scope resources to specific ARNs. Use resource-based conditions "
                        "and avoid granting write access to all resources."
                    ),
                }
            )

    # No condition on sensitive actions
    if not has_condition:
        sensitive_found = [a for a in actions if a in SENSITIVE_ACTIONS]
        if sensitive_found:
            findings.append(
                {
                    "policy": policy_name,
                    "issue": (
                        f"Sensitive action(s) {', '.join(sensitive_found[:3])} "
                        "granted with no conditions (no MFA, no IP restriction)"
                    ),
                    "severity": "Medium",
                    "recommendation": (
                        "Add Condition block requiring MFA "
                        "('aws:MultiFactorAuthPresent': 'true') and/or restrict "
                        "to known IP ranges via 'aws:SourceIp'."
                    ),
                }
            )

    # Inline policy flag
    if policy_type == "inline":
        findings.append(
            {
                "policy": policy_name,
                "issue": "Inline policy detected — harder to audit and reuse than managed policies",
                "severity": "Low",
                "recommendation": (
                    "Convert inline policies to customer-managed IAM policies for "
                    "centralised governance, version control, and reuse."
                ),
            }
        )

    return findings


def analyse_policies(policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyse all policies and return aggregated findings.

    Args:
        policies: List of policy dicts.

    Returns:
        Flat list of finding dicts.
    """
    all_findings: List[Dict[str, Any]] = []
    for policy in policies:
        name = policy.get("PolicyName", "UnknownPolicy")
        ptype = policy.get("PolicyType", "managed")
        doc = policy.get("Document", {})

        # Azure-style roles (no Document key)
        if "RoleName" in policy:
            role = policy.get("RoleName", "")
            if role in ("Owner", "Contributor"):
                all_findings.append(
                    {
                        "policy": f"{role} — {policy.get('PrincipalName', '')}",
                        "issue": (
                            f"Highly privileged built-in role '{role}' assigned at "
                            f"scope: {policy.get('Scope', '')}"
                        ),
                        "severity": "High" if role == "Contributor" else "Critical",
                        "recommendation": (
                            f"Review whether '{role}' is the minimum required role. "
                            "Consider scoping to resource groups rather than subscription."
                        ),
                    }
                )
            continue

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            all_findings.extend(analyse_statement(stmt, name, ptype))

    return all_findings


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SEVERITY_EMOJI = {"Critical": "🚨", "High": "🔴", "Medium": "🟠", "Low": "🟡"}


def render_report(
    policies: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    mode: str,
) -> str:
    """Render the markdown access review report.

    Args:
        policies: List of reviewed policies.
        findings: List of finding dicts.
        mode: Execution mode string.

    Returns:
        Markdown report string.
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    severity_counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines: List[str] = []
    lines.append("# IAM Access Review Report\n")
    lines.append(f"**Date:** {date_str}  ")
    lines.append(f"**Mode:** {mode}  ")
    lines.append(f"**Policies Reviewed:** {len(policies)}  ")
    lines.append(f"**Total Findings:** {len(findings)}\n")
    lines.append("---\n")

    # Executive summary
    lines.append("## Executive Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["Critical", "High", "Medium", "Low"]:
        emoji = SEVERITY_EMOJI.get(sev, "")
        lines.append(f"| {emoji} {sev} | {severity_counts.get(sev, 0)} |")
    lines.append("")

    if not findings:
        lines.append(
            "> ✅ No issues found. All reviewed policies appear to follow least-privilege principles.\n"
        )
        return "\n".join(lines)

    # Findings table
    lines.append("---\n")
    lines.append("## Findings\n")
    lines.append("| Policy Name | Issue | Severity | Recommendation |")
    lines.append("|-------------|-------|----------|----------------|")

    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "Low"), 3))
    for f in sorted_findings:
        sev = f.get("severity", "Low")
        emoji = SEVERITY_EMOJI.get(sev, "")
        policy = f.get("policy", "").replace("|", "\\|")
        issue = f.get("issue", "").replace("|", "\\|")
        rec = f.get("recommendation", "").replace("|", "\\|")
        lines.append(f"| `{policy}` | {issue} | {emoji} {sev} | {rec} |")

    lines.append("")
    lines.append("---\n")

    # Appendix
    lines.append("## Appendix — Policies Reviewed\n")
    for p in policies:
        name = p.get("PolicyName") or p.get("RoleName", "Unknown")
        ptype = p.get("PolicyType", "managed")
        lines.append(f"- `{name}` ({ptype})")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point."""
    args = parse_args()

    if args.mode == "local":
        policies = load_local_policies(args.input)
    elif args.mode == "aws":
        policies = load_aws_policies(args.dry_run)
    else:
        policies = load_azure_roles(args.dry_run)

    if not policies:
        print("ERROR: No policies found to analyse.", file=sys.stderr)
        sys.exit(1)

    findings = analyse_policies(policies)
    print(render_report(policies, findings, args.mode))


if __name__ == "__main__":
    main()
