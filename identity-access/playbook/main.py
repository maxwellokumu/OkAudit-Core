"""IAM Audit Playbook — step-by-step methodology for Identity & Access Management audits.

Provides structured guidance for each phase of an IAM audit engagement,
including objectives, artefacts, tools/commands, must-do checks, and
links to analysis skills in this role.
"""

import argparse
import sys
from typing import Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Playbook definition
# ---------------------------------------------------------------------------

PLAYBOOK: List[Dict] = [
    {
        "step": 1,
        "title": "User & Account Inventory",
        "objective": (
            "Establish a complete, accurate inventory of all user accounts, "
            "service accounts, and groups across all in-scope systems. "
            "This baseline is the foundation for all subsequent IAM testing."
        ),
        "artefacts": [
            "user_access_report.csv — full export of all active and disabled accounts",
            "service_account_register.csv — all non-human/service accounts with owners",
            "group_membership_report.csv — group-to-user mappings",
            "privileged_accounts.csv — accounts with admin/root/elevated privileges",
            "last_login_report.csv — last login date per account",
        ],
        "tools_commands": [
            "# AWS: export all IAM users",
            "aws iam list-users --output json > user_access_report.json",
            "",
            "# AWS: export all IAM groups and memberships",
            "aws iam list-groups --output json > groups.json",
            "aws iam get-group --group-name <GroupName> --output json",
            "",
            "# Azure AD: list all users",
            "az ad user list --output json > azure_users.json",
            "",
            "# Azure AD: list privileged role assignments",
            "az role assignment list --all --output json > azure_role_assignments.json",
            "",
            "# Active Directory (PowerShell)",
            "Get-ADUser -Filter * -Properties * | Export-Csv ad_users.csv",
            "Get-ADGroupMember -Identity 'Domain Admins' | Export-Csv domain_admins.csv",
        ],
        "must_do_checks": [
            "Confirm the inventory includes ALL environments (prod, staging, dev, DR)",
            "Verify service accounts are listed with a named human owner",
            "Identify shared/generic accounts (e.g., 'admin', 'sysadmin') — flag immediately",
            "Cross-reference against HR off-boarding list to find orphaned accounts",
            "Count total privileged accounts — flag if > 5% of total user base",
        ],
        "linked_skills": [
            "identity-access/privileged-account-monitor/",
        ],
    },
    {
        "step": 2,
        "title": "IAM Policy Review",
        "objective": (
            "Analyse all IAM policies attached to users, roles, and groups for "
            "excessive permissions, wildcard actions, admin-equivalent privileges, "
            "missing conditions, and inline policy usage."
        ),
        "artefacts": [
            "iam_policies.json — all managed and inline policies",
            "role_trust_policies.json — role trust relationships",
            "policy_analysis_report.md — output from access-review skill",
            "unused_permissions_report.csv — actions granted but never used (IAM Access Analyzer)",
        ],
        "tools_commands": [
            "# Run the access-review skill (local file)",
            "python identity-access/access-review/main.py \\",
            "  --input iam_policies.json --mode local",
            "",
            "# Run against live AWS environment",
            "python identity-access/access-review/main.py --mode aws",
            "",
            "# Run against Azure (dry-run first)",
            "python identity-access/access-review/main.py --mode azure --dry-run",
            "",
            "# AWS: export all managed policies",
            "aws iam list-policies --scope Local --output json > managed_policies.json",
            "",
            "# AWS: generate least-privilege report with Access Analyzer",
            "aws accessanalyzer list-analyzers --output json",
        ],
        "must_do_checks": [
            "Flag any policy with Action: '*' — escalate to Critical immediately",
            "Check all admin/root accounts use hardware MFA, not software MFA",
            "Verify no access keys exist for root account (aws iam get-account-summary)",
            "Confirm all cross-account trust relationships are documented and approved",
            "Review resource-based policies on S3 buckets, KMS keys, and Lambda functions",
        ],
        "linked_skills": [
            "identity-access/access-review/",
        ],
    },
    {
        "step": 3,
        "title": "MFA Verification",
        "objective": (
            "Verify that multi-factor authentication is enforced for all user accounts, "
            "with particular focus on privileged accounts and console access. "
            "Confirm MFA type (hardware vs software) for high-privilege accounts."
        ),
        "artefacts": [
            "mfa_status_report.csv — MFA enrolment status per user",
            "mfa_policy_evidence.json — IAM policy enforcing MFA for console access",
            "hardware_mfa_register.csv — hardware token assignments for privileged accounts",
        ],
        "tools_commands": [
            "# AWS: list users with MFA devices",
            "aws iam list-virtual-mfa-devices --output json > virtual_mfa.json",
            "",
            "# AWS: check specific user MFA",
            "aws iam list-mfa-devices --user-name <username>",
            "",
            "# AWS: identify users WITHOUT MFA",
            "aws iam generate-credential-report",
            "aws iam get-credential-report --query 'Content' --output text | base64 -d > cred_report.csv",
            "",
            "# Azure: check MFA status via Graph API",
            "az rest --method GET \\",
            "  --url 'https://graph.microsoft.com/v1.0/users?$select=displayName,mfaMethods'",
        ],
        "must_do_checks": [
            "100% of privileged accounts (admin, root, Owner) MUST have MFA — no exceptions",
            "Verify the MFA enforcement IAM policy is attached at the account level",
            "Confirm hardware MFA is used for root account and C-suite accounts",
            "Check MFA is required for all API access, not just console login",
            "Identify and remediate any accounts with MFA disabled that have active access keys",
        ],
        "linked_skills": [],
    },
    {
        "step": 4,
        "title": "Privileged Account Monitoring",
        "objective": (
            "Review recent activity of privileged accounts for anomalies including "
            "off-hours access, unusual action volumes, sensitive operations, and "
            "unknown/new accounts performing privileged activities."
        ),
        "artefacts": [
            "cloudtrail_logs.json or privileged_logs.csv — activity log extract",
            "privileged_account_monitor_report.md — output from privileged-account-monitor skill",
            "anomalous_events_list.csv — flagged events for management review",
        ],
        "tools_commands": [
            "# Run the privileged-account-monitor skill (local logs)",
            "python identity-access/privileged-account-monitor/main.py \\",
            "  --logs cloudtrail_logs.csv --baseline 50 --hours '08:00-18:00'",
            "",
            "# Run against live CloudTrail",
            "python identity-access/privileged-account-monitor/main.py --mode aws",
            "",
            "# AWS: filter CloudTrail for root activity",
            "aws cloudtrail lookup-events \\",
            "  --lookup-attributes AttributeKey=Username,AttributeValue=root \\",
            "  --output json",
            "",
            "# AWS: look for console login failures",
            "aws cloudtrail lookup-events \\",
            "  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLoginFailure",
        ],
        "must_do_checks": [
            "Any root account activity must be documented with a business justification",
            "Off-hours privileged access must be reviewed with the account owner",
            "New/unknown privileged users must be verified against HR and IT records",
            "Sensitive actions (DeleteTrail, StopLogging) require immediate escalation",
            "Review accounts exceeding baseline — confirm legitimate business reason",
        ],
        "linked_skills": [
            "identity-access/privileged-account-monitor/",
        ],
    },
    {
        "step": 5,
        "title": "Segregation of Duties Analysis",
        "objective": (
            "Identify users who hold conflicting roles that violate the four-eyes "
            "principle or enable fraud. Focus on financial, deployment, access management, "
            "and audit-related role conflicts."
        ),
        "artefacts": [
            "user_roles_matrix.json — user-to-role mapping for all in-scope systems",
            "sod_conflict_report.md — output from sod-analyzer skill",
            "sod_exceptions_register.csv — approved exceptions with compensating controls",
        ],
        "tools_commands": [
            "# Run the sod-analyzer skill with built-in conflict library",
            "python identity-access/sod-analyzer/main.py \\",
            "  --users user_roles_matrix.json \\",
            "  --builtin-conflicts",
            "",
            "# Run with custom and built-in conflicts",
            "python identity-access/sod-analyzer/main.py \\",
            "  --users user_roles_matrix.json \\",
            "  --conflicts custom_sod_rules.json \\",
            "  --builtin-conflicts",
            "",
            "# AWS: export role assignments for analysis",
            "aws iam list-users | jq '.Users[].UserName' | xargs -I {} \\",
            "  aws iam list-groups-for-user --user-name {}",
        ],
        "must_do_checks": [
            "All Critical SOD conflicts (financial, access management) must be remediated or formally excepted",
            "Exceptions must be approved by management and have documented compensating controls",
            "Re-run analysis after remediation to confirm conflicts are resolved",
            "Ensure the SOD matrix covers all applications, not just cloud IAM",
            "Validate service accounts do not hold conflicting roles that humans cannot",
        ],
        "linked_skills": [
            "identity-access/sod-analyzer/",
        ],
    },
    {
        "step": 6,
        "title": "Reporting & Remediation Tracking",
        "objective": (
            "Compile all IAM findings into a structured report, agree remediation "
            "timelines with management, and establish a tracking mechanism for "
            "open items until closure."
        ),
        "artefacts": [
            "iam_audit_findings.json — structured findings in exec-summary-writer format",
            "iam_executive_summary.md — output from exec-summary-writer skill",
            "management_action_plan.xlsx — agreed remediation actions and due dates",
            "remediation_evidence/ — evidence of completed fixes",
        ],
        "tools_commands": [
            "# Generate executive summary from findings",
            "python lead-it-auditor/exec-summary-writer/main.py \\",
            "  --findings iam_audit_findings.json \\",
            "  --scope 'IAM Audit — Q3 2025'",
            "",
            "# Track evidence collection",
            "python compliance-controls/evidence-tracker/main.py \\",
            "  --program audit_program.json --list",
        ],
        "must_do_checks": [
            "All Critical findings must have a remediation deadline within 7 days",
            "All High findings must have a remediation deadline within 30 days",
            "Obtain written management response for every finding",
            "Schedule a follow-up review for unresolved Critical/High items",
            "Document compensating controls for any finding that cannot be immediately remediated",
        ],
        "linked_skills": [
            "lead-it-auditor/exec-summary-writer/",
            "compliance-controls/evidence-tracker/",
        ],
    },
]


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="IAM audit playbook — step-by-step methodology for identity and access management audits."
    )
    parser.add_argument(
        "--step",
        default="full",
        help="Step number (1-6) or 'full' for all steps (default: full)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_step(step: Dict) -> str:
    """Render a single playbook step as markdown.

    Args:
        step: Step dict from PLAYBOOK.

    Returns:
        Markdown string for the step.
    """
    lines: List[str] = []
    lines.append(f"## Step {step['step']}: {step['title']}\n")
    lines.append(f"**Objective:** {step['objective']}\n")

    lines.append("### Artefacts to Collect\n")
    for a in step["artefacts"]:
        lines.append(f"- {a}")
    lines.append("")

    lines.append("### Tools & Commands\n")
    lines.append("```bash")
    for cmd in step["tools_commands"]:
        lines.append(cmd)
    lines.append("```\n")

    lines.append("### ✅ Must-Do Checks\n")
    for check in step["must_do_checks"]:
        lines.append(f"- [ ] {check}")
    lines.append("")

    if step["linked_skills"]:
        lines.append("### 🔗 Linked Skills\n")
        for skill in step["linked_skills"]:
            lines.append(f"- `{skill}`")
        lines.append("")

    lines.append("---\n")
    return "\n".join(lines)


def render_full() -> str:
    """Render the complete IAM playbook.

    Returns:
        Full markdown playbook string.
    """
    lines: List[str] = []
    lines.append("# Identity & Access Management Audit Playbook\n")
    lines.append(
        "This playbook provides a step-by-step methodology for auditing IAM controls "
        "across cloud and on-premise environments. Follow steps in sequence for a "
        "complete IAM audit engagement.\n"
    )
    lines.append("| Step | Title |")
    lines.append("|------|-------|")
    for s in PLAYBOOK:
        lines.append(f"| {s['step']} | {s['title']} |")
    lines.append("\n---\n")
    for s in PLAYBOOK:
        lines.append(render_step(s))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point."""
    args = parse_args()

    if args.step == "full":
        print(render_full())
        return

    try:
        step_num = int(args.step)
    except ValueError:
        print(f"ERROR: --step must be an integer (1-{len(PLAYBOOK)}) or 'full'.", file=sys.stderr)
        sys.exit(1)

    if step_num < 1 or step_num > len(PLAYBOOK):
        print(f"ERROR: --step must be between 1 and {len(PLAYBOOK)}.", file=sys.stderr)
        sys.exit(1)

    step = next(s for s in PLAYBOOK if s["step"] == step_num)
    print(f"# Identity & Access Management Audit Playbook\n")
    print(render_step(step))


if __name__ == "__main__":
    main()
