"""Compliance Checker — compare system configuration against security standards.

Checks a JSON configuration file against hardcoded control libraries for
CIS, SOC2, ISO 27001, and PCI-DSS. Produces a pass/fail report with
remediation guidance.
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Control libraries
# ---------------------------------------------------------------------------

STANDARDS: Dict[str, List[Dict[str, Any]]] = {
    "cis": [
        {"id": "CIS-1.1", "description": "Password minimum length >= 14 characters",
         "check_key": "password_min_length", "expected_value": 14, "operator": "gte",
         "remediation": "Set minimum password length to 14 or more characters in your password policy."},
        {"id": "CIS-1.2", "description": "Account lockout after <= 5 failed attempts",
         "check_key": "lockout_threshold", "expected_value": 5, "operator": "lte",
         "remediation": "Configure account lockout policy to trigger after 5 or fewer failed login attempts."},
        {"id": "CIS-1.3", "description": "Audit logging enabled",
         "check_key": "audit_logging_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Enable audit logging for all authentication and privileged actions."},
        {"id": "CIS-1.4", "description": "MFA enabled for all users",
         "check_key": "mfa_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Enforce MFA for all user accounts, especially those with privileged access."},
        {"id": "CIS-1.5", "description": "Encryption at rest enabled",
         "check_key": "encryption_at_rest", "expected_value": True, "operator": "eq",
         "remediation": "Enable encryption at rest for all data stores using AES-256 or equivalent."},
        {"id": "CIS-1.6", "description": "Patch management cycle <= 30 days for critical patches",
         "check_key": "patch_cycle_days", "expected_value": 30, "operator": "lte",
         "remediation": "Implement automated patching with a 30-day SLA for critical security patches."},
        {"id": "CIS-1.7", "description": "Firewall enabled and configured",
         "check_key": "firewall_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Ensure host-based and network firewalls are enabled and default-deny configured."},
        {"id": "CIS-1.8", "description": "Admin accounts used only for admin tasks",
         "check_key": "dedicated_admin_accounts", "expected_value": True, "operator": "eq",
         "remediation": "Create dedicated admin accounts separate from daily-use accounts for all admins."},
        {"id": "CIS-1.9", "description": "Remote access uses VPN or equivalent",
         "check_key": "vpn_required", "expected_value": True, "operator": "eq",
         "remediation": "Require VPN or Zero Trust Network Access for all remote administrative access."},
        {"id": "CIS-1.10", "description": "Backups taken at least daily",
         "check_key": "backup_frequency_hours", "expected_value": 24, "operator": "lte",
         "remediation": "Configure automated backups with at least daily frequency and test restores quarterly."},
        {"id": "CIS-1.11", "description": "Password complexity enforced",
         "check_key": "password_complexity_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Require passwords to include uppercase, lowercase, numbers, and special characters."},
        {"id": "CIS-1.12", "description": "Session timeout <= 15 minutes",
         "check_key": "session_timeout_minutes", "expected_value": 15, "operator": "lte",
         "remediation": "Set idle session timeout to 15 minutes or less for all management consoles."},
    ],
    "soc2": [
        {"id": "CC6.1", "description": "Logical access controls implemented",
         "check_key": "access_control_implemented", "expected_value": True, "operator": "eq",
         "remediation": "Implement role-based access control (RBAC) with documented access provisioning process."},
        {"id": "CC6.2", "description": "Authentication controls (passwords/MFA) in place",
         "check_key": "mfa_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Enforce multi-factor authentication for all user access to systems in scope."},
        {"id": "CC6.3", "description": "Access authorisation process documented",
         "check_key": "access_authorisation_documented", "expected_value": True, "operator": "eq",
         "remediation": "Document and implement a formal access request and authorisation workflow."},
        {"id": "CC7.1", "description": "Vulnerability management programme in place",
         "check_key": "vuln_management_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Establish a vulnerability management programme with regular scans and patch SLAs."},
        {"id": "CC7.2", "description": "Security monitoring and alerting enabled",
         "check_key": "security_monitoring_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Deploy SIEM or equivalent with alerts for anomalous activity and security events."},
        {"id": "CC8.1", "description": "Change management process implemented",
         "check_key": "change_management_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Implement a formal change management process with approval gates and rollback plans."},
        {"id": "A1.1", "description": "System availability SLA defined and monitored",
         "check_key": "availability_sla_defined", "expected_value": True, "operator": "eq",
         "remediation": "Define availability SLAs, implement uptime monitoring, and document DR procedures."},
        {"id": "PI1.1", "description": "Data processing integrity controls in place",
         "check_key": "data_integrity_controls", "expected_value": True, "operator": "eq",
         "remediation": "Implement input validation, checksums, and reconciliation controls for data processing."},
        {"id": "C1.1", "description": "Confidential data classified and protected",
         "check_key": "data_classification_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Implement data classification policy with appropriate handling controls per level."},
        {"id": "P1.1", "description": "Privacy notice provided to data subjects",
         "check_key": "privacy_notice_published", "expected_value": True, "operator": "eq",
         "remediation": "Publish a privacy notice describing data collection, use, and subject rights."},
        {"id": "CC9.1", "description": "Risk assessment conducted annually",
         "check_key": "risk_assessment_annual", "expected_value": True, "operator": "eq",
         "remediation": "Conduct and document a formal risk assessment at least annually."},
    ],
    "iso27001": [
        {"id": "A.9.1", "description": "Access control policy documented and approved",
         "check_key": "access_control_policy_exists", "expected_value": True, "operator": "eq",
         "remediation": "Create, approve, and communicate a formal access control policy aligned to ISO 27001 A.9."},
        {"id": "A.9.2", "description": "Formal user registration and de-registration process",
         "check_key": "user_lifecycle_managed", "expected_value": True, "operator": "eq",
         "remediation": "Implement formal joiner/mover/leaver process with documented approval workflow."},
        {"id": "A.9.4", "description": "System and application access control implemented",
         "check_key": "system_access_control_implemented", "expected_value": True, "operator": "eq",
         "remediation": "Restrict access to systems based on business need; implement least privilege."},
        {"id": "A.10.1", "description": "Cryptographic policy defined and key management in place",
         "check_key": "crypto_policy_defined", "expected_value": True, "operator": "eq",
         "remediation": "Define cryptographic controls policy covering algorithm standards, key lengths, and lifecycle."},
        {"id": "A.12.1", "description": "Documented operating procedures for IT operations",
         "check_key": "it_procedures_documented", "expected_value": True, "operator": "eq",
         "remediation": "Document all IT operational procedures and ensure they are reviewed annually."},
        {"id": "A.12.4", "description": "Logging and monitoring of system events",
         "check_key": "audit_logging_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Enable and retain system event logs; implement centralised log management."},
        {"id": "A.12.6", "description": "Technical vulnerability management process",
         "check_key": "vuln_management_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Establish timely identification and remediation of technical vulnerabilities."},
        {"id": "A.13.1", "description": "Network security controls implemented",
         "check_key": "network_security_controls", "expected_value": True, "operator": "eq",
         "remediation": "Implement network segregation, firewalls, and traffic monitoring per A.13."},
        {"id": "A.14.2", "description": "Secure development lifecycle policy",
         "check_key": "secure_sdlc_policy", "expected_value": True, "operator": "eq",
         "remediation": "Implement and enforce a secure software development lifecycle with security testing gates."},
        {"id": "A.16.1", "description": "Information security incident management process",
         "check_key": "incident_response_plan", "expected_value": True, "operator": "eq",
         "remediation": "Develop, test, and maintain a documented information security incident response plan."},
        {"id": "A.18.1", "description": "Compliance with legal and contractual requirements",
         "check_key": "legal_compliance_reviewed", "expected_value": True, "operator": "eq",
         "remediation": "Conduct regular reviews of legal and contractual obligations; document compliance status."},
    ],
    "pci-dss": [
        {"id": "PCI-1", "description": "Network access controls (firewall) installed and maintained",
         "check_key": "firewall_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Install and maintain network firewalls; document all rules with business justification."},
        {"id": "PCI-2", "description": "Vendor default passwords changed",
         "check_key": "default_passwords_changed", "expected_value": True, "operator": "eq",
         "remediation": "Change all vendor-supplied default passwords before deploying systems."},
        {"id": "PCI-3", "description": "Stored cardholder data protected (encryption/tokenisation)",
         "check_key": "cardholder_data_encrypted", "expected_value": True, "operator": "eq",
         "remediation": "Encrypt or tokenise all stored PAN data using strong cryptography (AES-256)."},
        {"id": "PCI-4", "description": "Cardholder data encrypted in transmission",
         "check_key": "encryption_in_transit", "expected_value": True, "operator": "eq",
         "remediation": "Use TLS 1.2+ for all transmission of cardholder data over public networks."},
        {"id": "PCI-6", "description": "Vulnerability management and secure development",
         "check_key": "vuln_management_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Maintain up-to-date security patches; implement secure coding practices and code reviews."},
        {"id": "PCI-7", "description": "Access to system components restricted to business need",
         "check_key": "access_control_implemented", "expected_value": True, "operator": "eq",
         "remediation": "Implement RBAC; grant access only based on documented business need and least privilege."},
        {"id": "PCI-8", "description": "Unique user IDs and authentication controls",
         "check_key": "unique_user_ids", "expected_value": True, "operator": "eq",
         "remediation": "Assign unique IDs to all users; prohibit shared accounts; enforce MFA for admin access."},
        {"id": "PCI-10", "description": "Access to network resources and cardholder data logged",
         "check_key": "audit_logging_enabled", "expected_value": True, "operator": "eq",
         "remediation": "Log all access to cardholder data environment; retain logs for at least 12 months."},
        {"id": "PCI-11", "description": "Regular testing of security systems and processes",
         "check_key": "security_testing_performed", "expected_value": True, "operator": "eq",
         "remediation": "Perform quarterly vulnerability scans and annual penetration tests."},
        {"id": "PCI-12", "description": "Information security policy maintained",
         "check_key": "infosec_policy_exists", "expected_value": True, "operator": "eq",
         "remediation": "Maintain a comprehensive information security policy reviewed at least annually."},
        {"id": "PCI-3.2", "description": "Sensitive authentication data not stored post-authorisation",
         "check_key": "sad_not_stored", "expected_value": True, "operator": "eq",
         "remediation": "Confirm CVV, full track data, and PIN data are never stored after transaction authorisation."},
    ],
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Check system configuration against CIS, SOC2, ISO27001, or PCI-DSS controls."
    )
    parser.add_argument("--config", required=True, help="Path to JSON configuration file")
    parser.add_argument(
        "--standard",
        required=True,
        choices=list(STANDARDS.keys()),
        help="Compliance standard to check against",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate_control(
    control: Dict[str, Any], config: Dict[str, Any]
) -> Dict[str, Any]:
    """Evaluate a single control against configuration.

    Args:
        control: Control definition dict.
        config: Configuration values dict.

    Returns:
        Result dict with status (Pass/Fail/N/A), actual value, and details.
    """
    key = control["check_key"]
    expected = control["expected_value"]
    operator = control.get("operator", "eq")

    if key not in config:
        return {
            "status": "N/A",
            "actual": "Not configured",
            "detail": f"Key '{key}' not found in configuration.",
        }

    actual = config[key]

    try:
        if operator == "eq":
            passed = actual == expected
        elif operator == "gte":
            passed = float(actual) >= float(expected)
        elif operator == "lte":
            passed = float(actual) <= float(expected)
        elif operator == "gt":
            passed = float(actual) > float(expected)
        elif operator == "lt":
            passed = float(actual) < float(expected)
        else:
            passed = actual == expected
    except (TypeError, ValueError):
        passed = False

    return {
        "status": "Pass" if passed else "Fail",
        "actual": actual,
        "detail": "",
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

STATUS_EMOJI = {"Pass": "✅", "Fail": "❌", "N/A": "⬜"}


def render_report(
    standard: str,
    config_path: str,
    controls: List[Dict[str, Any]],
    results: List[Dict[str, Any]],
) -> str:
    """Render the compliance check markdown report.

    Args:
        standard: Standard name string.
        config_path: Path to config file.
        controls: List of control dicts.
        results: List of result dicts (aligned with controls).

    Returns:
        Markdown string.
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    passed = sum(1 for r in results if r["status"] == "Pass")
    failed = sum(1 for r in results if r["status"] == "Fail")
    na = sum(1 for r in results if r["status"] == "N/A")
    total_scored = passed + failed
    pct = round((passed / total_scored * 100), 1) if total_scored > 0 else 0

    lines: List[str] = []
    lines.append(f"# Compliance Check Report — {standard.upper()}\n")
    lines.append(f"**Date:** {date_str}  ")
    lines.append(f"**Config File:** `{config_path}`  ")
    lines.append(f"**Standard:** {standard.upper()}  ")
    lines.append(f"**Controls Assessed:** {len(controls)}  ")
    lines.append(f"**Pass Rate:** {pct}% ({passed}/{total_scored} scored controls)\n")
    lines.append("---\n")

    # Summary bar
    lines.append("## Summary\n")
    lines.append("| Status | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| ✅ Pass | {passed} |")
    lines.append(f"| ❌ Fail | {failed} |")
    lines.append(f"| ⬜ N/A  | {na} |")
    lines.append("")
    lines.append("---\n")

    # Results table
    lines.append("## Control Results\n")
    lines.append("| Control ID | Description | Expected | Actual | Status | Remediation |")
    lines.append("|------------|-------------|----------|--------|--------|-------------|")

    for ctrl, result in zip(controls, results):
        status = result["status"]
        emoji = STATUS_EMOJI.get(status, "")
        expected = ctrl["expected_value"]
        actual = result["actual"]
        desc = ctrl["description"].replace("|", "\\|")
        remediation = ctrl["remediation"].replace("|", "\\|") if status == "Fail" else "—"
        lines.append(
            f"| `{ctrl['id']}` | {desc} | `{expected}` | `{actual}` | {emoji} {status} | {remediation} |"
        )

    lines.append("")

    # Failed controls callout
    failed_ctrls = [
        (ctrl, result)
        for ctrl, result in zip(controls, results)
        if result["status"] == "Fail"
    ]
    if failed_ctrls:
        lines.append("---\n")
        lines.append("## ❌ Failed Controls — Remediation Required\n")
        for ctrl, _ in failed_ctrls:
            lines.append(f"**{ctrl['id']} — {ctrl['description']}**  ")
            lines.append(f"{ctrl['remediation']}\n")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point."""
    args = parse_args()

    try:
        with open(args.config, "r", encoding="utf-8") as fh:
            config = json.load(fh)
    except FileNotFoundError:
        print(f"ERROR: Config file not found: '{args.config}'", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in config file — {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(config, dict):
        print("ERROR: Config file must be a JSON object.", file=sys.stderr)
        sys.exit(1)

    controls = STANDARDS[args.standard]
    results = [evaluate_control(ctrl, config) for ctrl in controls]
    print(render_report(args.standard, args.config, controls, results))


if __name__ == "__main__":
    main()
