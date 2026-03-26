"""Compliance & Controls Audit Playbook — step-by-step compliance audit methodology.

Guides the compliance specialist through control framework selection, evidence
planning, testing procedures, exceptions handling, and reporting.
"""

import argparse
import sys
from typing import Dict, List

from dotenv import load_dotenv

load_dotenv()

PLAYBOOK: List[Dict] = [
    {
        "step": 1,
        "title": "Control Framework Selection",
        "objective": (
            "Identify the applicable compliance frameworks and standards for the "
            "audit engagement, map them to in-scope systems, and select the control "
            "set that will be tested. Agree the scope with management before proceeding."
        ),
        "artefacts": [
            "framework_mapping.xlsx — applicable standards (SOC2, ISO27001, PCI-DSS, CIS) per system",
            "control_selection_memo.docx — documented rationale for controls selected",
            "prior_compliance_reports.pdf — previous audit findings and certifications",
            "regulatory_requirements_register.xlsx — mandatory compliance obligations",
        ],
        "tools_commands": [
            "# Generate audit program for selected frameworks",
            "python lead-it-auditor/audit-scope-checklist/main.py \\",
            "  --system 'AWS production environment' \\",
            "  --frameworks 'SOC2,ISO27001' \\",
            "  --roles 'compliance-controls,identity-access'",
            "",
            "# Review CIS benchmark for the target platform",
            "python compliance-controls/compliance-checker/main.py \\",
            "  --config sample_input/config.json --standard cis",
        ],
        "must_do_checks": [
            "Confirm all regulatory and contractual compliance obligations are identified",
            "Verify the framework version being assessed matches certifications (e.g. SOC2 CC 2017)",
            "Get management sign-off on the control selection before fieldwork begins",
            "Check whether prior certifications (SOC2 reports, ISO certs) are still valid",
            "Identify any newly applicable frameworks since the last audit",
        ],
        "linked_skills": [
            "lead-it-auditor/audit-scope-checklist/",
        ],
    },
    {
        "step": 2,
        "title": "Evidence Request Planning",
        "objective": (
            "Create a comprehensive evidence request list from the audit program, "
            "assign ownership to each request, set deadlines, and initialise the "
            "evidence tracker. Send formal evidence requests to the auditee."
        ),
        "artefacts": [
            "evidence_request_list.xlsx — all requested items with owner and due date",
            "evidence_tracker.json — initialised tracker state",
            "evidence_request_letter.docx — formal request communication to auditee",
        ],
        "tools_commands": [
            "# Generate audit program and save JSON",
            "python lead-it-auditor/audit-scope-checklist/main.py \\",
            "  --system 'Target system' --output-dir ./audit-2025/",
            "",
            "# Initialise evidence tracker from the program",
            "python compliance-controls/evidence-tracker/main.py \\",
            "  --program ./audit-2025/audit_program.json --init",
            "",
            "# List all requested items",
            "python compliance-controls/evidence-tracker/main.py --list",
            "",
            "# Filter to see only outstanding requests",
            "python compliance-controls/evidence-tracker/main.py \\",
            "  --list --filter-status Requested",
        ],
        "must_do_checks": [
            "Every control in the audit program must have a corresponding evidence request",
            "Each evidence request must have a named owner and a due date",
            "Send evidence requests at least 2 weeks before fieldwork begins",
            "Confirm auditee acknowledges the request list in writing",
            "Identify which controls can be tested via automated tools vs manual review",
        ],
        "linked_skills": [
            "compliance-controls/evidence-tracker/",
            "lead-it-auditor/artefact-gap-analyzer/",
        ],
    },
    {
        "step": 3,
        "title": "Control Testing Procedures",
        "objective": (
            "Execute control tests for each in-scope control using a combination of "
            "automated checkers, document review, walkthroughs, and re-performance. "
            "Document test procedures, evidence used, and conclusions."
        ),
        "artefacts": [
            "control_test_workpapers/ — folder of test documentation per control",
            "compliance_check_report.md — output from compliance-checker skill",
            "walkthrough_notes.docx — documented walkthroughs with auditee",
            "test_results_summary.xlsx — pass/fail/exception per control",
        ],
        "tools_commands": [
            "# Run compliance checker against collected config",
            "python compliance-controls/compliance-checker/main.py \\",
            "  --config collected_config.json --standard soc2",
            "",
            "python compliance-controls/compliance-checker/main.py \\",
            "  --config collected_config.json --standard iso27001",
            "",
            "# Update evidence tracker as items are tested",
            "python compliance-controls/evidence-tracker/main.py \\",
            "  --update '{\"id\": \"CC-001\", \"status\": \"Accepted\", \"file\": \"infosec_policy.pdf\", \"reviewer\": \"Auditor Name\"}'",
            "",
            "# Check gap between expected and received artefacts",
            "python lead-it-auditor/artefact-gap-analyzer/main.py \\",
            "  --program audit_program.json --provided ./evidence/",
        ],
        "must_do_checks": [
            "Test each control using at least two of: inspection, observation, enquiry, re-performance",
            "Document the specific evidence item used to support each test conclusion",
            "Flag any controls with no evidence as exceptions — do not skip",
            "Re-run automated checks after auditee implements fixes (evidence of remediation)",
            "Obtain at least one walkthrough per key process area (access management, change management)",
        ],
        "linked_skills": [
            "compliance-controls/compliance-checker/",
            "compliance-controls/evidence-tracker/",
            "lead-it-auditor/artefact-gap-analyzer/",
        ],
    },
    {
        "step": 4,
        "title": "Exceptions and Gap Management",
        "objective": (
            "Identify, document, and evaluate all control exceptions and gaps. "
            "Assess the risk impact of each exception, agree compensating controls "
            "with management, and track remediation commitments."
        ),
        "artefacts": [
            "exceptions_register.xlsx — all exceptions with risk rating, owner, and due date",
            "compensating_controls_memo.docx — approved compensating controls",
            "management_response_letters/ — written management responses to exceptions",
        ],
        "tools_commands": [
            "# Generate policies for missing policy controls",
            "python compliance-controls/policy-writer/main.py \\",
            "  --framework ISO27001 --topic access --org-name 'Acme Corp'",
            "",
            "python compliance-controls/policy-writer/main.py \\",
            "  --framework SOC2 --topic incident-response --org-name 'Acme Corp'",
            "",
            "# Mark rejected evidence items in tracker",
            "python compliance-controls/evidence-tracker/main.py \\",
            "  --update '{\"id\": \"CC-003\", \"status\": \"Rejected\", \"notes\": \"Policy not reviewed in 12 months\"}'",
            "",
            "# Filter to see all rejected/outstanding items",
            "python compliance-controls/evidence-tracker/main.py \\",
            "  --list --filter-status Rejected",
        ],
        "must_do_checks": [
            "Every failed control must be documented as a formal finding with risk rating",
            "All Critical exceptions must be escalated to senior management immediately",
            "Compensating controls must be tested — not just accepted as described by management",
            "Get written management response for every exception before closing fieldwork",
            "Exceptions with no remediation plan must be escalated to the audit committee",
        ],
        "linked_skills": [
            "compliance-controls/policy-writer/",
            "compliance-controls/evidence-tracker/",
        ],
    },
    {
        "step": 5,
        "title": "Compliance Reporting",
        "objective": (
            "Compile all findings into a structured report, generate the executive "
            "summary, export the final evidence collection status, and present "
            "results to management. Archive all working papers."
        ),
        "artefacts": [
            "audit_findings.json — structured findings for exec-summary-writer",
            "executive_summary.md — output from exec-summary-writer skill",
            "evidence_summary.md — final evidence collection status export",
            "working_papers_archive.zip — all test documentation archived",
            "management_action_plan.xlsx — agreed remediation actions with due dates",
        ],
        "tools_commands": [
            "# Export final evidence summary",
            "python compliance-controls/evidence-tracker/main.py --export",
            "",
            "# Generate executive summary from findings",
            "python lead-it-auditor/exec-summary-writer/main.py \\",
            "  --findings audit_findings.json \\",
            "  --scope 'SOC2 Compliance Audit Q3 2025' \\",
            "  --author 'Compliance Audit Team'",
            "",
            "# Check artefact coverage before closing",
            "python lead-it-auditor/artefact-gap-analyzer/main.py \\",
            "  --program audit_program.json --provided ./evidence/",
        ],
        "must_do_checks": [
            "Evidence coverage must be >= 90% before issuing the final report",
            "All Critical and High findings must have agreed management remediation dates",
            "Executive summary must be reviewed by the lead auditor before distribution",
            "All working papers must be archived and retained per the retention policy",
            "Schedule a follow-up review for all open Critical/High items within 30 days",
        ],
        "linked_skills": [
            "lead-it-auditor/exec-summary-writer/",
            "compliance-controls/evidence-tracker/",
            "lead-it-auditor/artefact-gap-analyzer/",
        ],
    },
]


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Compliance & Controls audit playbook — step-by-step methodology."
    )
    parser.add_argument(
        "--step",
        default="full",
        help="Step number (1-5) or 'full' for all steps (default: full)",
    )
    return parser.parse_args()


def render_step(step: Dict) -> str:
    """Render a single step as markdown."""
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


def main() -> None:
    """Main entry point."""
    args = parse_args()

    if args.step == "full":
        print("# Compliance & Controls Audit Playbook\n")
        print("| Step | Title |")
        print("|------|-------|")
        for s in PLAYBOOK:
            print(f"| {s['step']} | {s['title']} |")
        print("\n---\n")
        for s in PLAYBOOK:
            print(render_step(s))
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
    print("# Compliance & Controls Audit Playbook\n")
    print(render_step(step))


if __name__ == "__main__":
    main()
