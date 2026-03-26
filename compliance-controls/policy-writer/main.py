"""Policy Writer — generate security policy documents from framework-aligned templates.

Produces professional markdown policy documents for password, access control,
encryption, incident response, and acceptable use topics. Policy statements are
enriched with framework-specific language for SOC2, ISO27001, NIST, CIS,
PCI-DSS, and GDPR.
"""

import argparse
import sys
from datetime import date
from typing import Dict, List

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Framework-specific language injections
# ---------------------------------------------------------------------------

FRAMEWORK_REFS: Dict[str, Dict[str, str]] = {
    "SOC2": {
        "standard_ref": "SOC 2 Type II (AICPA Trust Services Criteria)",
        "access_criterion": "CC6.1, CC6.2, CC6.3",
        "logging_criterion": "CC7.2",
        "change_criterion": "CC8.1",
        "risk_criterion": "CC9.1",
        "privacy_criterion": "P1.1–P8.1",
        "crypto_criterion": "CC6.7",
        "incident_criterion": "CC7.3, CC7.4",
    },
    "ISO27001": {
        "standard_ref": "ISO/IEC 27001:2022",
        "access_criterion": "A.9.1, A.9.2, A.9.4",
        "logging_criterion": "A.12.4",
        "change_criterion": "A.12.1.2",
        "risk_criterion": "Clause 6.1",
        "privacy_criterion": "A.18.1.4",
        "crypto_criterion": "A.10.1",
        "incident_criterion": "A.16.1",
    },
    "NIST": {
        "standard_ref": "NIST Cybersecurity Framework 2.0 / SP 800-53",
        "access_criterion": "AC-2, AC-3, AC-6",
        "logging_criterion": "AU-2, AU-3, SI-4",
        "change_criterion": "CM-3, SA-10",
        "risk_criterion": "RA-3, PM-9",
        "privacy_criterion": "AP-1, AR-1",
        "crypto_criterion": "SC-12, SC-13, SC-28",
        "incident_criterion": "IR-4, IR-5, IR-6",
    },
    "CIS": {
        "standard_ref": "CIS Controls v8",
        "access_criterion": "CIS Control 5, 6",
        "logging_criterion": "CIS Control 8",
        "change_criterion": "CIS Control 4",
        "risk_criterion": "CIS Control 18",
        "privacy_criterion": "CIS Control 3",
        "crypto_criterion": "CIS Control 3.10, 3.11",
        "incident_criterion": "CIS Control 17",
    },
    "PCI-DSS": {
        "standard_ref": "PCI DSS v4.0",
        "access_criterion": "Req 7, Req 8",
        "logging_criterion": "Req 10",
        "change_criterion": "Req 6.3, Req 6.4",
        "risk_criterion": "Req 12.3",
        "privacy_criterion": "Req 3, Req 4",
        "crypto_criterion": "Req 3.5, Req 4.2",
        "incident_criterion": "Req 12.10",
    },
    "GDPR": {
        "standard_ref": "EU General Data Protection Regulation (GDPR) 2016/679",
        "access_criterion": "Article 25, Article 32",
        "logging_criterion": "Article 30, Article 32",
        "change_criterion": "Article 25",
        "risk_criterion": "Article 35 (DPIA)",
        "privacy_criterion": "Articles 12–23",
        "crypto_criterion": "Article 32(1)(a)",
        "incident_criterion": "Articles 33–34",
    },
}

DEFAULT_FRAMEWORK = {
    "standard_ref": "Industry best practice",
    "access_criterion": "Access control best practices",
    "logging_criterion": "Logging best practices",
    "change_criterion": "Change management best practices",
    "risk_criterion": "Risk management best practices",
    "privacy_criterion": "Privacy best practices",
    "crypto_criterion": "Cryptography best practices",
    "incident_criterion": "Incident response best practices",
}

# ---------------------------------------------------------------------------
# Policy templates
# ---------------------------------------------------------------------------


def get_framework(framework: str) -> Dict[str, str]:
    """Return framework reference dict, falling back to default.

    Args:
        framework: Framework name string.

    Returns:
        Framework reference dict.
    """
    return FRAMEWORK_REFS.get(framework.upper(), DEFAULT_FRAMEWORK)


def policy_password(org: str, framework: str, review_cycle: str) -> str:
    """Generate Password Management Policy.

    Args:
        org: Organisation name.
        framework: Compliance framework.
        review_cycle: Review frequency.

    Returns:
        Markdown policy string.
    """
    ref = get_framework(framework)
    today = date.today().isoformat()
    return f"""# Password Management Policy

| Field | Value |
|-------|-------|
| **Policy Title** | Password Management Policy |
| **Version** | 1.0 |
| **Effective Date** | {today} |
| **Owner** | Information Security Team |
| **Review Cycle** | {review_cycle} |
| **Framework Alignment** | {ref['standard_ref']} ({ref['access_criterion']}) |

---

## 1. Purpose

This policy establishes minimum requirements for the creation, complexity, storage,
and management of passwords used to access {org} systems, applications, and data.
Strong password controls reduce the risk of unauthorised access through credential
compromise or brute-force attacks.

---

## 2. Scope

This policy applies to all employees, contractors, consultants, temporary staff,
and third parties who access {org} information systems. It covers all passwords
used to authenticate to any system, application, cloud service, or network resource
owned or managed by {org}.

---

## 3. Policy Statements

1. **Minimum Length:** All passwords must be a minimum of **14 characters** in length.
   Passphrases of 4+ random words are encouraged as an alternative.

2. **Complexity:** Passwords must include at least three of the following: uppercase
   letters, lowercase letters, numbers, and special characters (!@#$%^&*).

3. **Password History:** Users must not reuse any of their last **12 passwords**.

4. **Maximum Age:** Passwords for privileged and administrative accounts must be
   changed every **90 days**. Standard user passwords must be changed every **180 days**,
   or immediately upon suspected compromise.

5. **Account Lockout:** Accounts must be locked after **5 consecutive failed** login
   attempts. Locked accounts require IT helpdesk intervention to unlock.

6. **No Sharing:** Passwords must never be shared between users. Shared/service
   account passwords must be stored in an approved password vault with access auditing.

7. **Password Storage:** Passwords must never be stored in plain text, embedded in
   scripts, or transmitted via email or messaging platforms. Use an approved password
   manager ({org}-sanctioned tool) for all password storage.

8. **Default Passwords:** All vendor-supplied default passwords must be changed
   before any system is placed into production. ({ref['access_criterion']})

9. **MFA Precedence:** Where multi-factor authentication is available, it takes
   precedence over password-only controls. All privileged access must use MFA.

10. **Immediate Reset:** Passwords must be reset immediately when: (a) compromise is
    suspected, (b) an employee with access leaves the organisation, or (c) IT Security
    requests a reset.

---

## 4. Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| **All Users** | Create strong passwords; never share; report suspected compromise immediately |
| **IT Security** | Define and enforce technical password controls; manage lockout policies |
| **IT Helpdesk** | Unlock accounts after verifying identity; reset compromised credentials |
| **System Owners** | Ensure systems enforce this policy; disable default accounts |
| **HR** | Notify IT Security immediately upon employee off-boarding |

---

## 5. Compliance and Enforcement

Violation of this policy may result in disciplinary action up to and including
termination of employment or contract. Incidents involving password misuse will
be investigated in accordance with {org}'s Incident Response Policy.

Technical controls will be implemented to enforce password requirements where
technically feasible. Compliance will be verified through periodic audits.

---

## 6. Exceptions Process

Exceptions to this policy must be submitted in writing to the Information Security
Team, include a documented risk assessment, and be approved by the CISO or equivalent.
All approved exceptions are time-limited to a maximum of **90 days** and must be
reviewed before renewal.

---

## 7. Review and Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | {today} | Information Security Team | Initial release |

---

## 8. Related Documents

- Access Control Policy
- Multi-Factor Authentication Standard
- Acceptable Use Policy
- Privileged Access Management Procedure
"""


def policy_access(org: str, framework: str, review_cycle: str) -> str:
    """Generate Access Control Policy.

    Args:
        org: Organisation name.
        framework: Compliance framework.
        review_cycle: Review frequency.

    Returns:
        Markdown policy string.
    """
    ref = get_framework(framework)
    today = date.today().isoformat()
    return f"""# Access Control Policy

| Field | Value |
|-------|-------|
| **Policy Title** | Access Control Policy |
| **Version** | 1.0 |
| **Effective Date** | {today} |
| **Owner** | Information Security Team |
| **Review Cycle** | {review_cycle} |
| **Framework Alignment** | {ref['standard_ref']} ({ref['access_criterion']}) |

---

## 1. Purpose

This policy defines the requirements for granting, reviewing, and revoking access
to {org} information systems and data. It ensures that access is granted based on
business need, follows the principle of least privilege, and is subject to regular
review to prevent unauthorised or excessive access.

---

## 2. Scope

This policy applies to all {org} information systems, applications, cloud services,
databases, and network infrastructure. It covers all access types including physical,
logical, privileged, and third-party access.

---

## 3. Policy Statements

1. **Least Privilege:** Access must be granted based on the minimum permissions
   required to perform a defined job function. No user or system shall have more
   access than necessary. ({ref['access_criterion']})

2. **Access Requests:** All access requests must be submitted through the formal
   access request workflow, approved by the requesting user's manager and the
   system owner before provisioning.

3. **Role-Based Access Control:** Access must be managed through defined roles
   aligned to job functions. Individual permissions outside of roles require
   additional CISO approval.

4. **Privileged Access:** Administrative and privileged access must be granted
   only to designated administrators, used only for administrative tasks, and
   reviewed quarterly.

5. **Access Reviews:** All user access must be reviewed at minimum every **90 days**
   for privileged accounts and every **6 months** for standard accounts. Access
   must be revoked promptly for any account no longer requiring it.

6. **Joiner/Mover/Leaver:** HR must notify IT Security within **24 hours** of an
   employee joining, changing roles, or leaving. Access must be provisioned,
   modified, or revoked within **24 hours** of notification.

7. **Termination:** All access must be disabled on or before the last day of
   employment or contract. Access keys, tokens, and certificates must be revoked.

8. **Third-Party Access:** Vendors and contractors must be granted time-limited
   access scoped to specific systems required for their engagement. All third-party
   access must be reviewed and reauthorised every **30 days**.

9. **Shared Accounts:** Generic or shared accounts (e.g., 'admin', 'root') are
   prohibited except where technically unavoidable. Where used, access must be
   vaulted and individually attributed through session recording.

10. **Multi-Factor Authentication:** MFA is mandatory for all privileged access,
    remote access, and cloud management console access. ({ref['access_criterion']})

---

## 4. Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| **Managers** | Approve access requests; certify quarterly access reviews for their teams |
| **System Owners** | Maintain accurate access lists; approve role-based access for their systems |
| **IT Security** | Define access control standards; conduct access audits; manage PAM tools |
| **HR** | Notify IT Security of all joiners, movers, and leavers within 24 hours |
| **All Users** | Use only authorised access; report suspected unauthorised access immediately |

---

## 5. Compliance and Enforcement

Access control compliance is verified through quarterly access reviews, annual
audits, and continuous monitoring via the SIEM platform. Violations may result
in immediate access revocation and disciplinary action.

---

## 6. Exceptions Process

Exceptions require written justification, risk assessment, CISO approval, and
a defined expiry date not exceeding 90 days.

---

## 7. Review and Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | {today} | Information Security Team | Initial release |

---

## 8. Related Documents

- Password Management Policy
- Privileged Access Management Procedure
- Third-Party Access Standard
- Identity Governance Procedure
"""


def policy_encryption(org: str, framework: str, review_cycle: str) -> str:
    """Generate Encryption Policy."""
    ref = get_framework(framework)
    today = date.today().isoformat()
    return f"""# Encryption Policy

| Field | Value |
|-------|-------|
| **Policy Title** | Encryption Policy |
| **Version** | 1.0 |
| **Effective Date** | {today} |
| **Owner** | Information Security Team |
| **Review Cycle** | {review_cycle} |
| **Framework Alignment** | {ref['standard_ref']} ({ref['crypto_criterion']}) |

---

## 1. Purpose

This policy establishes cryptographic standards for {org} to protect the
confidentiality and integrity of sensitive data at rest and in transit.

---

## 2. Scope

All {org} systems, applications, and services that store, process, or transmit
sensitive, confidential, or regulated data.

---

## 3. Policy Statements

1. **Encryption at Rest:** All sensitive and confidential data must be encrypted
   at rest using **AES-256** or equivalent. ({ref['crypto_criterion']})

2. **Encryption in Transit:** All data transmitted over public or untrusted networks
   must use **TLS 1.2 or higher**. TLS 1.0 and 1.1 are prohibited.

3. **Prohibited Algorithms:** MD5, SHA-1, DES, 3DES, RC4, and SSL are prohibited
   for any new implementations. Existing uses must be migrated within 12 months.

4. **Key Management:** Encryption keys must be stored separately from encrypted data,
   rotated annually, and managed in an approved key management system (KMS).

5. **Key Custody:** No single individual shall have sole access to encryption keys
   for critical systems. Dual-control or split-knowledge procedures must be used.

6. **Certificate Management:** TLS/SSL certificates must use a minimum of 2048-bit
   RSA or 256-bit ECC keys and be renewed before expiry with automated alerting.

7. **Mobile and Removable Media:** All mobile devices and removable media used to
   store {org} data must use full-disk encryption.

8. **Code and Secrets:** Cryptographic keys, passwords, and secrets must never be
   hardcoded in source code. Use approved secrets management tools.

9. **Data Deletion:** Cryptographic erasure is an acceptable method for data
   deletion on encrypted storage, provided key destruction is documented.

10. **Algorithm Review:** Approved encryption algorithms and key lengths will be
    reviewed annually against NIST and industry guidance.

---

## 4. Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| **IT Security** | Define approved algorithms; manage KMS; conduct annual algorithm review |
| **Developers** | Implement encryption per this policy; use approved libraries only |
| **System Owners** | Ensure encryption is enabled on all systems storing sensitive data |
| **IT Operations** | Manage certificate lifecycle; ensure timely renewal |

---

## 5. Compliance and Enforcement

Encryption compliance is verified through annual audits, vulnerability scans,
and code review processes. Non-compliant implementations must be remediated within
30 days of identification.

---

## 6. Exceptions Process

Exceptions require CISO approval, documented technical justification, and compensating
controls. Maximum exception period is 90 days.

---

## 7. Review and Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | {today} | Information Security Team | Initial release |

---

## 8. Related Documents

- Data Classification Policy
- Key Management Procedure
- Secure Development Policy
- Data Retention and Deletion Policy
"""


def policy_incident_response(org: str, framework: str, review_cycle: str) -> str:
    """Generate Incident Response Policy."""
    ref = get_framework(framework)
    today = date.today().isoformat()
    return f"""# Incident Response Policy

| Field | Value |
|-------|-------|
| **Policy Title** | Incident Response Policy |
| **Version** | 1.0 |
| **Effective Date** | {today} |
| **Owner** | Information Security Team |
| **Review Cycle** | {review_cycle} |
| **Framework Alignment** | {ref['standard_ref']} ({ref['incident_criterion']}) |

---

## 1. Purpose

This policy defines the framework for detecting, responding to, and recovering from
information security incidents at {org}. It ensures a consistent, timely, and
effective response that minimises business impact and meets regulatory obligations.

---

## 2. Scope

All information security incidents affecting {org} systems, data, personnel, or
third parties acting on behalf of {org}, regardless of origin.

---

## 3. Policy Statements

1. **Incident Definition:** An information security incident is any event that
   compromises or threatens the confidentiality, integrity, or availability of
   {org} data or systems. All suspected incidents must be reported.

2. **Reporting Obligation:** All employees must report suspected incidents to the
   IT Security team within **1 hour** of discovery via the designated reporting
   channel. Failure to report is itself a policy violation.

3. **Incident Response Team:** {org} must maintain a documented Incident Response
   Team (IRT) with defined roles, contacts, and escalation paths, available
   24/7 for critical incidents. ({ref['incident_criterion']})

4. **Incident Classification:** All incidents must be classified by severity
   (Critical, High, Medium, Low) within **2 hours** of identification, using the
   documented severity matrix.

5. **Response SLAs:** Critical incidents require immediate response with executive
   notification within **1 hour**. High incidents require response within **4 hours**.

6. **Containment First:** The first priority upon identifying an incident is
   containment to prevent further damage, before investigation or remediation.

7. **Evidence Preservation:** Digital evidence must be preserved in a forensically
   sound manner. Systems must not be powered off without IRT approval during an
   active investigation.

8. **Regulatory Notification:** Data breaches affecting personal data must be
   reported to the relevant regulator within **72 hours** of discovery.
   Affected data subjects must be notified without undue delay. ({ref['incident_criterion']})

9. **Post-Incident Review:** A post-incident review (PIR) must be conducted within
   **5 business days** of closing any Critical or High incident. Findings must be
   documented and remediation actions tracked.

10. **Testing:** The incident response plan must be tested at minimum **annually**
    through tabletop exercises or simulations. Lessons learned must update this policy.

---

## 4. Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| **All Staff** | Report suspected incidents immediately; preserve evidence; do not discuss externally |
| **IT Security** | Lead incident response; coordinate IRT; manage communications |
| **IRT Members** | Respond per defined runbooks; document all actions with timestamps |
| **Legal/Compliance** | Advise on regulatory obligations; manage external notifications |
| **Senior Management** | Approve major decisions; manage executive and board communications |

---

## 5. Compliance and Enforcement

All employees are required to cooperate fully with incident investigations.
Obstruction, evidence tampering, or failure to report incidents will result in
disciplinary action and may constitute a criminal offence.

---

## 6. Exceptions Process

No exceptions to incident reporting obligations are permitted.

---

## 7. Review and Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | {today} | Information Security Team | Initial release |

---

## 8. Related Documents

- Business Continuity Plan
- Data Breach Notification Procedure
- Forensic Investigation Procedure
- Crisis Communications Plan
"""


def policy_acceptable_use(org: str, framework: str, review_cycle: str) -> str:
    """Generate Acceptable Use Policy."""
    ref = get_framework(framework)
    today = date.today().isoformat()
    return f"""# Acceptable Use Policy

| Field | Value |
|-------|-------|
| **Policy Title** | Acceptable Use Policy |
| **Version** | 1.0 |
| **Effective Date** | {today} |
| **Owner** | Information Security Team |
| **Review Cycle** | {review_cycle} |
| **Framework Alignment** | {ref['standard_ref']} ({ref['access_criterion']}) |

---

## 1. Purpose

This policy defines acceptable and unacceptable use of {org} information systems,
devices, networks, and data. It protects {org} from legal liability and reputational
harm, and ensures the security and availability of systems for legitimate business use.

---

## 2. Scope

This policy applies to all employees, contractors, interns, and third parties who
access {org} systems or data, using either {org}-owned or personally-owned devices.

---

## 3. Policy Statements

1. **Business Use:** {org} systems and data must be used primarily for legitimate
   business purposes. Limited, reasonable personal use is permitted provided it
   does not interfere with work duties or consume significant resources.

2. **Prohibited Activities:** The following are strictly prohibited on {org} systems:
   - Accessing, storing, or distributing illegal content of any kind
   - Circumventing or attempting to circumvent security controls
   - Unauthorised access to systems, accounts, or data belonging to others
   - Installing unauthorised software without IT approval
   - Mining cryptocurrency or running non-business compute workloads
   - Sharing {org} data with unauthorised parties

3. **Data Handling:** Sensitive and confidential data must be handled in accordance
   with {org}'s Data Classification Policy. Confidential data must not be transmitted
   via personal email or unapproved file-sharing services.

4. **Device Security:** Users are responsible for keeping their assigned devices
   physically secure, applying approved screen locks, and reporting loss or theft
   immediately.

5. **Network Usage:** Users must not connect unauthorised devices to {org} networks.
   Use of public Wi-Fi for accessing {org} systems requires an approved VPN.

6. **Social Media:** Employees must not disclose confidential {org} information on
   social media. All external communications referencing {org} must comply with
   the Communications Policy.

7. **Monitoring:** {org} reserves the right to monitor, access, and review all
   activity on its systems and networks, to the extent permitted by applicable law.
   Users have no expectation of privacy on {org}-owned systems.

8. **Software Licensing:** Users must only use software for which {org} holds a
   valid licence. Pirated or unlicensed software is prohibited.

9. **Email and Communications:** Users must not use {org} email to send unsolicited
   commercial messages (spam), engage in harassment, or misrepresent their identity.

10. **Incident Reporting:** Users must immediately report suspected security incidents,
    policy violations, or suspicious activity to IT Security.

---

## 4. Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| **All Users** | Read, understand, and comply with this policy; report violations |
| **Managers** | Ensure team members have read and acknowledged this policy |
| **IT Security** | Monitor compliance; investigate violations; update policy annually |
| **HR** | Incorporate policy acknowledgement into on-boarding; manage disciplinary process |

---

## 5. Compliance and Enforcement

All staff must acknowledge this policy annually. Violations may result in
disciplinary action up to and including termination. Serious violations may be
referred to law enforcement authorities.

---

## 6. Exceptions Process

Exceptions (e.g., security research requiring access to prohibited content) must
be approved in advance by IT Security and Legal, with documented scope and time limit.

---

## 7. Review and Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | {today} | Information Security Team | Initial release |

---

## 8. Related Documents

- Data Classification Policy
- Password Management Policy
- Incident Response Policy
- Remote Working Policy
"""


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

POLICY_FUNCTIONS = {
    "password": policy_password,
    "access": policy_access,
    "encryption": policy_encryption,
    "incident-response": policy_incident_response,
    "acceptable-use": policy_acceptable_use,
}


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate a framework-aligned security policy document."
    )
    parser.add_argument(
        "--framework",
        required=True,
        help="Compliance framework (e.g. SOC2, ISO27001, NIST, CIS, PCI-DSS, GDPR)",
    )
    parser.add_argument(
        "--topic",
        required=True,
        choices=list(POLICY_FUNCTIONS.keys()),
        help="Policy topic",
    )
    parser.add_argument(
        "--org-name",
        default="Your Organization",
        help="Organisation name to embed in the policy (default: 'Your Organization')",
    )
    parser.add_argument(
        "--review-cycle",
        default="Annual",
        help="Policy review frequency (default: Annual)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point."""
    args = parse_args()
    fn = POLICY_FUNCTIONS[args.topic]
    print(fn(args.org_name, args.framework, args.review_cycle))


if __name__ == "__main__":
    main()
