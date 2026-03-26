# policy-writer

Generate professional, framework-aligned security policy documents ready for
review and adoption. Each policy includes all standard sections with numbered,
enforceable policy statements enriched with framework-specific references.

---

## Requirements

```bash
pip install python-dotenv
```

---

## Usage

```bash
# ISO 27001 Access Control Policy
python main.py --framework ISO27001 --topic access --org-name "Acme Corp"

# PCI-DSS Password Policy
python main.py \
  --framework PCI-DSS \
  --topic password \
  --org-name "PaymentCo Ltd" \
  --review-cycle "Semi-Annual"

# GDPR Incident Response Policy
python main.py --framework GDPR --topic incident-response --org-name "DataCo"

# NIST Encryption Policy
python main.py --framework NIST --topic encryption

# CIS Acceptable Use Policy
python main.py --framework CIS --topic acceptable-use --org-name "TechOrg"
```

---

## Available Topics

| Topic | Description |
|-------|-------------|
| `password` | Password creation, complexity, rotation, and storage |
| `access` | Access provisioning, least privilege, reviews, and off-boarding |
| `encryption` | Encryption standards, key management, prohibited algorithms |
| `incident-response` | Incident detection, response SLAs, breach notification |
| `acceptable-use` | System use rules, prohibited activities, monitoring notice |

---

## Supported Frameworks

`SOC2` · `ISO27001` · `NIST` · `CIS` · `PCI-DSS` · `GDPR`

Other framework names are accepted but will use generic best-practice language.

---

## Policy Sections

Every generated policy includes:
1. Title and metadata table (version, date, owner, review cycle, framework reference)
2. Purpose
3. Scope
4. Policy Statements (8–10 numbered, enforceable statements)
5. Roles and Responsibilities
6. Compliance and Enforcement
7. Exceptions Process
8. Review and Revision History
9. Related Documents
