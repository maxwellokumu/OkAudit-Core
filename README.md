# OkAudit Core

[![CI](https://github.com/maxwellokumu/OkAudit/actions/workflows/ci.yml/badge.svg)](https://github.com/maxwellokumu/OkAudit/actions/workflows/ci.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-85%25-green.svg)]()
[![Frameworks](https://img.shields.io/badge/frameworks-SOC2%20%7C%20ISO27001%20%7C%20PCI--DSS%20%7C%20NIST%20%7C%20GDPR-blue)]()

> **OkAudit Core** is the canonical source repository for building, testing, and evolving reusable IT audit capabilities. It is the upstream development home for the OkAudit virtual audit team: specialist roles, structured playbooks, and executable skills designed to support real-world assurance work from planning through reporting.

---

## Table of Contents

- [Overview](#overview)
- [What OkAudit Core Is](#what-okaudit-core-is)
- [Architecture](#architecture)
- [Skill Domains](#skill-domains)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
  - [CLI Usage](#cli-usage)
  - [Capability Packaging](#capability-packaging)
- [Configuration](#configuration)
- [Environment Variables](#environment-variables)
- [Testing](#testing)
- [Compliance Frameworks](#compliance-frameworks)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Author](#author)
- [License](#license)

---

## Overview

IT audit work is still slowed down by repeated setup, fragmented evidence collection, inconsistent review quality, and workflows that are difficult to scale across teams and frameworks.

**OkAudit Core** addresses this by turning practical audit methods into reusable capabilities. The repository organizes a virtual audit team of **9 specialist roles** and **36 skills**, each built to support discrete audit tasks across identity, compliance, privacy, application security, network security, logging, vendor risk, hardware and physical controls, and lead auditor workflows.

These capabilities can be developed and tested independently, executed through CLI workflows, and packaged downstream for practitioner-facing use.

### Why This Matters

OkAudit Core is designed to help teams:

- structure audit planning more consistently
- improve evidence review and control analysis
- standardize workflows across multiple assurance domains
- reduce repeated setup work in recurring audits
- move faster from fieldwork to defensible reporting

---

## What OkAudit Core Is

OkAudit Core is:

- the canonical development repository for the OkAudit capability library
- the place where specialist audit skills are built, tested, and refined
- a framework-aware source of reusable audit workflows
- the upstream foundation behind the Claude-ready distribution repository

OkAudit currently has two complementary public layers:

- **OkAudit Core**: the source repository where capabilities are built, tested, and extended
- **OkAudit Claude Skills**: the distribution repository where skills are packaged for direct Claude upload and use

Use this repository if you want the source logic, development workflow, tests, and capability framework.  
Use the Claude Skills repository if you want upload-ready practitioner packages.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                         OkAudit Core                        │
│             Source Repository for Audit Capabilities        │
└─────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
   │  CLI Runner │    │ Skill Logic │    │  Packaging  │
   │  (main.py)  │    │ + Playbooks │    │   Layer     │
   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
          └───────────────────┼───────────────────┘
                              │
                ┌─────────────▼─────────────┐
                │     Capability Library     │
                │  (36 reusable audit skills)│
                └─────────────┬─────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
 ┌────────────┐       ┌────────────┐       ┌────────────┐
 │  Evidence  │       │  Analysis  │       │  Reporting │
 │  Inputs    │──────▶│   Engine   │──────▶│  Outputs   │
 │ (JSON/CSV) │       │(Rules+Logic)│      │(MD/JSON/CSV)│
 └────────────┘       └────────────┘       └────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │  SOC2    │   │ ISO27001 │   │ PCI-DSS  │
        │  NIST    │   │  GDPR    │   │ Mappings │
        └──────────┘   └──────────┘   └──────────┘


OkAudit follows a layered architecture where raw system data is ingested, transformed through modular AI skills, and surfaced as structured, framework-aligned audit intelligence. Each layer is independently testable and replaceable.

---

## Skill Domains

OkAudit organizes its 36 skills across 9 specialist audit roles:

| Role | Skills | Key Capabilities |
|------|--------|-----------------|
|  **Lead IT Auditor** | Scope, Reporting, Orchestration | Audit scoping, risk prioritization, executive reporting |
| **Identity & Access** | Access Review, SoD Analysis, Privilege Audit | Over-privileged account detection, separation of duties analysis, MFA compliance |
|  **Compliance** | Policy Validation, Control Tracking, Gap Analysis | Framework control mapping, policy drift detection, remediation tracking |
|  **Log Monitoring** | Threat Detection, Anomaly Analysis, Audit Trail | Log ingestion, behavioral anomaly detection, incident reconstruction |
|  **Vendor Risk** | Risk Scoring, Third-Party Review, Contract Analysis | Vendor classification, risk scoring, SLA compliance checks |
|  **Network Security** | Firewall Review, Segmentation Audit, Exposure Analysis | Firewall rule analysis, network zone validation, open port enumeration |
|  **Privacy & Data** | Data Mapping, Consent Review, Retention Audit | PII identification, data flow mapping, consent chain validation |
|  **Hardware & Assets** | Asset Inventory, Configuration Baseline, EOL Detection | Asset discovery, baseline drift detection, end-of-life flagging |
|  **Application Security** | Code Review, Dependency Audit, Auth Analysis | SAST-aligned code review, CVE detection in dependencies, auth flow analysis |

---

## Quick Start

The fastest way to work with OkAudit Core is to clone the repository and execute a skill directly.

```bash
# Clone the repository
git clone https://github.com/maxwellokumu/OkAudit.git
cd OkAudit

# Set up the Python environment
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run an audit scope workflow
cd lead-it-auditor/audit-scope-checklist
python main.py \
  --system "AWS payment application" \
  --roles "iam,network" \
  --frameworks "PCI-DSS"

---

## Installation

### Prerequisites

- Python 3.8 or higher
- `pip` and `venv`
- AWS or Azure credentials only for cloud-connected skills

### Steps

```bash
# 1. Clone
git clone https://github.com/maxwellokumu/OkAudit.git
cd OkAudit

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Configure environment variables
cp .env.example .env
# Edit .env with your credentials

```

---

## Usage

### CLI Usage

Each skill lives in its own directory and exposes a `main.py` entry point. All skills follow a consistent invocation pattern:

```bash
python main.py [--input <file>] [--options <values>]
```

#### IAM Access Review

```bash
cd identity-access/access-review
python main.py --input iam_policy.json
```

**Sample output:**
```json
{
  "findings": [
    {
      "severity": "HIGH",
      "user": "svc-payments",
      "issue": "AdministratorAccess policy attached",
      "recommendation": "Restrict to least-privilege policy",
      "framework_ref": "PCI-DSS 7.1"
    }
  ],
  "summary": {
    "total_users": 42,
    "over_privileged": 7,
    "mfa_disabled": 3
  }
}
```

#### Log Analysis

```bash
cd log-monitoring/log-analyzer
python main.py --logs cloudtrail.json --frameworks "SOC2,ISO27001"
```

#### Audit Scope Definition

```bash
cd lead-it-auditor/audit-scope-checklist
python main.py \
  --system "Azure SaaS platform" \
  --roles "iam,appsec,vendor" \
  --frameworks "ISO27001,GDPR"
```

#### Vendor Risk Scoring

```bash
cd vendor-risk/risk-scoring
python main.py --vendor vendor_profile.json --tier critical
```

#### Network Firewall Review

```bash
cd network-security/firewall-review
python main.py --rules firewall_rules.json --segment "production"
```

---

### Claude Integration

OkAudit skills can be executed directly inside Claude using its code execution environment.

**Step 1:** Enable code execution in Claude settings.

**Step 2:** Upload the relevant skill folder (e.g., `identity-access/access-review/`) together with your evidence file.

**Step 3:** Use natural language to invoke the skill:

```
Analyze this IAM policy for over-privileged accounts and SoD violations.
Map findings to PCI-DSS controls.
```

Each skill includes a `skill.yaml` that declares its inputs, outputs, and Claude execution context. Claude reads this automatically when the folder is uploaded.

**Example prompts:**

```
Run an access review on the attached iam_policy.json and highlight
any accounts with AdministratorAccess.
```

```
Analyze these CloudTrail logs for anomalous activity and produce
a SOC2 CC6.1-aligned finding report.
```

```
Score this vendor profile against our third-party risk framework
and flag any critical gaps.
```

---

## Configuration

Each skill can be configured via its `config.yaml`. Common configuration options:

```yaml
# config.yaml (example — identity-access/access-review)
frameworks:
  - PCI-DSS
  - SOC2

thresholds:
  max_admin_accounts: 2
  mfa_required: true
  inactive_days_threshold: 90

output:
  format: json            # json | csv | markdown
  include_remediation: true
  severity_filter: medium # low | medium | high | critical
```

---

## Environment Variables

Copy `.env.example` to `.env` and populate the variables relevant to the skills you intend to run. Cloud credential variables are only required for skills that connect to live cloud environments.

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_ACCESS_KEY_ID` | Optional | AWS access key for cloud-connected skills |
| `AWS_SECRET_ACCESS_KEY` | Optional | AWS secret key |
| `AWS_DEFAULT_REGION` | Optional | Default AWS region (e.g., `us-east-1`) |
| `AZURE_CLIENT_ID` | Optional | Azure service principal client ID |
| `AZURE_CLIENT_SECRET` | Optional | Azure service principal secret |
| `AZURE_TENANT_ID` | Optional | Azure Active Directory tenant ID |
| `LOG_LEVEL` | Optional | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `INFO`) |
| `OUTPUT_DIR` | Optional | Directory for audit output files (default: `./output`) |

> **Security note:** Never commit `.env` to version control. The `.gitignore` in this repo excludes it by default.

---

## Testing

OkAudit includes a full test suite with coverage reporting.

```bash
# Run all tests
pytest tests/

# Run with HTML coverage report
pytest tests/ --cov=. --cov-report=html
open htmlcov/index.html

# Run tests for a specific skill domain
pytest tests/identity_access/ -v

# Run only unit tests (skip integration)
pytest tests/ -m "not integration"
```

### Test structure

```
tests/
├── unit/
│   ├── test_iam_review.py
│   ├── test_log_analyzer.py
│   ├── test_vendor_scoring.py
│   └── ...
├── integration/
│   ├── test_pipeline_execution.py
│   └── test_claude_skill_invocation.py
└── fixtures/
    ├── sample_iam_policy.json
    ├── sample_cloudtrail.json
    └── sample_vendor_profile.json
```

---

## Compliance Frameworks

OkAudit Core is built around practical workflows that can support framework-aware assurance work across:

| Framework | Scope | Example Controls |
|-----------|-------|-----------------|
| **SOC 2** | Trust service criteria | CC6.1, CC6.2, CC7.2, CC9.2 |
| **ISO 27001** | ISMS controls | A.9.2, A.12.4, A.14.2 |
| **PCI-DSS v4** | Payment card security | 7.1, 8.3, 10.2, 11.3 |
| **NIST CSF** | Cybersecurity framework | ID.AM, PR.AC, DE.CM, RS.AN |
| **GDPR** | Data protection | Art. 5, Art. 25, Art. 30, Art. 32 |

The focus is not just control naming, but reusable workflows that help practitioners test, interpret, and report on control effectiveness.

---

## Project Structure

```
OkAudit/
├── lead-it-auditor/
│   ├── audit-scope-checklist/
│   ├── risk-prioritization/
│   └── audit-reporting/
├── identity-access/
│   ├── access-review/
│   ├── sod-analysis/
│   └── privilege-audit/
├── compliance/
│   ├── policy-validation/
│   └── gap-analysis/
├── log-monitoring/
│   ├── log-analyzer/
│   └── anomaly-detection/
├── vendor-risk/
│   └── risk-scoring/
├── network-security/
│   ├── firewall-review/
│   └── segmentation-audit/
├── privacy-data/
│   ├── data-mapping/
│   └── consent-review/
├── hardware-assets/
│   └── asset-validation/
├── application-security/
│   └── dependency-audit/
├── tests/
├── assets/
├── requirements.txt
├── .env.example
├── CONTRIBUTING.md
└── README.md
```

---

## Roadmap

| Milestone | Status |
|-----------|--------|
| 36 core skills | Complete |
| Claude-ready packaging layer | Complete |
| CLI execution across domains | Complete |
| Expanded framework coverage | In progress |
| Jurisdiction-specific extensions | Planned |
| Additional assurance workflows | Planned |
| Broader integration surfaces | Planned |

Future expansion may include more regional and regulatory support, including jurisdiction-specific privacy and cyber governance workflows where practitioner demand justifies it.


---

## Contributing

Contributions are welcome from practitioners and builders who want to improve reusable audit workflows.

1. Fork the repository
2. Create a feature branch
3. Follow the existing skill structure
4. Ensure tests pass
5. Open a pull request with a clear description of the capability being added or improved

Please read `CONTRIBUTING.md` for code style, testing standards, and skill authoring guidance.


---

## Author

**Maxwell Okumu**

Open to IT Audit Consulting, AI Systems Design, and Security Automation engagements.

- Profile: https://maxwellokumu.github.io
- Email: omaxwell23@gmail.com

---

## License

MIT © Maxwell Okumu — see [LICENSE](LICENSE) for full terms.
