# access-review

Analyse IAM policies for excessive permissions, wildcard actions, admin-equivalent
privileges, missing conditions, and inline policy usage. Supports local file analysis,
live AWS IAM, and Azure role assignments.

---

## Purpose

- Flags `Action: "*"` and other wildcard patterns
- Detects admin-equivalent actions (`iam:*`, `s3:Delete*`, `ec2:Terminate*`, etc.)
- Identifies resource wildcards combined with write/delete actions
- Highlights sensitive actions granted without MFA or IP conditions
- Flags inline policies as higher-risk than managed policies

---

## Requirements

```bash
pip install python-dotenv boto3 msal
```

---

## Usage

```bash
# Local mode — analyse a JSON policy file
python main.py --input sample_input/iam_policy.json

# Local mode — pipe raw JSON string
python main.py --input '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'

# AWS mode — fetch live IAM policies
python main.py --mode aws

# AWS mode — dry run with sample data (no credentials needed)
python main.py --mode aws --dry-run

# Azure mode — fetch live role assignments
python main.py --mode azure

# Azure mode — dry run with sample data
python main.py --mode azure --dry-run
```

---

## Sample Output (truncated)

```markdown
# IAM Access Review Report

**Date:** 2025-07-01
**Mode:** local
**Policies Reviewed:** 3
**Total Findings:** 5

## Executive Summary

| Severity | Count |
|----------|-------|
| 🚨 Critical | 1 |
| 🔴 High | 2 |
| 🟠 Medium | 1 |
| 🟡 Low | 1 |

## Findings

| Policy Name | Issue | Severity | Recommendation |
|-------------|-------|----------|----------------|
| `AdminWildcardPolicy` | Wildcard action '*' grants unrestricted permissions | 🚨 Critical | Replace wildcard... |
```

---

## Input Format (Local Mode)

Accepts AWS IAM policy document format:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:*"],
      "Resource": "*"
    }
  ]
}
```

Or a list of wrapped policies:

```json
[
  {
    "PolicyName": "MyPolicy",
    "PolicyType": "managed",
    "Document": { "Version": "2012-10-17", "Statement": [...] }
  }
]
```

---

## Environment Variables (Cloud Modes)

See `.env.example` in the repo root. AWS mode uses `AWS_*` vars; Azure mode uses `AZURE_*` vars.
