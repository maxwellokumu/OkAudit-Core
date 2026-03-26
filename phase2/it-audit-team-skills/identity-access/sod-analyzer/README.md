# sod-analyzer

Detect segregation of duties (SOD) conflicts in user role assignments. Checks every
user's roles against a library of known conflicting pairs and reports violations with
risk ratings and remediation guidance.

---

## Purpose

SOD violations occur when one person can perform two conflicting functions — such as
initiating and approving a payment, or creating and deleting users. This skill:

- Checks user roles against 20 built-in common SOD conflict pairs
- Supports custom conflict rules via JSON
- Rates each conflict as Critical, High, or Medium
- Provides remediation guidance per conflict
- Lists clean users for management sign-off

---

## Requirements

```bash
pip install python-dotenv
```

---

## Usage

```bash
# Use built-in conflict library only
python main.py \
  --users sample_input/users.json \
  --builtin-conflicts

# Use custom conflict rules only
python main.py \
  --users sample_input/users.json \
  --conflicts sample_input/conflicts.json

# Use both built-in and custom rules
python main.py \
  --users sample_input/users.json \
  --conflicts sample_input/conflicts.json \
  --builtin-conflicts
```

---

## Input Format

**users.json**
```json
{
  "alice": ["approve_payment", "create_invoice"],
  "bob": ["developer", "read_audit_logs"],
  "carol": ["deploy_code", "approve_deployment"]
}
```

**conflicts.json** (custom pairs)
```json
[
  ["role_a", "role_b", "High", "Custom rationale here"],
  {"role_a": "write_report", "role_b": "approve_report", "risk": "Medium", "category": "Governance"}
]
```

---

## Sample Output (truncated)

```markdown
# Segregation of Duties Analysis Report

**Date:** 2025-07-01
**Built-in Conflicts Used:** Yes
**Custom Conflict Rules:** 0

## Summary

| Metric | Value |
|--------|-------|
| Users Reviewed | 10 |
| Users with Conflicts | 3 |
| Total Conflicts Found | 4 |

## Conflicts Detected

| User | Role A | Role B | Risk | Remediation |
|------|--------|--------|------|-------------|
| `carol` | `deploy_code` | `approve_deployment` | 🚨 Critical | Remove 'approve_deployment'... |
```
