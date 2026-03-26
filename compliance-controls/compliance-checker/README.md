# compliance-checker

Compare a system configuration JSON file against hardcoded control libraries for
CIS, SOC2, ISO 27001, and PCI-DSS. Produces a pass/fail report with remediation
guidance for every failed control.

---

## Purpose

- Evaluates configuration keys against expected values using operators (eq, gte, lte)
- Supports 4 standards with 10–12 controls each
- Flags N/A for controls where the config key is absent
- Provides per-control remediation guidance

---

## Requirements

```bash
pip install python-dotenv
```

---

## Usage

```bash
# Check against CIS benchmark
python main.py --config sample_input/config_cis.json --standard cis

# Check against SOC2
python main.py --config sample_input/config.json --standard soc2

# Check against ISO 27001
python main.py --config sample_input/config.json --standard iso27001

# Check against PCI-DSS
python main.py --config sample_input/config.json --standard pci-dss
```

---

## Config File Format

A flat JSON object with configuration keys matching the control library:

```json
{
  "password_min_length": 12,
  "mfa_enabled": true,
  "audit_logging_enabled": true,
  "encryption_at_rest": false,
  "patch_cycle_days": 45
}
```

---

## Sample Output (truncated)

```markdown
# Compliance Check Report — CIS

**Pass Rate:** 75.0% (9/12 scored controls)

## Control Results

| Control ID | Description | Expected | Actual | Status | Remediation |
|------------|-------------|----------|--------|--------|-------------|
| CIS-1.1 | Password minimum length >= 14 | 14 | 12 | ❌ Fail | Set minimum... |
| CIS-1.3 | Audit logging enabled | True | True | ✅ Pass | — |
```
