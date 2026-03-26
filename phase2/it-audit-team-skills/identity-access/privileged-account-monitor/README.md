# privileged-account-monitor

Review privileged account activity logs for anomalies including baseline exceedances,
off-hours access, sensitive actions, and new unknown users. Supports local CSV/JSON
logs and live AWS CloudTrail.

---

## Requirements

```bash
pip install python-dotenv boto3
```

---

## Usage

```bash
# Local mode — CSV logs
python main.py --logs sample_input/privileged_logs.csv

# Local mode — custom baseline and hours
python main.py \
  --logs sample_input/privileged_logs.csv \
  --baseline 50 \
  --hours "08:00-18:00"

# AWS mode — live CloudTrail (past 7 days)
python main.py --mode aws

# AWS mode — dry run
python main.py --mode aws --dry-run
```

---

## Log Format (CSV)

```csv
timestamp,user,action,source_ip,resource
2025-07-01T08:15:00,alice,ListBuckets,10.0.0.1,s3
2025-07-01T02:30:00,svc-deploy,TerminateInstances,10.0.0.50,ec2
```

---

## Sensitive Actions Flagged

`DeleteBucket`, `PutBucketPolicy`, `DeleteTrail`, `StopLogging`, `CreateUser`,
`DeleteUser`, `AttachUserPolicy`, `PutUserPolicy`, `CreateAccessKey`,
`DeleteAccessKey`, `UpdateLoginProfile`, `TerminateInstances`, `DeleteVpc`,
`PassRole`, `ConsoleLoginFailure`, and more.

---

## Sample Output (truncated)

```markdown
# Privileged Account Monitor Report

**Baseline Threshold:** 100 actions/day
**Business Hours:** 07:00-19:00
**Total Events Analysed:** 21

## User Activity Summary

| User | Total Actions | Days Active | Max/Day | Off-Hours | Sensitive | Flags |
|------|--------------|-------------|---------|-----------|-----------|-------|
| `svc-deploy` | 4 | 2 | 2 | 3 | 3 | 🌙 Off-Hours 🔴 Sensitive |
| `root` | 5 | 1 | 5 | 0 | 2 | 🔴 Sensitive 🆕 New User |
```
