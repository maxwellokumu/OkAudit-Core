# evidence-tracker

Track the status of every audit evidence request from initial request through to
acceptance. Maintains a persistent JSON state file and produces markdown status
reports and final summaries.

---

## Requirements

```bash
pip install python-dotenv
```

---

## Usage

```bash
# 1. Initialise from an audit program
python main.py --program audit_program.json --init

# 2. List all items
python main.py --list

# 3. Filter by status
python main.py --list --filter-status "Requested"

# 4. Update an item
python main.py --update '{"id": "IAM-001", "status": "Received", "file": "iam_policy.pdf", "reviewer": "Jane"}'

# 5. Mark as accepted
python main.py --update '{"id": "IAM-001", "status": "Accepted", "notes": "Verified complete"}'

# 6. Export final summary
python main.py --export

# Use a custom tracker file location
python main.py --tracker-file ./audit-2025/tracker.json --list
```

---

## Status Workflow

```
Requested → In Progress → Received → Accepted
                                   → Rejected → In Progress
         → Not Applicable
```

Invalid transitions (e.g. Accepted → Requested) are blocked with an error.

---

## Valid Statuses

| Status | Meaning |
|--------|---------|
| 📋 Requested | Evidence has been requested from the auditee |
| 🔄 In Progress | Auditee is preparing/gathering the evidence |
| 📥 Received | Evidence received, pending auditor review |
| ✅ Accepted | Auditor has reviewed and accepted the evidence |
| ❌ Rejected | Evidence received but not acceptable — re-request needed |
| ⬜ Not Applicable | Control is not applicable to this audit scope |

---

## Sample Output (--list)

```markdown
# Evidence Tracker

**Total Items:** 15

## Status Summary
| Status | Count |
|--------|-------|
| ✅ Accepted | 7 |
| 📥 Received | 3 |
| 📋 Requested | 4 |
| ❌ Rejected | 1 |

## All Items
| ID | Control | Artefact | Status | File | Reviewer |
|----|---------|----------|--------|------|----------|
| `IAM-001` | User access inventory | `user_access_report.csv` | ✅ Accepted | user_access_report.csv | Jane |
```
