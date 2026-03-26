"""Evidence Tracker — track audit evidence requests and collection status.

Maintains a persistent JSON state file (evidence_tracker.json) tracking the
status of every artefact in an audit program. Supports initialisation from an
audit program JSON, status updates with transition validation, listing, filtering,
and exporting a final evidence summary.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRACKER_FILE = "evidence_tracker.json"

VALID_STATUSES = [
    "Requested",
    "In Progress",
    "Received",
    "Accepted",
    "Rejected",
    "Not Applicable",
]

# Allowed forward transitions (terminal states cannot go back to Requested)
ALLOWED_TRANSITIONS: Dict[str, List[str]] = {
    "Requested": ["In Progress", "Received", "Not Applicable"],
    "In Progress": ["Received", "Not Applicable", "Requested"],
    "Received": ["Accepted", "Rejected", "In Progress"],
    "Accepted": ["Rejected"],  # Only downgrade allowed from Accepted
    "Rejected": ["In Progress", "Received"],
    "Not Applicable": ["Requested"],
}

STATUS_EMOJI = {
    "Requested": "📋",
    "In Progress": "🔄",
    "Received": "📥",
    "Accepted": "✅",
    "Rejected": "❌",
    "Not Applicable": "⬜",
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Track audit evidence requests and collection status."
    )
    parser.add_argument(
        "--program",
        help="Path to audit_program.json (required for --init)",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialise tracker from audit program JSON",
    )
    parser.add_argument(
        "--update",
        help='JSON string: {"id": "IAM-001", "status": "Received", "file": "...", "notes": "...", "reviewer": "..."}',
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all evidence items and their status",
    )
    parser.add_argument(
        "--filter-status",
        help="Filter --list output by status (e.g. 'Missing', 'Received')",
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Export final evidence summary to evidence_summary.md",
    )
    parser.add_argument(
        "--tracker-file",
        default=TRACKER_FILE,
        help=f"Path to tracker state file (default: {TRACKER_FILE})",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------


def load_tracker(path: str) -> Dict[str, Any]:
    """Load tracker state from JSON file.

    Args:
        path: Path to tracker JSON file.

    Returns:
        Tracker state dict, or empty state if file doesn't exist.
    """
    if not os.path.exists(path):
        return {"items": {}, "created": datetime.now().isoformat(), "program": None}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Tracker file is corrupted — {exc}", file=sys.stderr)
        sys.exit(1)


def save_tracker(state: Dict[str, Any], path: str) -> None:
    """Save tracker state to JSON file.

    Args:
        state: Tracker state dict.
        path: Output path.
    """
    state["last_updated"] = datetime.now().isoformat()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_init(program_path: str, tracker_path: str) -> None:
    """Initialise tracker from audit program JSON.

    Args:
        program_path: Path to audit_program.json.
        tracker_path: Path to write tracker state.
    """
    try:
        with open(program_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"ERROR: Audit program file not found: '{program_path}'", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in audit program — {exc}", file=sys.stderr)
        sys.exit(1)

    # Support both {"controls": [...]} and raw array
    controls = data.get("controls", data) if isinstance(data, dict) else data
    if not isinstance(controls, list):
        print("ERROR: Audit program must contain a list of controls.", file=sys.stderr)
        sys.exit(1)

    if os.path.exists(tracker_path):
        print(
            f"WARNING: Tracker file '{tracker_path}' already exists. "
            "Use --update to modify existing items. "
            "Delete the file manually to re-initialise.",
            file=sys.stderr,
        )
        sys.exit(1)

    items: Dict[str, Any] = {}
    for ctrl in controls:
        cid = ctrl.get("id", "")
        if not cid:
            continue
        items[cid] = {
            "id": cid,
            "control": ctrl.get("control", ""),
            "artefact": ctrl.get("artefact", ""),
            "role": ctrl.get("role", ""),
            "details": ctrl.get("details", ""),
            "acceptance": ctrl.get("acceptance", ""),
            "status": "Requested",
            "file": "",
            "notes": "",
            "reviewer": "",
            "updated": datetime.now().isoformat(),
        }

    state = {
        "items": items,
        "created": datetime.now().isoformat(),
        "program": program_path,
    }
    save_tracker(state, tracker_path)
    print(f"✅ Tracker initialised with {len(items)} items from '{program_path}'.")
    print(f"   State saved to: {tracker_path}")


def cmd_update(update_json: str, tracker_path: str) -> None:
    """Update a single evidence item's status.

    Args:
        update_json: JSON string with update fields.
        tracker_path: Path to tracker state file.
    """
    try:
        update = json.loads(update_json)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in --update argument — {exc}", file=sys.stderr)
        sys.exit(1)

    item_id = update.get("id", "").strip()
    if not item_id:
        print("ERROR: --update JSON must include an 'id' field.", file=sys.stderr)
        sys.exit(1)

    new_status = update.get("status", "").strip()
    if new_status and new_status not in VALID_STATUSES:
        print(
            f"ERROR: Invalid status '{new_status}'. "
            f"Valid statuses: {', '.join(VALID_STATUSES)}",
            file=sys.stderr,
        )
        sys.exit(1)

    state = load_tracker(tracker_path)
    items = state.get("items", {})

    if item_id not in items:
        print(f"ERROR: Item ID '{item_id}' not found in tracker.", file=sys.stderr)
        print(f"       Available IDs: {', '.join(list(items.keys())[:10])}", file=sys.stderr)
        sys.exit(1)

    item = items[item_id]
    current_status = item["status"]

    # Validate status transition
    if new_status and new_status != current_status:
        allowed = ALLOWED_TRANSITIONS.get(current_status, [])
        if new_status not in allowed:
            print(
                f"ERROR: Invalid status transition '{current_status}' → '{new_status}'. "
                f"Allowed transitions from '{current_status}': {', '.join(allowed)}",
                file=sys.stderr,
            )
            sys.exit(1)
        item["status"] = new_status

    # Apply other fields
    for field in ("file", "notes", "reviewer"):
        if field in update and update[field]:
            item[field] = update[field]

    item["updated"] = datetime.now().isoformat()
    save_tracker(state, tracker_path)
    print(f"✅ Updated item '{item_id}': status={item['status']}, file='{item['file']}'")


def cmd_list(tracker_path: str, filter_status: Optional[str]) -> None:
    """Print evidence items as a markdown table.

    Args:
        tracker_path: Path to tracker state file.
        filter_status: Optional status to filter by.
    """
    state = load_tracker(tracker_path)
    items = list(state.get("items", {}).values())

    if not items:
        print("No items in tracker. Run --init first.")
        return

    if filter_status:
        items = [i for i in items if i["status"].lower() == filter_status.lower()]
        if not items:
            print(f"No items with status '{filter_status}'.")
            return

    # Counts
    counts: Dict[str, int] = {}
    for i in list(state.get("items", {}).values()):
        counts[i["status"]] = counts.get(i["status"], 0) + 1

    lines: List[str] = []
    lines.append("# Evidence Tracker\n")
    lines.append(f"**Program:** {state.get('program', 'unknown')}  ")
    lines.append(f"**Last Updated:** {state.get('last_updated', 'never')}  ")
    lines.append(f"**Total Items:** {len(state.get('items', {}))}\n")

    lines.append("## Status Summary\n")
    lines.append("| Status | Count |")
    lines.append("|--------|-------|")
    for s in VALID_STATUSES:
        emoji = STATUS_EMOJI.get(s, "")
        lines.append(f"| {emoji} {s} | {counts.get(s, 0)} |")
    lines.append("")

    if filter_status:
        lines.append(f"## Items — Status: {filter_status}\n")
    else:
        lines.append("## All Items\n")

    lines.append("| ID | Control | Artefact | Status | File | Reviewer | Updated |")
    lines.append("|----|---------|----------|--------|------|----------|---------|")

    for item in sorted(items, key=lambda x: x["id"]):
        emoji = STATUS_EMOJI.get(item["status"], "")
        lines.append(
            f"| `{item['id']}` | {item['control']} | `{item['artefact']}` | "
            f"{emoji} {item['status']} | {item['file'] or '—'} | "
            f"{item['reviewer'] or '—'} | {item['updated'][:10]} |"
        )

    print("\n".join(lines))


def cmd_export(tracker_path: str) -> None:
    """Export final evidence summary to evidence_summary.md.

    Args:
        tracker_path: Path to tracker state file.
    """
    state = load_tracker(tracker_path)
    items = list(state.get("items", {}).values())

    if not items:
        print("No items in tracker. Run --init first.")
        return

    lines: List[str] = []
    lines.append("# Evidence Collection Summary\n")
    lines.append(f"**Program:** {state.get('program', 'unknown')}  ")
    lines.append(f"**Export Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ")
    accepted = sum(1 for i in items if i["status"] == "Accepted")
    lines.append(f"**Accepted / Total:** {accepted} / {len(items)}\n")
    lines.append("---\n")

    for status in VALID_STATUSES:
        group = [i for i in items if i["status"] == status]
        if not group:
            continue
        emoji = STATUS_EMOJI.get(status, "")
        lines.append(f"## {emoji} {status} ({len(group)} items)\n")
        lines.append("| ID | Control | Artefact | File | Notes | Reviewer |")
        lines.append("|----|---------|----------|------|-------|----------|")
        for item in sorted(group, key=lambda x: x["id"]):
            lines.append(
                f"| `{item['id']}` | {item['control']} | `{item['artefact']}` | "
                f"{item['file'] or '—'} | {item['notes'] or '—'} | {item['reviewer'] or '—'} |"
            )
        lines.append("")

    output = "\n".join(lines)
    with open("evidence_summary.md", "w", encoding="utf-8") as fh:
        fh.write(output)

    print("✅ Evidence summary exported to: evidence_summary.md")
    print(output)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point."""
    args = parse_args()

    if args.init:
        if not args.program:
            print("ERROR: --program is required with --init.", file=sys.stderr)
            sys.exit(1)
        cmd_init(args.program, args.tracker_file)

    elif args.update:
        cmd_update(args.update, args.tracker_file)

    elif args.list:
        cmd_list(args.tracker_file, args.filter_status)

    elif args.export:
        cmd_export(args.tracker_file)

    else:
        print(
            "ERROR: Specify one of --init, --update, --list, or --export.",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
