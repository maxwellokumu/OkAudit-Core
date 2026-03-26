"""Privileged Account Monitor — review privileged account activity logs for anomalies.

Analyses CloudTrail-format logs (CSV or JSON) for baseline exceedances,
off-hours access, sensitive actions, and new/unknown users. Supports local
file analysis and live AWS CloudTrail via boto3.
"""

import argparse
import csv
import io
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SENSITIVE_ACTIONS = {
    "DeleteBucket", "PutBucketPolicy", "DeleteTrail", "StopLogging",
    "CreateUser", "DeleteUser", "AttachUserPolicy", "PutUserPolicy",
    "DeleteRolePolicy", "PassRole", "AssumeRoleWithWebIdentity",
    "PutBucketAcl", "DeleteObject", "TerminateInstances", "DeleteVpc",
    "ModifyInstanceAttribute", "CreateAccessKey", "DeleteAccessKey",
    "UpdateLoginProfile", "ConsoleLoginFailure", "PutBucketPublicAccessBlock",
    "DeleteSecurityGroup", "AuthorizeSecurityGroupIngress",
}

# ---------------------------------------------------------------------------
# Sample data for --dry-run
# ---------------------------------------------------------------------------

SAMPLE_LOGS_CSV = """timestamp,user,action,source_ip,resource
2025-07-01T08:15:00,alice,ListBuckets,10.0.0.1,s3
2025-07-01T08:20:00,alice,GetObject,10.0.0.1,s3:::prod-bucket
2025-07-01T09:00:00,bob,CreateUser,203.0.113.5,iam
2025-07-01T09:05:00,bob,AttachUserPolicy,203.0.113.5,iam
2025-07-01T09:10:00,bob,CreateAccessKey,203.0.113.5,iam
2025-07-01T02:30:00,svc-deploy,TerminateInstances,10.0.0.50,ec2
2025-07-01T02:35:00,svc-deploy,DeleteBucket,10.0.0.50,s3:::old-logs
2025-07-01T02:40:00,svc-deploy,DeleteTrail,10.0.0.50,cloudtrail
2025-07-01T10:00:00,carol,DescribeInstances,10.0.0.2,ec2
2025-07-01T10:05:00,carol,ListUsers,10.0.0.2,iam
2025-07-01T11:00:00,root,ConsoleLoginFailure,198.51.100.10,console
2025-07-01T11:01:00,root,ConsoleLoginFailure,198.51.100.10,console
2025-07-01T11:02:00,root,ConsoleLoginFailure,198.51.100.10,console
2025-07-01T11:03:00,root,ConsoleLogin,198.51.100.10,console
2025-07-01T11:05:00,root,DeleteBucket,198.51.100.10,s3:::backup-2024
2025-07-02T03:00:00,svc-deploy,PutBucketPolicy,10.0.0.50,s3:::prod-bucket
2025-07-02T07:55:00,alice,GetObject,10.0.0.1,s3:::prod-bucket
2025-07-02T08:00:00,alice,PutObject,10.0.0.1,s3:::prod-bucket
2025-07-02T09:30:00,new_admin,CreateUser,45.33.32.156,iam
2025-07-02T09:31:00,new_admin,AttachUserPolicy,45.33.32.156,iam
2025-07-02T09:32:00,new_admin,PutBucketAcl,45.33.32.156,s3:::public-data
"""


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Monitor privileged account activity for anomalies and policy violations."
    )
    parser.add_argument(
        "--logs",
        help="Path to CSV or JSON log file (required for local mode)",
    )
    parser.add_argument(
        "--baseline",
        type=int,
        default=100,
        help="Maximum actions per day before flagging a user (default: 100)",
    )
    parser.add_argument(
        "--hours",
        default="07:00-19:00",
        help="Business hours window HH:MM-HH:MM (default: 07:00-19:00)",
    )
    parser.add_argument(
        "--mode",
        choices=["local", "aws"],
        default="local",
        help="Execution mode (default: local)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use bundled sample data instead of live API calls",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


def parse_business_hours(hours_str: str) -> Tuple[int, int, int, int]:
    """Parse HH:MM-HH:MM into (start_h, start_m, end_h, end_m).

    Args:
        hours_str: String like '07:00-19:00'.

    Returns:
        Tuple of (start_hour, start_min, end_hour, end_min).
    """
    try:
        start_str, end_str = hours_str.split("-")
        sh, sm = map(int, start_str.split(":"))
        eh, em = map(int, end_str.split(":"))
        return sh, sm, eh, em
    except (ValueError, AttributeError):
        print(f"ERROR: Invalid --hours format '{hours_str}'. Use HH:MM-HH:MM.", file=sys.stderr)
        sys.exit(1)


def is_off_hours(ts: datetime, sh: int, sm: int, eh: int, em: int) -> bool:
    """Return True if timestamp is outside business hours.

    Args:
        ts: Event datetime.
        sh/sm: Business start hour/minute.
        eh/em: Business end hour/minute.

    Returns:
        True if outside business hours.
    """
    start = ts.replace(hour=sh, minute=sm, second=0, microsecond=0)
    end = ts.replace(hour=eh, minute=em, second=0, microsecond=0)
    return ts < start or ts > end


# ---------------------------------------------------------------------------
# Log loading
# ---------------------------------------------------------------------------


def parse_events(raw: str) -> List[Dict[str, Any]]:
    """Parse CSV or JSON-lines log content into event dicts.

    Args:
        raw: Raw file content string.

    Returns:
        List of event dicts with keys: timestamp, user, action, source_ip, resource.
    """
    raw = raw.strip()
    if not raw:
        return []

    events: List[Dict[str, Any]] = []

    # Try JSON-lines first
    if raw.startswith("{") or raw.startswith("["):
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
        # Try JSON-lines
        for line in raw.splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        if events:
            return events

    # Fall back to CSV
    reader = csv.DictReader(io.StringIO(raw))
    for row in reader:
        events.append(dict(row))
    return events


def load_logs(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Load log events from file or AWS CloudTrail.

    Args:
        args: Parsed CLI arguments.

    Returns:
        List of event dicts.
    """
    if args.mode == "aws":
        return load_cloudtrail(args.dry_run)

    if args.dry_run:
        print("INFO: --dry-run enabled — using sample log data.\n", file=sys.stderr)
        return parse_events(SAMPLE_LOGS_CSV)

    if not args.logs:
        print("ERROR: --logs is required for local mode.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.logs, "r", encoding="utf-8") as fh:
            return parse_events(fh.read())
    except FileNotFoundError:
        print(f"ERROR: Log file not found: '{args.logs}'", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"ERROR: Cannot read log file — {exc}", file=sys.stderr)
        sys.exit(1)


def load_cloudtrail(dry_run: bool) -> List[Dict[str, Any]]:
    """Fetch CloudTrail events from AWS for the past 7 days.

    Args:
        dry_run: If True, return sample data.

    Returns:
        List of event dicts.
    """
    if dry_run:
        print("INFO: --dry-run enabled — using sample CloudTrail data.\n", file=sys.stderr)
        return parse_events(SAMPLE_LOGS_CSV)

    try:
        import boto3  # type: ignore
    except ImportError:
        print("ERROR: boto3 is not installed. Run: pip install boto3", file=sys.stderr)
        sys.exit(1)

    try:
        ct = boto3.client("cloudtrail")
        end = datetime.utcnow()
        start = end - timedelta(days=7)
        events: List[Dict[str, Any]] = []
        paginator = ct.get_paginator("lookup_events")
        for page in paginator.paginate(StartTime=start, EndTime=end):
            for e in page["Events"]:
                raw = json.loads(e.get("CloudTrailEvent", "{}"))
                events.append({
                    "timestamp": e.get("EventTime", "").isoformat()
                    if hasattr(e.get("EventTime", ""), "isoformat")
                    else str(e.get("EventTime", "")),
                    "user": (
                        raw.get("userIdentity", {}).get("userName")
                        or raw.get("userIdentity", {}).get("type", "unknown")
                    ),
                    "action": e.get("EventName", ""),
                    "source_ip": raw.get("sourceIPAddress", ""),
                    "resource": e.get("Resources", [{}])[0].get("ResourceName", "") if e.get("Resources") else "",
                })
        return events
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: AWS CloudTrail API call failed — {exc}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def analyse_events(
    events: List[Dict[str, Any]],
    baseline: int,
    sh: int, sm: int, eh: int, em: int,
) -> Dict[str, Any]:
    """Analyse events for anomalies.

    Args:
        events: List of event dicts.
        baseline: Max actions per day threshold.
        sh/sm/eh/em: Business hours bounds.

    Returns:
        Analysis results dict.
    """
    user_daily: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    off_hours_events: List[Dict] = []
    sensitive_events: List[Dict] = []
    known_users: set = set()
    all_users: set = set()
    flagged_new_users: List[str] = []

    for evt in events:
        raw_ts = evt.get("timestamp", "") or evt.get("EventTime", "")
        user = evt.get("user", "") or evt.get("Username", "unknown")
        action = evt.get("action", "") or evt.get("EventName", "")
        source_ip = evt.get("source_ip", "") or evt.get("SourceIPAddress", "")
        resource = evt.get("resource", "")

        # Parse timestamp
        ts: Optional[datetime] = None
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                ts = datetime.strptime(raw_ts[:19], fmt)
                break
            except (ValueError, TypeError):
                pass

        if not ts:
            continue

        day_key = ts.strftime("%Y-%m-%d")
        user_daily[user][day_key] += 1
        all_users.add(user)

        # Off-hours check
        if is_off_hours(ts, sh, sm, eh, em):
            off_hours_events.append({
                "timestamp": raw_ts,
                "user": user,
                "action": action,
                "source_ip": source_ip,
                "resource": resource,
            })

        # Sensitive action check
        if action in SENSITIVE_ACTIONS:
            sensitive_events.append({
                "timestamp": raw_ts,
                "user": user,
                "action": action,
                "source_ip": source_ip,
                "resource": resource,
            })

    # Identify new users (first 20% are considered "known baseline users" heuristic)
    # In practice: any user not seen in first day of logs is flagged as new
    if events:
        first_ts_str = events[0].get("timestamp", "")
        first_ts: Optional[datetime] = None
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                first_ts = datetime.strptime(first_ts_str[:19], fmt)
                break
            except (ValueError, TypeError):
                pass

        if first_ts:
            first_day = first_ts.strftime("%Y-%m-%d")
            for evt in events:
                raw_ts2 = evt.get("timestamp", "")
                user2 = evt.get("user", "unknown")
                ts2: Optional[datetime] = None
                for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                    try:
                        ts2 = datetime.strptime(raw_ts2[:19], fmt)
                        break
                    except (ValueError, TypeError):
                        pass
                if ts2 and ts2.strftime("%Y-%m-%d") == first_day:
                    known_users.add(user2)

            for u in all_users:
                if u not in known_users:
                    flagged_new_users.append(u)

    # Per-user summary
    user_summary: List[Dict] = []
    for user, daily_counts in sorted(user_daily.items()):
        total = sum(daily_counts.values())
        days_active = len(daily_counts)
        max_day = max(daily_counts.values())
        off_count = sum(1 for e in off_hours_events if e["user"] == user)
        sens_count = sum(1 for e in sensitive_events if e["user"] == user)
        exceeds = max_day > baseline
        user_summary.append({
            "user": user,
            "total_actions": total,
            "days_active": days_active,
            "max_per_day": max_day,
            "off_hours_count": off_count,
            "sensitive_count": sens_count,
            "exceeds_baseline": exceeds,
            "is_new": user in flagged_new_users,
        })

    return {
        "user_summary": user_summary,
        "off_hours_events": sorted(off_hours_events, key=lambda x: x["timestamp"]),
        "sensitive_events": sorted(sensitive_events, key=lambda x: x["timestamp"]),
        "new_users": flagged_new_users,
        "total_events": len(events),
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def render_report(results: Dict[str, Any], baseline: int, hours_str: str) -> str:
    """Render the markdown privileged account monitor report.

    Args:
        results: Analysis results dict.
        baseline: Baseline threshold used.
        hours_str: Business hours string.

    Returns:
        Markdown string.
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    lines: List[str] = []

    lines.append("# Privileged Account Monitor Report\n")
    lines.append(f"**Date:** {date_str}  ")
    lines.append(f"**Baseline Threshold:** {baseline} actions/day  ")
    lines.append(f"**Business Hours:** {hours_str}  ")
    lines.append(f"**Total Events Analysed:** {results['total_events']}\n")
    lines.append("---\n")

    # User summary table
    lines.append("## User Activity Summary\n")
    lines.append("| User | Total Actions | Days Active | Max/Day | Off-Hours | Sensitive | Flags |")
    lines.append("|------|--------------|-------------|---------|-----------|-----------|-------|")

    for u in sorted(results["user_summary"], key=lambda x: x["total_actions"], reverse=True):
        flags = []
        if u["exceeds_baseline"]:
            flags.append("⚠️ Baseline")
        if u["off_hours_count"] > 0:
            flags.append("🌙 Off-Hours")
        if u["sensitive_count"] > 0:
            flags.append("🔴 Sensitive")
        if u["is_new"]:
            flags.append("🆕 New User")
        flag_str = " ".join(flags) if flags else "✅ Clean"
        lines.append(
            f"| `{u['user']}` | {u['total_actions']} | {u['days_active']} | "
            f"{u['max_per_day']} | {u['off_hours_count']} | {u['sensitive_count']} | {flag_str} |"
        )

    lines.append("")
    lines.append("---\n")

    # Outliers
    outliers = [u for u in results["user_summary"] if u["exceeds_baseline"] or u["is_new"]]
    if outliers:
        lines.append("## ⚠️ Outliers\n")
        for u in outliers:
            lines.append(f"### `{u['user']}`")
            if u["exceeds_baseline"]:
                lines.append(
                    f"- **Baseline exceeded:** {u['max_per_day']} actions/day "
                    f"(threshold: {baseline})"
                )
            if u["is_new"]:
                lines.append("- **New user:** Not seen in baseline period — verify identity and authorisation")
            lines.append("")

    # Off-hours events
    if results["off_hours_events"]:
        lines.append("---\n")
        lines.append("## 🌙 Off-Hours Activity\n")
        lines.append("| Timestamp | User | Action | Source IP | Resource |")
        lines.append("|-----------|------|--------|-----------|----------|")
        for e in results["off_hours_events"]:
            lines.append(
                f"| {e['timestamp']} | `{e['user']}` | `{e['action']}` | "
                f"{e['source_ip']} | {e['resource']} |"
            )
        lines.append("")

    # Sensitive events
    if results["sensitive_events"]:
        lines.append("---\n")
        lines.append("## 🔴 Sensitive Action Timeline\n")
        lines.append("| Timestamp | User | Action | Source IP | Resource |")
        lines.append("|-----------|------|--------|-----------|----------|")
        for e in results["sensitive_events"]:
            lines.append(
                f"| {e['timestamp']} | `{e['user']}` | `{e['action']}` | "
                f"{e['source_ip']} | {e['resource']} |"
            )
        lines.append("")

    # New users
    if results["new_users"]:
        lines.append("---\n")
        lines.append("## 🆕 New / Unknown Users\n")
        lines.append("These users were not seen in the baseline period. Verify authorisation.\n")
        for u in results["new_users"]:
            lines.append(f"- `{u}`")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point."""
    args = parse_args()
    sh, sm, eh, em = parse_business_hours(args.hours)
    events = load_logs(args)

    if not events:
        print("ERROR: No log events found.", file=sys.stderr)
        sys.exit(1)

    results = analyse_events(events, args.baseline, sh, sm, eh, em)
    print(render_report(results, args.baseline, args.hours))


if __name__ == "__main__":
    main()
