#!/usr/bin/env python3
"""SOC Log Analyzer: defensive authentication-log triage using Python stdlib."""
from __future__ import annotations
import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

def load_events(path: Path):
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".jsonl":
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    elif path.suffix.lower() == ".json":
        data = json.loads(text)
        rows = data if isinstance(data, list) else data.get("events", [])
    else:
        rows = list(csv.DictReader(text.splitlines()))
    events = []
    for row in rows:
        events.append({
            "timestamp": str(row.get("timestamp", "")),
            "username": str(row.get("username", row.get("user", "unknown"))),
            "source_ip": str(row.get("source_ip", row.get("src_ip", row.get("ip", "unknown")))),
            "event": str(row.get("event", row.get("action", "login"))).lower(),
            "result": str(row.get("result", row.get("status", "unknown"))).lower(),
        })
    return events

def analyze(events, threshold=5):
    failures = defaultdict(list)
    alerts = []
    for event in events:
        failed = event["result"] in {"failed", "failure", "denied", "invalid"}
        success = event["result"] in {"success", "successful", "accepted"}
        key = (event["source_ip"], event["username"])
        if failed:
            failures[key].append(event["timestamp"])
        elif success and len(failures[key]) >= threshold:
            alerts.append({
                "severity": "HIGH",
                "type": "SUCCESS_AFTER_REPEATED_FAILURES",
                "source_ip": key[0], "username": key[1],
                "failed_attempts": len(failures[key]),
                "timestamp": event["timestamp"],
                "description": "Successful authentication followed repeated failures; investigate possible account compromise."
            })
    for (ip, user), timestamps in failures.items():
        if len(timestamps) >= threshold:
            alerts.append({
                "severity": "MEDIUM",
                "type": "REPEATED_AUTH_FAILURES",
                "source_ip": ip, "username": user,
                "failed_attempts": len(timestamps),
                "timestamp": timestamps[-1],
                "description": "Repeated failed authentication attempts; validate whether activity is expected."
            })
    return sorted(alerts, key=lambda a: (a["severity"] != "HIGH", -a["failed_attempts"]))

def main():
    parser = argparse.ArgumentParser(description="Analyze authentication events for defensive SOC triage.")
    parser.add_argument("input", type=Path, help="JSONL, JSON, or CSV event file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed attempts per IP/user before alerting (default: 5)")
    parser.add_argument("--json", dest="output", type=Path, help="Optional path to save JSON alerts")
    args = parser.parse_args()
    if args.threshold < 2:
        parser.error("--threshold must be at least 2")
    try:
        events = load_events(args.input)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(f"could not read input: {exc}")
    alerts = analyze(events, args.threshold)
    result = {"events_analyzed": len(events), "alerts_found": len(alerts), "alerts": alerts}
    print(json.dumps(result, indent=2))
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 1 if alerts else 0

if __name__ == "__main__":
    raise SystemExit(main())
