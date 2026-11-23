# SOC Log Analyzer

**A lightweight Python tool for first-level SOC triage of authentication logs.**

SOC Log Analyzer parses JSONL, JSON, and CSV events, groups failed logins by source IP and username, and highlights repeated failures and successful logins that follow a burst of failures.

## Why it matters
Authentication triage is a common first step during alert investigation. This project demonstrates log parsing, detection logic, severity assignment, structured reporting, and unit testing.

## Quick start
Requires Python 3.10+; no third-party packages.

```bash
cd projects/soc-log-analyzer
python soc_log_analyzer.py sample_auth.jsonl --threshold 5
python soc_log_analyzer.py sample_auth.jsonl --threshold 5 --json alerts.json
python -m unittest -v
```

Exit code is **1 when alerts are found** and **0 when no alerts are found**. This makes the tool suitable for simple automation.

## Detection rules
| Rule | Severity | Meaning |
|---|---|---|
| Repeated authentication failures | MEDIUM | Threshold reached for an IP/username pair |
| Success after repeated failures | HIGH | A successful login follows the configured number of failures |

## Input format
Each event should contain `timestamp`, `username` (or `user`), `source_ip` (or `ip`), `event`, and `result` (for example `failed` or `success`). CSV headers use the same field names.

## Limitations
This is a portfolio-grade learning project, not a production SIEM or proof of compromise. It currently uses a simple count threshold and does not correlate time windows, enrich IP reputation, or parse vendor-specific Windows/Linux formats. Validate every alert with surrounding telemetry.

## Safety
Use sanitized, synthetic, or authorized logs only. The included IP addresses are documentation-only ranges (RFC 5737).
