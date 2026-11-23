#!/usr/bin/env python3
"""Linux Posture Audit: read-only baseline checks for a Linux host."""
from __future__ import annotations
import argparse
import json
import os
import platform
import re
import stat
import subprocess
from pathlib import Path

def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return None

def command_output(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)
        return (result.stdout + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired):
        return None

def add(items, check, severity, status, detail, recommendation):
    items.append({"check": check, "severity": severity, "status": status,
                  "detail": detail, "recommendation": recommendation})

def audit():
    findings = []
    if platform.system() != "Linux":
        add(findings, "Linux host", "INFO", "SKIPPED",
            f"Detected {platform.system()}; Linux-specific checks were not run.",
            "Run this assessment on a Linux host or VM.")
        return findings

    ssh = read_text("/etc/ssh/sshd_config")
    if ssh is None:
        add(findings, "SSH daemon configuration", "INFO", "UNKNOWN",
            "Could not read /etc/ssh/sshd_config.",
            "Review SSH configuration manually with appropriate permissions.")
    else:
        settings = {}
        for line in ssh.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                match = re.match(r"(?i)^(PermitRootLogin|PasswordAuthentication)\s+(\S+)", line)
                if match:
                    settings[match.group(1).lower()] = match.group(2).lower()
        root = settings.get("permitrootlogin", "default")
        if root in {"yes", "without-password", "prohibit-password"}:
            sev = "HIGH" if root == "yes" else "MEDIUM"
            add(findings, "SSH root login", sev, "REVIEW",
                f"PermitRootLogin is {root}.",
                "Prefer PermitRootLogin no and use named accounts with sudo, after validating access.")
        elif root == "no":
            add(findings, "SSH root login", "INFO", "PASS", "Root SSH login is disabled.",
                "Keep this setting and monitor authorized access.")
        else:
            add(findings, "SSH root login", "MEDIUM", "UNKNOWN",
                "No explicit PermitRootLogin directive found; effective value may depend on defaults/includes.",
                "Verify the effective setting with sshd -T.")
        password = settings.get("passwordauthentication", "default")
        if password == "yes":
            add(findings, "SSH password authentication", "MEDIUM", "REVIEW",
                "PasswordAuthentication is explicitly enabled.",
                "Consider key-based authentication and MFA where supported; test before changing access.")
        elif password == "no":
            add(findings, "SSH password authentication", "INFO", "PASS",
                "PasswordAuthentication is disabled in the main config.",
                "Ensure key management and recovery access are documented.")
        else:
            add(findings, "SSH password authentication", "INFO", "UNKNOWN",
                "No explicit PasswordAuthentication directive found.",
                "Verify the effective setting with sshd -T and inspect included config files.")

    ufw = command_output(["ufw", "status"])
    if ufw is None:
        add(findings, "UFW firewall", "INFO", "UNKNOWN", "UFW is unavailable or could not be executed.",
            "Check the host firewall using the firewall manager installed on this distribution.")
    elif "Status: active" in ufw:
        add(findings, "UFW firewall", "INFO", "PASS", "UFW reports active.",
            "Review allowed rules and remove unnecessary exposure.")
    elif "Status: inactive" in ufw:
        add(findings, "UFW firewall", "MEDIUM", "REVIEW", "UFW reports inactive.",
            "Confirm whether another host firewall is enforcing the intended policy.")
    else:
        add(findings, "UFW firewall", "INFO", "UNKNOWN", ufw[:180],
            "Confirm firewall status with the platform's firewall tooling.")

    forwarding = read_text("/proc/sys/net/ipv4/ip_forward")
    if forwarding is not None:
        value = forwarding.strip()
        if value == "1":
            add(findings, "IPv4 forwarding", "MEDIUM", "REVIEW", "IPv4 forwarding is enabled.",
                "Disable forwarding if this host is not intended to route traffic.")
        else:
            add(findings, "IPv4 forwarding", "INFO", "PASS", "IPv4 forwarding is disabled.",
                "Keep disabled unless routing is an explicit host requirement.")

    shadow = Path("/etc/shadow")
    try:
        mode = stat.S_IMODE(shadow.stat().st_mode)
        if mode & 0o007 or mode & 0o020:
            add(findings, "Shadow file permissions", "HIGH", "REVIEW",
                f"/etc/shadow permissions are {oct(mode)}.",
                "Restrict access to root and the required system group; follow distribution guidance.")
        else:
            add(findings, "Shadow file permissions", "INFO", "PASS",
                f"/etc/shadow permissions are {oct(mode)}.",
                "Keep credential database permissions restrictive.")
    except OSError:
        add(findings, "Shadow file permissions", "INFO", "UNKNOWN",
            "Could not inspect /etc/shadow permissions.",
            "Review file ownership and permissions with an authorized administrator.")

    login_defs = read_text("/etc/login.defs")
    if login_defs:
        match = re.search(r"(?m)^\s*UMASK\s+(0?[0-7]{3})\b", login_defs)
        if match:
            mask = match.group(1)
            add(findings, "Default user umask", "INFO", "REVIEW" if mask in {"000", "002"} else "PASS",
                f"Configured UMASK is {mask}.",
                "Use a restrictive default such as 027 or 077 when appropriate for the environment.")
    return findings

def main():
    parser = argparse.ArgumentParser(description="Run read-only baseline security checks on a Linux host.")
    parser.add_argument("--json", dest="json_path", help="Write findings to a JSON file")
    args = parser.parse_args()
    findings = audit()
    counts = {level: sum(1 for item in findings if item["severity"] == level) for level in ("HIGH", "MEDIUM", "LOW", "INFO")}
    result = {"host": platform.node(), "platform": platform.platform(), "checks": len(findings),
              "severity_summary": counts, "findings": findings,
              "note": "Read-only baseline assessment; findings require human validation."}
    print(json.dumps(result, indent=2))
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
