"""Read-only Windows Firewall posture snapshot, without collecting identifiers."""
import argparse
import json
import os
import subprocess
import sys

# Run only a fixed command. Project only enum values and counts, never rule details.
COLLECTOR = """
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
    [pscustomobject]@{
        name = [string]$_.Name
        enabled = [string]$_.Enabled
        inbound = [string]$_.DefaultInboundAction
        outbound = [string]$_.DefaultOutboundAction
    }
})
$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True)
[pscustomobject]@{
    profiles = $profiles
    inbound_allow_all_profiles = @($rules | Where-Object {
        $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and $_.Profile -eq 'Any'
    }).Count
    outbound_block_rules = @($rules | Where-Object {
        $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block'
    }).Count
} | ConvertTo-Json -Compress -Depth 4
"""

PROFILE_ORDER = ("Domain", "Private", "Public")
DEMO = {
    "profiles": [
        {"name": "Domain", "enabled": "True", "inbound": "Block", "outbound": "Allow"},
        {"name": "Private", "enabled": "True", "inbound": "Block", "outbound": "Allow"},
        {"name": "Public", "enabled": "True", "inbound": "Block", "outbound": "Allow"},
    ],
    "inbound_allow_all_profiles": 3,
    "outbound_block_rules": 1,
}


def audit(data, *, demo=False):
    if not isinstance(data, dict) or not isinstance(data.get("profiles"), list):
        raise ValueError("Invalid firewall data.")
    profiles = {}
    for row in data["profiles"]:
        if not isinstance(row, dict) or row.get("name") not in PROFILE_ORDER:
            raise ValueError("Invalid firewall profile.")
        name = row["name"]
        if name in profiles:
            raise ValueError("Duplicate firewall profile.")
        profiles[name] = row
    if set(profiles) != set(PROFILE_ORDER):
        raise ValueError("Incomplete firewall profiles.")

    output = {"source": "synthetic-demo" if demo else "windows-active-store",
              "profiles": [], "findings": []}
    for name in PROFILE_ORDER:
        row = profiles[name]
        enabled = row.get("enabled")
        inbound = row.get("inbound")
        outbound = row.get("outbound")
        normalized = {
            "name": name,
            "enabled": enabled if enabled in ("True", "False") else "Unknown",
            "inbound": inbound if inbound in ("Allow", "Block") else "Unknown",
            "outbound": outbound if outbound in ("Allow", "Block") else "Unknown",
        }
        output["profiles"].append(normalized)
        for condition, level, code in (
            (enabled == "False", "high", "FIREWALL_DISABLED"),
            (inbound == "Allow", "high", "INBOUND_DEFAULT_ALLOW"),
            ("Unknown" in normalized.values(), "review", "PROFILE_SETTING_UNKNOWN"),
            (outbound == "Allow", "info", "OUTBOUND_DEFAULT_ALLOW"),
            (outbound == "Block", "review", "VERIFY_OUTBOUND_ALLOWLIST"),
        ):
            if condition:
                output["findings"].append({"profile": name, "level": level, "code": code})
    for key in ("inbound_allow_all_profiles", "outbound_block_rules"):
        value = data.get(key)
        if type(value) is not int or value < 0:
            raise ValueError("Invalid firewall rule count.")
        output[key] = value
    if output["inbound_allow_all_profiles"]:
        output["findings"].append(
            {"level": "review", "code": "REVIEW_ALL_PROFILE_INBOUND_ALLOW_RULES"}
        )
    return output


def run_windows():
    if sys.platform != "win32":
        raise RuntimeError("Live audit requires Windows; use --demo elsewhere.")
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    powershell = os.path.join(system_root, "System32", "WindowsPowerShell", "v1.0",
                              "powershell.exe")
    try:
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive",
                                 "-Command", COLLECTOR],
                                capture_output=True, encoding="utf-8-sig", errors="strict",
                                timeout=30, check=True)
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
        # Raw stderr could expose host information; do not print or save it.
        raise RuntimeError("Could not query NetSecurity. Check Windows Firewall access or run "
                           "from an approved elevated terminal.") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true", help="use synthetic data, no Windows query")
    args = parser.parse_args(argv)
    try:
        report = audit(DEMO if args.demo else run_windows(), demo=args.demo)
    except (ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 1 if any(item["level"] == "high" for item in report["findings"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
