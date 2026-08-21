"""Command-line interface for CyberLabKit.

The MVP intentionally performs only local, non-destructive operations.
"""

from __future__ import annotations

import argparse
import platform
import shutil
import sys
from pathlib import Path


def check_environment() -> int:
    checks = {
        "Python": sys.version.split()[0],
        "Platform": platform.platform(),
        "Git": shutil.which("git") or "not found",
        "Docker": shutil.which("docker") or "not found",
    }
    print("CyberLabKit environment check")
    print("=" * 32)
    for name, value in checks.items():
        print(f"{name:10}: {value}")
    print("\nNo remote hosts are scanned and no network attack is performed.")
    return 0


def init_lab(name: str) -> int:
    root = Path(name)
    root.mkdir(parents=True, exist_ok=True)
    (root / "evidence").mkdir(exist_ok=True)
    (root / "notes").mkdir(exist_ok=True)
    (root / "lab.yaml").write_text(
        """name: {name}\nstatus: not-started\nobjective: Define your authorized learning objective here.\n""".format(name=name),
        encoding="utf-8",
    )
    (root / "notes" / "README.md").write_text(
        "# Lab notes\n\nRecord observations, commands, and lessons learned here. Never add secrets or private data.\n",
        encoding="utf-8",
    )
    print(f"Created lab workspace: {root}")
    return 0


def report(name: str) -> int:
    root = Path(name)
    if not root.exists():
        print(f"Lab not found: {name}", file=sys.stderr)
        return 1
    evidence = list((root / "evidence").glob("**/*")) if (root / "evidence").exists() else []
    notes = list((root / "notes").glob("**/*")) if (root / "notes").exists() else []
    output = root / "REPORT.md"
    output.write_text(
        "# CyberLabKit Lab Report\n\n"
        f"- Lab: `{name}`\n"
        "- Evidence files: " + str(len([p for p in evidence if p.is_file()])) + "\n"
        "- Note files: " + str(len([p for p in notes if p.is_file()])) + "\n\n"
        "## Reviewer checklist\n\n"
        "- [ ] Objective is clearly defined\n"
        "- [ ] Environment is authorized\n"
        "- [ ] Evidence contains no secrets\n"
        "- [ ] Findings are reproducible\n"
        "- [ ] Mitigations are documented\n",
        encoding="utf-8",
    )
    print(f"Generated: {output}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="CyberLabKit safe cybersecurity learning toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="Check local learning environment")
    init_parser = sub.add_parser("init", help="Create a local lab workspace")
    init_parser.add_argument("name")
    report_parser = sub.add_parser("report", help="Generate a lab report")
    report_parser.add_argument("name")

    args = parser.parse_args()
    if args.command == "check":
        return check_environment()
    if args.command == "init":
        return init_lab(args.name)
    if args.command == "report":
        return report(args.name)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
