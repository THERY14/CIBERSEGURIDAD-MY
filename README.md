# Cybersecurity Portfolio | THERY14

<p align="center">
  <strong>Blue Team · SOC Operations · Python Security Automation · Linux Hardening</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Focus-Blue%20Team-0ea5e9?style=for-the-badge" alt="Blue Team focus">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-111827?style=for-the-badge" alt="Linux and Windows">
  <img src="https://img.shields.io/badge/Safety-Defensive%20Only-16a34a?style=for-the-badge" alt="Defensive only">
</p>

**I am building practical cybersecurity skills through defensive tools, repeatable labs, and documented investigations.** This repository is a hands-on portfolio focused on entry-level SOC and Junior Cybersecurity Analyst workflows.

> **Portfolio principle:** every project should be reproducible, documented, testable, and honest about its limitations. All exercises are designed for synthetic data or systems I own / am authorized to assess.

## Featured projects

| Project | What it does | Skills demonstrated |
|---|---|---|
| [SOC Log Analyzer](projects/soc-log-analyzer/) | Parses authentication events and flags repeated failures and successful logins after failure bursts. | Python, log analysis, detection logic, alert triage, JSON, unit tests |
| [Linux Posture Audit](projects/linux-posture-audit/) | Performs read-only baseline checks for selected Linux security settings and produces structured findings. | Linux, SSH hardening, permissions, firewall awareness, risk prioritization |
| [Windows Firewall Guard](projects/windows-firewall-guard/) | Audits Windows Firewall profiles without changing rules and documents a reversible outbound blocking lab. | Windows Firewall, PowerShell, Python, data minimization, unit tests |
| [CyberLabKit](#cyberlabkit) | Creates local cybersecurity lab workspaces and generates Markdown evidence reports. | Python CLI, lab documentation, repeatable learning environments |

## Project 1 — SOC Log Analyzer

A small defensive triage utility for JSONL, JSON, and CSV authentication events.

- Groups failed logins by source IP and username.
- Flags repeated failures and a successful login after a failure burst.
- Assigns severity and exports machine-readable JSON.
- Includes synthetic sample events and unit tests.

**Run it**
```bash
cd projects/soc-log-analyzer
python soc_log_analyzer.py sample_auth.jsonl
python -m unittest -v
```

[Open project documentation →](projects/soc-log-analyzer/README.md)

## Project 2 — Linux Posture Audit

A read-only Linux baseline checker. It reviews selected SSH settings, UFW status, IPv4 forwarding, shadow-file permissions, and default UMASK.

- Produces findings with severity, status, evidence, and remediation guidance.
- Reports UNKNOWN when a check cannot be completed.
- Does not change system configuration.
- Includes tests and a JSON output option.

**Run it**
```bash
cd projects/linux-posture-audit
python linux_posture_audit.py
python -m unittest -v
```

[Open project documentation →](projects/linux-posture-audit/README.md)

## CyberLabKit

CyberLabKit is an offline-first toolkit for creating and documenting safe cybersecurity learning labs.

Current commands:
- `cyberlabkit check` — checks local learning prerequisites.
- `cyberlabkit init <name>` — creates a lab workspace with notes and evidence folders.
- `cyberlabkit report <name>` — generates a Markdown lab report.

**Quick start**
```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\\Scripts\\Activate.ps1
pip install -e .
cyberlabkit check
cyberlabkit init my-first-lab
cyberlabkit report my-first-lab
```

## Technical focus

- **Security operations:** authentication-log review, alert triage, incident documentation.
- **Systems:** Windows and Linux support, Linux security baselines, troubleshooting.
- **Automation:** Python fundamentals, command-line tools, structured JSON reporting.
- **IT operations:** ticket handling, prioritization, documentation, and SLA awareness.
- **Learning path:** SOC fundamentals, SIEM concepts, network security, vulnerability management, and incident response.

## Certifications & learning

- Cisco Networking Academy — Introduction to Cybersecurity
- Cisco Networking Academy — Python Essentials 1
- Santander Academy — Introduction to Data Science

## Engineering quality

- Python 3.10+
- Standard-library-first implementations where practical
- Automated tests with GitHub Actions
- Synthetic sample data; no customer or private production logs
- Clear scope, limitations, and remediation guidance

## Roadmap

- [x] Build a repeatable cybersecurity lab workspace (CyberLabKit MVP)
- [x] Create an authentication-log triage prototype
- [x] Create a read-only Linux posture baseline prototype
- [ ] Add time-window correlation and Windows Event Log parsing
- [ ] Add more Linux checks with distribution-aware validation
- [ ] Publish investigation write-ups with sanitized evidence
- [ ] Add SIEM integration labs (e.g. Wazuh) in an isolated environment

## About this portfolio

I am pursuing opportunities in **SOC L1 / Junior Cybersecurity Analyst / Blue Team** roles. My approach is to connect my IT support and systems foundation with practical security automation and documented hands-on work.

**Languages:** Spanish (native); English — developing professional proficiency.

## Responsible use

These projects are for education and defensive security. Use only synthetic data or systems you own or have explicit authorization to assess. Findings are indicators for human review, not proof of compromise or compliance.

---
*Maintained by [@THERY14](https://github.com/THERY14).*
