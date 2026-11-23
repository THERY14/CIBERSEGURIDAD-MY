# Linux Posture Audit

**A read-only Linux baseline checker for junior security and system-administration practice.**

This tool inspects a small set of local security controls and produces structured findings with severity, evidence, and remediation guidance. It does not change system configuration.

## Checks included
- SSH root-login and password-authentication directives in the main sshd configuration
- UFW firewall status, when UFW is installed
- IPv4 forwarding state
- Permissions on `/etc/shadow`
- Default UMASK in `/etc/login.defs`

## Run
Requires Python 3.10+ and Linux. No third-party packages.

```bash
cd projects/linux-posture-audit
python linux_posture_audit.py
python linux_posture_audit.py --json posture-report.json
python -m unittest -v
```

Run with suitable permissions to inspect protected files. Checks that cannot be completed are reported as UNKNOWN rather than silently treated as passing.

## Example output
The command prints JSON with host metadata, a severity summary, and findings containing `check`, `severity`, `status`, `detail`, and `recommendation`.

## Scope and limitations
This is a learning baseline, not a compliance certification or a replacement for a vulnerability scanner, configuration-management platform, or professional security assessment. SSH include files and effective daemon settings are not fully resolved; verify them with your distribution's tooling. UFW status does not establish whether another firewall is active.

## Safety
The program is read-only: it does not modify firewall, SSH, permissions, packages, or kernel settings. Review recommendations before making changes to a production system.
