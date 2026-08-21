# CyberLabKit Labs

Labs are small, reproducible learning environments. Every lab must define an objective, prerequisites, authorized scope, expected evidence, and a verification method.

## Structure

Each lab should contain:

```text
lab-name/
├── README.md
├── lab.yaml
├── notes/
└── evidence/
```

## Lab levels

- `beginner` — foundational concepts and safe observation.
- `intermediate` — investigation, configuration, and troubleshooting.
- `advanced` — multi-step scenarios requiring analysis and documentation.

## Safety boundary

Only use systems you own or have explicit permission to test. Vulnerable targets must be intentionally provided for training. Never put real credentials, personal data, or third-party targets in a lab.

## Planned catalog

- Networking fundamentals
- Linux hardening
- Windows event analysis
- Web security with intentionally vulnerable targets
- SOC alert triage
- Incident response
- Threat hunting
- Active Directory security in an isolated lab
