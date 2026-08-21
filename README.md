# CyberLabKit

Open-source toolkit for building, validating, and documenting cybersecurity learning labs.

CyberLabKit is designed for students, educators, and security practitioners who want a repeatable way to turn a computer into a safe cybersecurity practice environment. The project combines environment checks, guided lab definitions, evidence collection, and learning documentation.

> **Safety first:** CyberLabKit is intended for systems you own or have explicit authorization to test. It does not automate attacks against third-party systems.

## Why this project exists

Cybersecurity education is often split between theory and isolated exercises. CyberLabKit aims to bridge that gap by providing a consistent workflow:

**Learn → Build → Validate → Practice → Document → Improve**

The long-term goal is a community-maintained collection of labs covering networking, Linux, Windows, web security, SOC, incident response, cloud security, and defensive automation.

## Current MVP

The first release focuses on a safe local workflow:

- `cyberlabkit check` validates common prerequisites on a learning machine.
- `cyberlabkit init` creates a structured workspace for a new lab.
- `cyberlabkit report` generates a Markdown progress report from lab metadata.
- Lab definitions are plain YAML/JSON-friendly files so educators can version them with Git.
- The project is intentionally offline-first and does not require cloud credentials.

## Quick start

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install -e .
cyberlabkit check
cyberlabkit init my-first-lab
cyberlabkit report my-first-lab
```

## Example workflow

1. Create a lab workspace.
2. Add the systems and objectives you are authorized to use.
3. Run the environment checks.
4. Complete the lab manually.
5. Record observations and evidence.
6. Generate a report that can be reviewed by a mentor or included in a learning portfolio.

## Roadmap

### Phase 1 — Foundation
- environment validation
- lab templates
- Markdown reporting
- unit tests and CI

### Phase 2 — Learning labs
- networking fundamentals
- Linux hardening
- Windows event analysis
- web security exercises using intentionally vulnerable targets

### Phase 3 — Blue Team
- log collection templates
- IOC tracking
- incident-response case files
- MITRE ATT&CK mapping helpers

### Phase 4 — Community
- contribution templates
- reviewed community labs
- multilingual content (English / Spanish)
- reusable instructor guides

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and safety rules.

## Security

See [SECURITY.md](SECURITY.md). Security issues should be reported responsibly. Do not submit real credentials, private logs, or targets that you do not own or have permission to test.

## License

MIT — see [LICENSE](LICENSE).
