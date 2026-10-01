# Security Policy

AgentLatch is an early proof of concept and is not a security certification or a guarantee that scanned software is safe.

## Reporting a vulnerability

Please do not disclose exploitable vulnerabilities publicly before maintainers can assess them. Use GitHub's private vulnerability reporting for this repository when enabled. Until then, contact the repository maintainer privately through GitHub. Do not include real credentials or sensitive customer data in reports.

## Scanner safety boundaries

- Scanning is local by default; the scanner does not upload targets.
- Treat scanned repositories and generated reports as sensitive.
- Findings are heuristic and may have false positives or miss issues.
- Do not use this tool to scan repositories or systems without authorization.
