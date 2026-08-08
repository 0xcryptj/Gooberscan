# AgentSec Security Policy

AgentSec is security tooling, so reports about AgentSec itself should be handled carefully.

## Reporting a vulnerability

Please do not publish a working exploit for an unpatched AgentSec vulnerability in a public issue.

Use GitHub's private vulnerability reporting feature for this repository when it is enabled. If private reporting is unavailable, contact the repository owner privately and provide enough information to reproduce and assess the issue safely.

Useful details include:

- affected AgentSec version/commit
- operating system and agent/client
- exact feature or script involved
- impact
- minimal reproduction steps
- whether the problem can cause unintended command execution, secret disclosure, unsafe scanning, privilege escalation or scope/authorization bypass

Do not include real third-party secrets, credentials or customer data in a report.

## Security boundaries

AgentSec is intended for defensive development and authorized security assessment.

The project deliberately separates:

- local repository/static/configuration review
- read-only local server hardening inspection
- authorized remote enumeration
- explicitly authorized active web vulnerability validation

Active remote validation requires explicit CLI flags and must not be silently enabled by an agent.

## Scanner output

Scanner findings are evidence, not automatic proof of a vulnerability. AgentSec agents are instructed to correlate findings with code, configuration and architecture before labeling them confirmed.

## Generated reports

AgentSec reports can contain hostnames, ports, paths, dependency information, security findings and other sensitive details. Generated output under `.agentsec/` is gitignored by default. Treat reports as confidential unless you have intentionally reviewed them for publication.

## Dependency and skill supply chain

Before installing or updating AgentSec in a sensitive environment:

- review the repository source and recent changes
- pin to a trusted commit/tag when reproducibility matters
- review installer behavior before running it with elevated privileges
- avoid granting the coding agent broader filesystem/network privileges than the audit requires
- review any remediation patch before deploying it to production

AgentSec intentionally avoids automatically adding users to the Docker group because Docker socket/group access is typically highly privileged.

## Installation security model

The quick installer is a convenience wrapper around the `skills` CLI. It installs the `agentsec` skill for the selected agent scope; it does not require root and does not enable remote scanning.

For reproducible or high-assurance environments:

1. inspect the repository and installer source
2. install from a reviewed release tag or commit instead of `main`
3. verify the installed `SKILL.md` before using it
4. grant the coding agent only the filesystem, network and command permissions required for the audit

The optional `install-deps.sh` script is separate because it installs operating-system packages and may require `sudo`. Review it before use and run it only on supported Debian, Ubuntu or WSL systems.
