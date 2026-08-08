# AgentSec Reference Library

These files are the deeper playbooks AgentSec loads only when they are relevant. This keeps the primary `SKILL.md` compact enough for coding-agent context while preserving senior-level security guidance.

## Core references

- [Repository Reading](repo-reading.md) - token-efficient repository reconnaissance and progressive disclosure
- [Architecture Security](architecture-security.md) - trust boundaries, least privilege, identity and security architecture
- [Repository Security](repository-security.md) - source, dependency, secret, CI/CD and configuration review
- [Web Security](web-security.md) - authorized web assessment and exposure review
- [Server Security](server-security.md) - Linux, network, service and infrastructure hardening
- [Remediation](remediation.md) - root-cause fixes and verification
- [Standards and Tools](standards-and-tools.md) - OWASP, CWE, CIS, NIST, Burp Suite, SonarQube, Snyk and scanner correlation

## Loading rule

Do not load every reference into context for every audit.

1. Read the repository shape first.
2. Build a compact architecture/security map.
3. Load only the reference that matches the surface under review.
4. Use scanner output to narrow deeper source reading.
5. Preserve a compact working summary rather than repeatedly rereading large files.

This progressive approach is part of AgentSec's KISS philosophy: spend complexity and tokens only where they improve the security decision.
