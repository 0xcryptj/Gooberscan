---
name: agentsec
description: >
  Defensive security auditing and remediation for software repositories, web applications, Linux servers, dependencies, and deployment configuration. Use when reviewing an application for OWASP risks, vulnerable or compromised dependencies, npm/package advisories, exposed files or directories, insecure server configuration, secrets, weak authentication or authorization, SQL injection, XSS, TLS, network exposure, container risks, or when asked to harden and fix a project after an authorized security audit.
license: MIT
compatibility: Linux/macOS/WSL. Python 3.10+ recommended. Optional tools include nmap, gobuster, ffuf, nikto, sqlmap, Docker/ZAP, lynis, npm, Semgrep, Trivy, OSV-Scanner, Gitleaks and ecosystem-specific package auditors.
metadata:
  author: 0xcryptj
  version: "1.0.0"
---

# AgentSec

AgentSec is a defensive security-engineering skill for coding agents. It combines deterministic scanners with agent reasoning so the agent can find, explain, prioritize, remediate, and verify security issues instead of merely dumping scanner output.

## Core behavior

1. Determine the audit scope: repository, web application, server, or a combination.
2. Prefer non-destructive local inspection and passive checks first.
3. Run the bundled AgentSec CLI when available:
   - Repository: `python3 scripts/agentsec.py repo <path>`
   - Local server: `python3 scripts/agentsec.py server --local`
   - Remote server exposure: `python3 scripts/agentsec.py server --target <host>`
   - Web application: `python3 scripts/agentsec.py web <url>`
4. Read the generated report and correlate findings with the actual code/configuration before declaring a vulnerability.
5. Rank findings as critical, high, medium, low, or informational. Include evidence and affected files/components.
6. When the user requests fixes, implement the smallest safe remediation, preserve behavior, then rerun relevant tests and security checks.
7. Never silently weaken authentication, authorization, TLS, validation, logging, rate limiting, or security headers to make tests pass.

## Authorization boundary

Local repository review, dependency review, secret detection, configuration review, and local server hardening checks are defensive inspection.

For remote web or network targets, only perform active vulnerability validation when the user owns the system or has explicit authorization. AgentSec's active mode requires both `--authorized` and `--active`. Do not bypass that guardrail. Do not perform credential attacks, persistence, destructive exploitation, data exfiltration, denial-of-service testing, or post-exploitation.

## Repository audit workflow

Run:

```bash
python3 scripts/agentsec.py repo .
```

Inspect at minimum:

- Dependency advisories and package-lock integrity.
- npm audit results for JavaScript/TypeScript projects.
- Package signatures when the installed npm version supports `npm audit signatures`.
- OSV/Trivy findings when those tools are available.
- Secrets and credentials committed to source.
- Unsafe deserialization, command execution, path traversal, SSRF, SQL injection, XSS, CSRF, IDOR/access-control mistakes, weak crypto, insecure randomness, open redirects, upload handling, and auth/session problems.
- CORS, CSP, cookie flags, security headers, debug modes, source maps, environment files, backup files, cloud credentials, Dockerfiles, CI workflows, IaC, and deployment manifests.

For npm remediation, first inspect the advisory path. Prefer a direct dependency upgrade to a patched compatible version. Use `npm audit fix` only when it does not require an unsafe major-version jump, then run the project's tests/build. Never use `npm audit fix --force` automatically.

See [references/repository-security.md](references/repository-security.md) for the detailed checklist.

## Web application audit workflow

Run a baseline authorized assessment:

```bash
python3 scripts/agentsec.py web https://example.com
```

Baseline mode may inspect TLS, headers, exposed paths, public metadata, server fingerprints, directory exposure, and passive scanner findings. Treat directory enumeration as a defensive exposure check: the goal is to discover what an unauthenticated outsider can find and then close or protect sensitive paths.

If the user explicitly authorizes active validation:

```bash
python3 scripts/agentsec.py web https://example.com --authorized --active
```

Active mode may use controlled ZAP/sqlmap checks for XSS and SQL injection against the authorized scope. Keep request rates conservative. Stop if instability appears.

For exposed directories or Gobuster/ffuf findings:

1. Determine whether the path is intended to be public.
2. Check for directory listing, backup archives, `.git`, `.env`, logs, database dumps, admin panels, debug endpoints, source maps, storage buckets, generated reports, or internal documentation.
3. Fix the underlying deployment/server configuration, not merely the scanner result.
4. Add explicit deny rules where appropriate and remove sensitive artifacts from the web root.
5. Verify the path returns the intended 401/403/404 behavior and cannot be reached through alternate routing/encoding.

See [references/web-security.md](references/web-security.md).

## Server audit workflow

For the machine AgentSec is running on:

```bash
python3 scripts/agentsec.py server --local
```

For external exposure of an authorized server:

```bash
python3 scripts/agentsec.py server --target server.example.com
```

Review:

- Listening services and unnecessary ports.
- OS/package patch status.
- SSH configuration, root login, password auth, weak algorithms, and exposed management interfaces.
- Firewall state and network binding.
- TLS protocols/ciphers and certificate problems.
- SUID/SGID files, world-writable sensitive paths, unsafe permissions, cron/systemd persistence surfaces, and risky service accounts.
- Docker/container privileges, exposed Docker socket, host networking, privileged containers, mounted secrets, and stale images.
- Web-server configuration, directory indexes, server-status pages, default sites, upload paths, and secrets under document roots.
- Database listeners exposed beyond the required network boundary.
- Lynis findings when available.

See [references/server-security.md](references/server-security.md).

## Remediation rules

When fixing a finding:

1. Cite the evidence that proves the issue exists.
2. Identify the root cause.
3. Change code/configuration rather than hiding scanner output.
4. Preserve backwards compatibility when reasonable.
5. Add or update a regression test when the issue is testable.
6. Rerun the smallest relevant security check plus the project's normal tests.
7. Report anything that remains unverified.

Common safe remediations include parameterized database queries, context-aware output encoding, strict input validation, least-privilege IAM/database roles, secure cookie flags, CSP, CSRF defenses, dependency upgrades, protected admin routes, removal of public backups/secrets, firewall rules, SSH hardening, and disabling directory indexing.

See [references/remediation.md](references/remediation.md).

## Output expected from the agent

Return a concise audit with:

- Scope and checks performed.
- Findings grouped by severity.
- Evidence and affected component/file.
- Why each issue matters.
- Concrete remediation.
- Changes actually implemented, if requested.
- Verification/tests run and remaining limitations.

Do not report a scanner heuristic as confirmed without checking the evidence.