---
name: agentsec
description: >
  Defensive security engineering for software repositories, web applications, Linux servers, dependencies, architecture, identity, authorization, cloud/edge configuration, and deployment. Use when asked to audit, harden, threat-model, review OWASP risks, find vulnerable or suspicious dependencies, assess npm supply-chain risk, discover exposed files/directories, review server configuration, apply least privilege, evaluate MFA/passkeys, inspect Cloudflare security opportunities, fix SQL injection/XSS, or implement and verify security improvements.
license: MIT
compatibility: Linux/macOS/WSL. Python 3.10+ recommended. Optional tools include nmap, gobuster, ffuf, nikto, sqlmap, Docker/ZAP, lynis, npm, Semgrep, Trivy, OSV-Scanner, Gitleaks and ecosystem-specific package auditors.
metadata:
  author: 0xcryptj
  version: "1.0.0"
---

# AgentSec

AgentSec is a defensive security-engineering skill for coding agents. It combines architecture reasoning, source review and deterministic scanners so the agent can understand a system, identify security gaps, verify findings, implement safe remediations and retest the result.

The goal is not to dump scanner output. Act like a security engineer embedded in the development workflow.

## Core behavior

1. Determine the audit scope: repository, architecture, web application, server, or a combination.
2. Understand the architecture and trust boundaries before making broad recommendations.
3. Prefer non-destructive local inspection and passive checks first.
4. Run the bundled tools when available:
   - Architecture inventory: `python3 scripts/architecture_inventory.py <path> --output <file>`
   - Repository: `python3 scripts/agentsec.py repo <path>`
   - Local server: `python3 scripts/agentsec.py server --local`
   - Remote server exposure: `python3 scripts/agentsec.py server --target <host> --authorized`
   - Web application baseline: `python3 scripts/agentsec.py web <url> --authorized`
   - Authorized active validation: `python3 scripts/agentsec.py web <url> --authorized --active`
5. Read reports and correlate findings with the actual code, configuration and architecture before declaring a vulnerability.
6. Rank findings as critical, high, medium, low or informational, and separately identify security design gaps and defense-in-depth opportunities.
7. When the user requests fixes, implement the smallest safe remediation, preserve behavior, then rerun relevant tests and security checks.
8. Never silently weaken authentication, authorization, TLS, validation, logging, rate limiting, isolation or security headers to make tests pass.

## Authorization boundary

Local repository review, architecture review, dependency review, secret detection, configuration review and local server hardening checks are defensive inspection.

For remote web or network targets, only perform scanning or active vulnerability validation when the user owns the system or has explicit authorization. AgentSec active mode requires both `--authorized` and `--active`. Do not bypass that guardrail. Do not perform credential attacks, destructive exploitation, persistence, data exfiltration, denial-of-service testing or post-exploitation.

## Architecture and threat-model workflow

For a repository audit, run the architecture inventory before or alongside scanners:

```bash
python3 scripts/architecture_inventory.py . --output .agentsec-architecture.json
```

Use the inventory as a hypothesis generator, then inspect the source and configuration to confirm the architecture.

Map at minimum:

- clients and public entry points
- CDN/edge/reverse proxy
- application/API services
- authentication provider and session model
- normal, privileged and service identities
- background workers and queues
- databases, caches and object storage
- external APIs, webhooks and payment systems
- CI/CD, cloud identities and deployment path
- logging, monitoring, backups and recovery paths

Apply security architecture reasoning, including:

- principle of least privilege for users, admins, services, workers, database roles, CI and cloud IAM
- trust-boundary minimization
- tenant and object authorization
- MFA/passkeys or step-up authentication for privileged/high-impact actions where appropriate
- separate migration/admin database credentials from runtime credentials
- rate limiting and abuse controls based on action and identity
- secret scoping and rotation capability
- secure defaults and fail-closed authorization
- auditability for privileged and financial actions
- isolation of user-controlled files/content
- recovery and incident-response design

Do not claim MFA, rate limiting, WAF or another externally managed control is absent merely because it is not visible in source. Mark it `review-needed` and verify the IdP/CDN/cloud configuration when available.

See [references/architecture-security.md](references/architecture-security.md).

## Repository audit workflow

Run:

```bash
python3 scripts/agentsec.py repo .
```

Inspect at minimum:

- dependency advisories and lockfile integrity
- npm audit and installed dependency tree for JavaScript/TypeScript projects
- package signatures when the installed npm/registry supports them
- OSV/Trivy findings when available
- suspicious dependency additions, typosquatting indicators, install scripts and unexpected lockfile churn
- secrets and credentials committed to source
- unsafe deserialization, command execution, path traversal, SSRF, SQL injection, XSS, CSRF, IDOR/access-control mistakes, weak crypto, insecure randomness, open redirects, upload handling and auth/session problems
- CORS, CSP, cookie flags, security headers, debug modes, source maps, environment files, backup files, cloud credentials, Dockerfiles, CI workflows, IaC and deployment manifests

For npm remediation, inspect the advisory and dependency path first. Prefer a direct dependency upgrade to a patched compatible version. Use `npm audit fix` only when it does not require an unsafe breaking jump and run the project's tests/build afterward. Never use `npm audit fix --force` automatically.

If a dependency is confirmed compromised or malicious, a version bump may not be enough. Consider credential rotation, CI/developer-host review and incident response based on what that package could access.

See [references/repository-security.md](references/repository-security.md).

## Web application audit workflow

Run a baseline authorized assessment:

```bash
python3 scripts/agentsec.py web https://example.com --authorized
```

Baseline mode may inspect TLS, headers, exposed paths, public metadata, server fingerprints, directory exposure and passive scanner findings. Treat directory enumeration as a defensive exposure check: the goal is to discover what an unauthenticated outsider can find and then remove, authenticate or correctly protect sensitive paths.

If the user explicitly authorizes active validation:

```bash
python3 scripts/agentsec.py web https://example.com --authorized --active
```

Active mode may use controlled ZAP/sqlmap checks for XSS and SQL injection against the authorized scope. Keep request rates conservative and stop if instability appears.

For exposed directories or Gobuster/ffuf findings:

1. Determine whether the path is intended to be public.
2. Check for directory listing, backup archives, `.git`, `.env`, logs, database dumps, admin panels, debug endpoints, source maps, storage paths, generated reports or internal documentation.
3. Fix the underlying deployment/server configuration, not merely the scanner result.
4. Remove sensitive artifacts from the web root and add explicit deny/auth rules where appropriate.
5. Verify the path returns the intended 401/403/404 behavior and cannot be reached through alternate routing.

Do not use `robots.txt` to hide sensitive routes. It is crawler policy, not authorization.

See [references/web-security.md](references/web-security.md).

## Cloudflare-aware review

If repository/runtime evidence indicates Cloudflare, inspect the architecture and recommend only controls relevant to the application and available plan.

Potential security controls include:

- Cloudflare Managed WAF rules appropriate to the stack
- OWASP managed rules when available
- endpoint-specific rate limits for login, signup, reset, API abuse and destructive/expensive actions
- Turnstile for abuse-sensitive forms with server-side token verification
- bot controls where automated abuse is a real threat
- Full (strict) TLS to origin
- origin firewall restrictions and/or Authenticated Origin Pulls to reduce direct-origin bypass
- safe cache rules for public/static content
- cache bypass for authenticated, personalized or authorization-sensitive responses
- edge security headers when that is the chosen source of truth

Do not recommend caching personalized responses without proving that cache keys and bypass rules preserve user/tenant isolation.

## robots.txt, llms.txt and security.txt

AgentSec may identify these as operational recommendations:

- `robots.txt`: crawler/SEO policy. Not a secrecy or access-control mechanism.
- `llms.txt`: optional emerging AI-readable content index. Not a security control.
- `/.well-known/security.txt`: useful vulnerability-disclosure contact/policy for public projects.

Do not score a missing `robots.txt` or `llms.txt` as a vulnerability.

## Server audit workflow

For the machine AgentSec is running on:

```bash
python3 scripts/agentsec.py server --local
```

For external exposure of an authorized server:

```bash
python3 scripts/agentsec.py server --target server.example.com --authorized
```

Review:

- listening services and unnecessary ports
- OS/package patch status
- SSH configuration, root login, password auth, obsolete algorithms and exposed management interfaces
- firewall state and network binding
- TLS protocols/ciphers and certificate problems
- SUID/SGID files, world-writable sensitive paths, unsafe permissions, cron/systemd privilege surfaces and risky service accounts
- Docker/container privileges, exposed Docker socket, host networking, privileged containers, mounted secrets and stale images
- web-server configuration, directory indexes, server-status pages, default sites, upload paths and secrets under document roots
- database/cache listeners exposed beyond the required network boundary
- Lynis findings when available

See [references/server-security.md](references/server-security.md).

## Remediation rules

When fixing a finding:

1. Cite the evidence that proves the issue exists.
2. Identify the root cause and affected trust boundary.
3. Change code/configuration rather than hiding scanner output.
4. Preserve backwards compatibility when reasonable.
5. Add or update a regression test when the issue is testable.
6. Rerun the smallest relevant security check plus the project's normal tests.
7. Report anything that remains unverified.

Common safe remediations include parameterized database queries, context-aware output encoding, strict input validation, least-privilege IAM/database roles, secure cookie flags, CSP, CSRF defenses, dependency upgrades, protected admin routes, removal of public backups/secrets, firewall rules, SSH hardening, disabling directory indexing and safe Cloudflare edge controls.

See [references/remediation.md](references/remediation.md).

## Findings taxonomy

Use these labels deliberately:

### Confirmed vulnerability

Evidence demonstrates an unsafe condition or exploitable behavior.

### Security design gap

Architecture evidence demonstrates a missing/weak control with concrete risk, but it may not be independently exploitable.

### Security opportunity

A defense-in-depth, resilience, observability or operational improvement. Do not inflate it into a vulnerability.

### Review needed

Repo evidence suggests a potential gap, but the relevant control may exist outside source control or requires runtime/provider verification.

## Output expected from the agent

Return a concise audit with:

- architecture summary and trust boundaries
- scope and checks performed
- confirmed findings grouped by severity
- security design gaps
- defense-in-depth opportunities
- evidence and affected component/file
- why each issue matters
- concrete remediation
- changes actually implemented, if requested
- verification/tests run and remaining limitations

Do not report a scanner heuristic or architecture guess as confirmed without checking the evidence.