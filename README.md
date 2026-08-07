# AgentSec

**Agentic Security Auditing & Remediation**

AgentSec is a portable security-engineering skill for AI coding agents. It gives Claude Code, Codex, Cursor, GitHub Copilot and other Agent Skills-compatible tools a repeatable workflow for understanding an application's architecture, auditing repositories and servers, finding security weaknesses, proposing architectural improvements, applying safe fixes and verifying the result.

AgentSec replaces the original Gooberscan design. The old project was primarily a scanner orchestrator. AgentSec keeps deterministic scanners, but puts an architecture-aware security skill above them so an AI coding agent can reason about **why** a control is needed and **where** to implement it.

> **Authorized defensive use only.** Only scan remote systems you own or have explicit permission to assess. AgentSec does not enable credential attacks, destructive exploitation, persistence, data exfiltration, denial-of-service testing or post-exploitation.

## Why AgentSec

A scanner might tell you that port 5432 is open or that a package has a CVE. AgentSec is designed to go further:

- "Your application runtime appears to use the same database identity as migrations. Split these credentials and grant the runtime only the table actions it needs."
- "This project has privileged/admin roles and authentication, but no MFA/passkey implementation is visible. Check the external identity provider, then consider MFA or step-up authentication for privileged actions."
- "Cloudflare is already in the architecture. Consider Managed WAF rules, route-specific rate limiting, Turnstile for abuse-sensitive forms and origin lockdown so attackers cannot bypass the edge."
- "Gobuster found a backup path. Do not rename it and call it fixed. Remove the backup from the web root, disable indexing and verify access controls on the entire route tree."
- "This npm advisory is transitive through dependency X. Upgrade the compatible direct dependency, rerun the tests, then rerun the audit."
- "A `robots.txt` file may be useful for crawler policy, but it cannot protect a private route."

That is the core idea: **find -> understand -> verify -> harden -> fix -> retest**.

## What AgentSec audits

| Area | Examples |
| --- | --- |
| Architecture | trust boundaries, privileged identities, least privilege, service separation, MFA/passkey opportunities, tenant isolation, recovery flows |
| Source code | SQL injection, XSS, command injection, SSRF, path traversal, unsafe deserialization, auth/authz bugs, IDOR, CSRF, insecure crypto, uploads |
| Dependencies | npm advisories/tree/signatures, suspicious package changes, OSV, Trivy, pip-audit, cargo-audit |
| Supply chain | lockfile integrity, install scripts, secret leakage, CI permissions, third-party actions, compromised-package response |
| Secrets | `.env`, keys, tokens, cloud credentials, database files, backups, logs and sensitive deployment artifacts |
| Web exposure | TLS, headers, CORS, CSP, exposed directories/files, Gobuster/ffuf, Nikto, ZAP baseline |
| Authorized active validation | controlled SQL injection validation with sqlmap and XSS/web testing with ZAP |
| Linux servers | patch status, listeners, SSH, firewall, SUID/SGID, permissions, cron/systemd, Nginx/Apache, Docker, databases, Lynis |
| Cloud/edge | Cloudflare WAF, rate limits, Turnstile, origin protection, TLS and caching boundaries when Cloudflare is detected |
| Operational security | `security.txt`, crawler policy, logging/auditability and incident-response readiness |

## Portable Agent Skill

AgentSec follows the open Agent Skills format. The repository contains a root [`SKILL.md`](SKILL.md), executable scripts and progressively loaded security references.

```text
AgentSec/
├── SKILL.md
├── README.md
├── agentsec
├── install-deps.sh
├── scripts/
│   ├── agentsec.py
│   ├── architecture_inventory.py
│   └── local_server_audit.sh
└── references/
    ├── architecture-security.md
    ├── repository-security.md
    ├── web-security.md
    ├── server-security.md
    └── remediation.md
```

The same skill can be installed into multiple coding agents rather than maintaining separate Claude/Codex/Cursor prompts.

## Install the skill

After this repository is renamed to `AgentSec`:

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec
```

To target the three main coding agents explicitly:

```bash
npx skills add 0xcryptj/AgentSec \
  --skill agentsec \
  --agent claude-code \
  --agent codex \
  --agent cursor
```

Install globally if you want AgentSec available across projects:

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec --global
```

While the GitHub repository is still named `Gooberscan`, install from a local clone:

```bash
git clone https://github.com/0xcryptj/Gooberscan.git AgentSec
cd AgentSec
git checkout agent-skill-v1
npx skills add . --skill agentsec
```

If a particular agent does not discover an installed skill automatically, copy or symlink the `agentsec` skill directory into that agent's documented skills directory. The Agent Skills ecosystem is evolving quickly, so the repository itself remains the canonical source.

## Install security tools

AgentSec can provide security reasoning without every scanner installed, but deterministic tooling makes audits substantially stronger.

Debian / Ubuntu / WSL:

```bash
chmod +x install-deps.sh agentsec scripts/local_server_audit.sh
sudo ./install-deps.sh
```

Then:

```bash
./agentsec --help
```

Optional tools AgentSec understands include:

- Nmap
- Gobuster / ffuf
- Nikto
- sqlmap
- OWASP ZAP
- Lynis
- npm audit
- OSV-Scanner
- Trivy
- Semgrep
- Gitleaks
- pip-audit
- cargo-audit

Missing optional tools are reported and skipped rather than causing the entire audit to fail.

## Quick start

### 1. Audit architecture

```bash
python3 scripts/architecture_inventory.py . --output architecture.json
```

This inventories framework/auth/database/cloud/worker/storage/security signals and gives the AI agent evidence to investigate.

The inventory intentionally labels many architectural recommendations as `review-needed`. For example, MFA may be enforced by Auth0 or another IdP outside the repository, so absence from source is not proof that MFA is missing.

### 2. Audit a repository

```bash
./agentsec repo .
```

AgentSec checks the dependency/supply-chain surface, sensitive artifacts and available static/security scanners.

For conservative package-manager remediation:

```bash
./agentsec repo . --fix
```

AgentSec will **not** automatically use `npm audit fix --force`.

### 3. Audit the local Linux server

```bash
./agentsec server --local
```

The host audit is read-only. It reviews patch state, listening services, firewall/SSH configuration, permissions, web roots, Docker exposure, databases/admin ports, cron/systemd and Lynis output where available.

### 4. Audit an authorized server externally

```bash
./agentsec server --target server.example.com --authorized
```

This reviews the exposed network/service surface. For configuration-level findings, run the local host audit on the server as well.

### 5. Audit an authorized web app

```bash
./agentsec web https://staging.example.com --authorized
```

For explicitly authorized active SQLi/XSS validation:

```bash
./agentsec web https://staging.example.com --authorized --active
```

Active validation is deliberately opt-in.

## Architecture-aware security review

The skill instructs the coding agent to build an application security model before blindly recommending controls.

It identifies:

- public and internal entry points
- users, admins and service identities
- databases, queues, caches and object storage
- webhooks and third-party integrations
- CI/CD and deployment identities
- privilege boundaries
- sensitive or irreversible actions

Then it evaluates opportunities such as:

### Principle of least privilege

AgentSec looks beyond user roles. It asks whether:

- the runtime database user needs schema-owner rights
- a worker needs access to every table/bucket
- CI needs write/admin permissions
- a cloud IAM role can be narrowed
- API/OAuth tokens have excess scopes
- admins and ordinary users are enforced differently on the server

### MFA and step-up authentication

If authentication and privileged/high-impact actions exist, AgentSec evaluates whether MFA, passkeys or step-up authentication would materially reduce risk.

It first checks whether an external identity provider may already provide the control. It should never claim "no MFA" based on source code alone when the IdP configuration is unavailable.

### Cloudflare-aware hardening

When AgentSec detects Cloudflare/Wrangler, it considers:

- Managed WAF rules
- route-specific rate limits
- login/signup/reset/API abuse protection
- Turnstile for abuse-sensitive forms
- bot protection where relevant
- Full (strict) origin TLS
- origin firewall restrictions and Authenticated Origin Pulls
- caching only where responses are safe to share
- explicit cache bypass for personalized or authorization-sensitive responses

Cloudflare is treated as defense in depth. It does not replace application authorization, parameterized queries or correct output encoding.

### Directory enumeration resistance

AgentSec assumes routes can be guessed or enumerated.

If Gobuster/ffuf discovers a sensitive path, the remediation is to:

1. remove sensitive artifacts from the public web root when possible
2. disable directory indexing
3. require authentication and server-side authorization for protected paths
4. deny accidental dotfiles/backups/logs where appropriate
5. fix deployment scripts that keep publishing sensitive files
6. verify alternate routes/hosts do not expose the same resource

Renaming `/admin` or hiding a path in `robots.txt` is not considered a security fix.

## robots.txt, llms.txt and security.txt

AgentSec understands the distinction:

- **`robots.txt`** manages crawler behavior. It is not access control.
- **`llms.txt`** is an optional emerging convention for presenting public site information to AI agents. It is not access control.
- **`/.well-known/security.txt`** can provide a clear vulnerability-disclosure contact for public projects.

AgentSec may recommend these as operational improvements, but it will not inflate a missing `robots.txt` or `llms.txt` into a vulnerability.

## Reports

New AgentSec runs write to:

```text
.agentsec/reports/<scope>-<timestamp>/
```

Each run contains raw tool output plus `summary.json` and `summary.md` so both humans and agents can inspect exactly what was executed.

Audit output is gitignored because it may contain sensitive information.

## Finding types

AgentSec distinguishes:

- **Confirmed vulnerability**: evidence demonstrates an unsafe condition.
- **Security design gap**: architecture shows a missing/weak control with concrete risk.
- **Security opportunity**: defense-in-depth, resilience or operational hardening.
- **Review needed**: repo evidence suggests a possible gap but external/runtime configuration must be checked.

That distinction is intentional. Security tooling becomes much less useful when every recommendation is painted red.

## Knowledge base

The skill progressively loads references for the task at hand:

- [`references/architecture-security.md`](references/architecture-security.md)
- [`references/repository-security.md`](references/repository-security.md)
- [`references/web-security.md`](references/web-security.md)
- [`references/server-security.md`](references/server-security.md)
- [`references/remediation.md`](references/remediation.md)

This keeps the primary `SKILL.md` small enough for agent context while retaining deeper security guidance when needed.

## Safety model

AgentSec is designed for defensive development and authorized assessment.

Remote enumeration requires explicit authorization in the CLI. More intrusive SQLi/XSS validation requires both:

```text
--authorized --active
```

The skill explicitly avoids credential attacks, persistence, destructive exploitation, data theft, denial-of-service tests and post-exploitation workflows.

## Project direction

Planned areas for AgentSec include:

- richer framework-specific audit modules
- cloud/IaC posture analysis
- GitHub Actions security checks
- SBOM generation and dependency provenance analysis
- security regression tests generated from confirmed findings
- SARIF output for CI/code-scanning integrations
- richer architecture diagrams and threat models
- automated, reviewable remediation patches

## License

MIT
