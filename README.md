<p align="center">
  <img src="assets/agentsec-banner.jpg" alt="AgentSec project banner" width="100%" />
</p>

<h1 align="center">AgentSec</h1>
<p align="center"><strong>Agentic Security Auditing & Remediation</strong></p>
<p align="center">
  A portable security engineering skill for AI coding agents that can understand architecture, audit code and infrastructure, identify security design gaps, implement defensive fixes, and verify the result.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-white" />
  <img alt="Agent Skills" src="https://img.shields.io/badge/Agent%20Skills-Compatible-black" />
  <img alt="Security" src="https://img.shields.io/badge/Security-First-b91c1c" />
</p>

<p align="center">
  <a href="#quick-install-for-agents">Quick Install</a> ·
  <a href="#what-agentsec-does">Capabilities</a> ·
  <a href="#how-agentsec-thinks">Security Model</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#documentation">Documentation</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

> [!IMPORTANT]
> AgentSec is built for defensive development and authorized security assessment. Only scan remote systems you own or are explicitly permitted to assess. Active web validation is intentionally opt-in.

## Quick Install for Agents

Install AgentSec globally for every agent supported by the open `skills` CLI:

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec --agent '*' -g -y
```

That is the one-liner to give Claude Code, Codex, Cursor, GitHub Copilot, and other compatible coding agents.

Install only for a few agents:

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec -g -a claude-code -a codex -a cursor -y
```

Install into the current project instead of globally:

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec --agent '*' -y
```

Update later with:

```bash
npx skills update agentsec -y
```

See [`docs/QUICKSTART.md`](docs/QUICKSTART.md) for the shortest path or [`docs/INSTALLATION.md`](docs/INSTALLATION.md) for agent paths, local installation, troubleshooting, and scanner dependencies.

## What AgentSec Does

AgentSec is not just a wrapper around scanners. It combines deterministic security tools with architecture-aware reasoning so an AI coding agent can move through a full defensive loop:

```text
DISCOVER -> MODEL -> AUDIT -> VERIFY -> REMEDIATE -> RETEST
```

| Capability | What AgentSec looks for |
| --- | --- |
| Application security | SQL injection, XSS, SSRF, command injection, path traversal, CSRF, IDOR, unsafe uploads, weak crypto, auth/session problems |
| Architecture | trust boundaries, service identities, tenant isolation, privilege boundaries, data flows, irreversible operations |
| Least privilege | overpowered database users, workers, CI identities, cloud IAM roles, API tokens, admin paths, service accounts |
| Identity | MFA, passkeys, step-up auth, session controls, recovery flows, privileged account separation |
| Supply chain | vulnerable npm packages, malicious package signals, dependency trees, package signatures, lockfile integrity, install scripts |
| Secrets | credentials, keys, `.env` files, database dumps, backups, cloud tokens, logs and sensitive deployment artifacts |
| Web exposure | TLS, headers, CSP, CORS, exposed files, directory indexing, Gobuster/ffuf findings, Nikto, ZAP baseline |
| Server security | patch state, listeners, SSH, firewall, SUID/SGID, permissions, systemd/cron, Docker, web roots, database exposure |
| Cloud and edge | Cloudflare WAF, rate limits, Turnstile, origin lockdown, TLS mode, cache boundaries, public bucket exposure |
| CI/CD | token scope, workflow permissions, third-party actions, secret handling, deployment identity privilege |
| Operational security | `security.txt`, logging, auditability, incident readiness, crawler policy, public metadata |
| Remediation | targeted code/config fixes, regression tests, reruns of the relevant security checks |

## Why an Agent Skill

Traditional scanners answer questions like:

> Is port 5432 open?

AgentSec is designed to ask the next questions:

> Why is Postgres reachable from that network? Which service actually needs it? Can the application bind privately and use a narrower database role?

A package scanner may report a vulnerable transitive dependency. AgentSec should determine which direct dependency introduced it, whether a patched compatible path exists, whether the package executed install scripts, what credentials may have been exposed, and what must be retested after remediation.

A route scanner may discover `/backup.zip`. AgentSec should not recommend renaming it. It should remove the archive from the public web root, inspect the deployment process that put it there, disable directory indexing, verify authorization, and retest alternate routes and hosts.

## How AgentSec Thinks

Before recommending controls, AgentSec builds a lightweight security model of the application.

### 1. Map the architecture

It looks for:

- public clients and entry points
- APIs and server actions
- users, admins and service identities
- databases, queues, caches and object storage
- webhooks and third-party integrations
- workers and scheduled jobs
- CI/CD and deployment identities
- cloud/edge providers
- privileged and irreversible operations

The repository inventory is generated by:

```bash
python3 scripts/architecture_inventory.py . --output architecture.json
```

### 2. Identify trust boundaries

AgentSec asks where data or authority crosses boundaries, for example:

```text
Browser
  |
  v
Cloudflare edge
  |
  v
Application/API
  |       \
  v        v
Postgres   Worker
             |
             v
          Queue/R2
```

It then reviews whether each transition has the right authentication, authorization, validation, encryption, rate limiting, and observability.

### 3. Apply least privilege

AgentSec evaluates privilege at multiple layers:

- Does the runtime database user also own the schema?
- Can a background worker access tables or buckets it never needs?
- Does CI have write permissions when read-only would work?
- Are cloud IAM policies broader than the deployed service requires?
- Do API keys and OAuth tokens have excessive scopes?
- Are admin controls enforced server-side, not only in the UI?
- Can one compromised service identity reach unrelated systems?

### 4. Evaluate identity controls

When privileged or high-impact actions exist, AgentSec considers:

- MFA
- passkeys / WebAuthn
- step-up authentication
- session lifetime and rotation
- recovery flow abuse
- privileged account separation
- brute force and credential stuffing controls

Absence of MFA code in the repo is not automatically treated as proof that MFA is missing. External IdPs may enforce it. AgentSec labels uncertain cases as `review-needed` until runtime/provider configuration is checked.

### 5. Use existing infrastructure intelligently

If Cloudflare is detected, AgentSec can recommend and reason about:

- Managed WAF rules
- endpoint-specific rate limiting
- login, signup and password-reset abuse controls
- Turnstile on abuse-sensitive forms
- bot protections where appropriate
- Full (strict) TLS
- origin firewall restrictions
- Authenticated Origin Pulls where appropriate
- cache bypass for personalized or authorization-sensitive responses
- direct-origin bypass prevention

Cloudflare is defense in depth. AgentSec does not treat edge controls as a replacement for application authorization, parameterized queries, secure sessions, or output encoding.

## Finding Classes

AgentSec avoids painting every suggestion bright red.

| Class | Meaning |
| --- | --- |
| **Confirmed vulnerability** | Evidence demonstrates an unsafe condition. |
| **Security design gap** | The architecture has a concrete weakness or missing control. |
| **Security opportunity** | Defense-in-depth, resilience or operational hardening would reduce risk. |
| **Review needed** | Repo evidence suggests a possible gap, but runtime or provider configuration must be verified. |

## Usage

### Audit a repository

```bash
./agentsec repo .
```

The repository audit can use:

- npm audit
- npm dependency tree analysis
- npm package signature checks when supported
- OSV-Scanner
- Trivy
- Semgrep
- Gitleaks
- pip-audit
- cargo-audit
- sensitive artifact discovery
- architecture inventory

### Conservative dependency remediation

```bash
./agentsec repo . --fix
```

AgentSec deliberately does not run `npm audit fix --force` automatically.

### Audit the local Linux host

```bash
./agentsec server --local
```

The host audit is read-only and checks areas such as:

- patch state
- exposed listeners
- SSH settings
- firewall state
- SUID/SGID binaries
- sensitive file permissions
- systemd and cron surfaces
- Docker privileges and socket exposure
- web server configuration
- public document roots
- database and cache listeners
- Lynis results when installed

### Audit an authorized server externally

```bash
./agentsec server --target server.example.com --authorized
```

### Audit an authorized web application

```bash
./agentsec web https://staging.example.com --authorized
```

### Explicitly enable controlled active validation

```bash
./agentsec web https://staging.example.com --authorized --active
```

Active mode may run controlled SQL injection and web vulnerability validation using available tools such as sqlmap and OWASP ZAP. Credential attacks, persistence, destructive exploitation, data theft, denial-of-service testing and post-exploitation are outside AgentSec's workflow.

## Directory and Path Exposure

AgentSec assumes that routes can be guessed, crawled, indexed or enumerated.

When Gobuster or ffuf discovers a sensitive path, AgentSec's remediation model is:

1. Decide whether the resource should be public at all.
2. Remove sensitive artifacts from the served tree whenever possible.
3. Disable directory indexing.
4. Enforce authentication and server-side authorization on protected paths.
5. Deny accidental dotfiles, source-control metadata, backups and logs where appropriate.
6. Fix build/deployment scripts that publish sensitive files.
7. Check aliases, symlinks, alternate hosts and alternate routing.
8. Retest the path and verify the intended 401, 403 or 404 behavior.

Renaming `/admin`, hiding a route in `robots.txt`, or relying on an obscure URL is not considered a security fix.

## Supply Chain and Compromised Packages

For Node.js projects AgentSec reviews more than the advisory count.

It considers:

- direct and transitive dependency paths
- affected and patched versions
- unexpected new packages
- typosquatting and naming anomalies
- install and postinstall scripts
- package provenance/signatures when available
- lockfile churn
- package age and maintenance signals when relevant
- whether the package executes in CI, build or production
- what secrets or filesystem access the package could have reached

For remediation, AgentSec prefers:

1. upgrade the direct dependency introducing the vulnerable package
2. move to the nearest compatible patched version
3. use package-manager overrides only when necessary and tested
4. rerun build/tests
5. rerun the dependency audit
6. rotate credentials and inspect affected systems if a package is confirmed malicious

See [`docs/SECURITY_CONCEPTS.md`](docs/SECURITY_CONCEPTS.md) and [`references/repository-security.md`](references/repository-security.md).

## `robots.txt`, `llms.txt`, and `security.txt`

AgentSec keeps these concepts separate:

- `robots.txt` is crawler policy, not access control.
- `llms.txt` is optional public metadata for AI-oriented discovery, not access control.
- `/.well-known/security.txt` can provide a clear vulnerability disclosure contact.

A missing `robots.txt` or `llms.txt` may be an operational recommendation. It should not be presented as a vulnerability.

## Reports

Audit runs write to:

```text
.agentsec/reports/<scope>-<timestamp>/
```

Each run preserves raw tool output plus machine-readable and human-readable summaries so an agent can reason from evidence instead of silently discarding scanner details.

## Repository Layout

```text
AgentSec/
├── SKILL.md
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
├── agentsec
├── install-deps.sh
├── assets/
│   └── agentsec-banner.jpg
├── docs/
│   ├── QUICKSTART.md
│   ├── GETTING_STARTED.md
│   ├── INSTALLATION.md
│   ├── USAGE.md
│   ├── ARCHITECTURE.md
│   ├── SECURITY_CONCEPTS.md
│   ├── REMEDIATION_GUIDE.md
│   └── DEVELOPMENT.md
├── scripts/
│   ├── agentsec.py
│   ├── architecture_inventory.py
│   └── local_server_audit.sh
├── references/
│   ├── architecture-security.md
│   ├── repository-security.md
│   ├── web-security.md
│   ├── server-security.md
│   └── remediation.md
└── tests/
```

## Documentation

| Document | Purpose |
| --- | --- |
| [`docs/QUICKSTART.md`](docs/QUICKSTART.md) | One-line install and immediate commands/prompts |
| [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) | Five-minute introduction and first full audit |
| [`docs/INSTALLATION.md`](docs/INSTALLATION.md) | Agent installation, scanner dependencies and troubleshooting |
| [`docs/USAGE.md`](docs/USAGE.md) | Commands, modes, authorization flags and examples |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How AgentSec is structured and how agents consume it |
| [`docs/SECURITY_CONCEPTS.md`](docs/SECURITY_CONCEPTS.md) | Threat modeling, least privilege, identity, supply chain, edge and server concepts |
| [`docs/REMEDIATION_GUIDE.md`](docs/REMEDIATION_GUIDE.md) | How findings should be fixed and verified |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Extending AgentSec, tests, integrations and design rules |
| [`SECURITY.md`](SECURITY.md) | Responsible disclosure and project security policy |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Development and contribution workflow |

The deeper task-specific knowledge used by the skill lives under [`references/`](references/).

## Agent Compatibility

AgentSec follows the shared Agent Skills `SKILL.md` format. The open `skills` CLI supports installation into many coding agents from one source, including Claude Code, Codex, Cursor, GitHub Copilot and other compatible tools.

The skill is intentionally vendor-neutral. `SKILL.md` is the brain; the CLI and references are the evidence and playbooks.

## Design Principles

- **Reason before scanning.** Understand architecture and scope first.
- **Evidence before severity.** Scanner heuristics are not automatically confirmed vulnerabilities.
- **Least privilege by default.** Reduce blast radius across users, services, databases, CI and cloud roles.
- **Fix root causes.** Do not hide scanner results or rely on obscurity.
- **Preserve behavior.** Security changes should be minimal, reviewable and tested.
- **Verify fixes.** Rerun the relevant security check and normal project tests.
- **Use defense in depth.** Edge, app, host and data-layer controls should reinforce each other.
- **Respect scope.** Remote active testing requires explicit authorization.

## Project Direction

Planned development areas include:

- framework-specific AppSec playbooks for Next.js, React, Express/Fastify, Prisma/Postgres, Supabase and common auth providers
- richer Cloudflare, AWS and infrastructure-as-code review
- GitHub Actions and CI privilege analysis
- SBOM generation and provenance analysis
- SARIF output for code-scanning platforms
- security regression tests generated from confirmed findings
- architecture diagrams and threat models generated from repository evidence
- reviewable remediation patches with verification results

## Contributing

Contributions are welcome, especially defensive checks, framework-specific hardening guidance, tests, false-positive reductions and documentation improvements.

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a PR.

## License

AgentSec is released under the [MIT License](LICENSE).

<p align="center"><strong>Audit. Reason. Remediate. Verify.</strong></p>
