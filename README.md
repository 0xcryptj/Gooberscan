# Install AgentSec

**Open your coding agent and paste this command:**

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec --agent '*' -g -y
```

**That's it.** AgentSec is now available to supported coding agents. Try:

```text
Use AgentSec to audit this project, explain the biggest security risks, and propose the simplest safe fixes.
```

<p align="center">
  <img src="assets/agentsec-hero.webp" alt="AgentSec - Spy on threats. Secure everything." width="100%" />
</p>

<h1 align="center">AgentSec</h1>
<p align="center"><strong>Your senior security engineer for AI-built software.</strong></p>

<p align="center">
  AgentSec helps AI coding agents review a project like an experienced security engineer. It finds security mistakes, explains what actually matters, tells the agent how the code or configuration should change, and helps verify the fix.
</p>

<p align="center">
  <a href="docs/GETTING_STARTED.md">Docs</a> ·
  <a href="docs/QUICKSTART.md">Quick Start</a> ·
  <a href="#what-it-does">What it does</a> ·
  <a href="#advanced">Advanced</a> ·
  <a href="docs/USAGE.md">Usage</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" />
  <img alt="MIT License" src="https://img.shields.io/badge/License-MIT-555" />
  <a href="https://github.com/0xcryptj/AgentSec/actions/workflows/agentsec-ci.yml"><img alt="Build" src="https://github.com/0xcryptj/AgentSec/actions/workflows/agentsec-ci.yml/badge.svg" /></a>
  <img alt="Agent Skills" src="https://img.shields.io/badge/Agent%20Skills-Compatible-555" />
  <img alt="Security First" src="https://img.shields.io/badge/Security-First-b91c1c" />
</p>

> [!IMPORTANT]
> AgentSec is for defensive development and authorized security assessment. Only scan systems you own or have permission to test.

---

## What it does

AgentSec is designed for **vibe-coded and AI-assisted projects** where software can move faster than the security review around it.

Think of it as giving your coding agent a senior security engineer to consult while it works.

<table>
<tr>
<td width="50%" valign="top">

### 🔍 Reviews what you built
Looks at your code, packages, app architecture, server setup, cloud configuration, and exposed surfaces.

### 🧠 Understands before judging
Builds a lightweight picture of how the project works before throwing security recommendations at it.

### 🛡️ Catches easy-to-miss mistakes
Looks for exposed secrets, overly powerful accounts, weak authorization, unsafe queries, vulnerable packages, public backups, risky server settings, and similar problems.

### 📦 Watches the supply chain
Checks current package advisories and can identify vulnerable or known-malicious npm dependencies that are actually present in the project.

</td>
<td width="50%" valign="top">

### 🛠️ Tells your agent how to fix it
Gives concrete, stack-appropriate rewrite and configuration guidance instead of vague advice like "sanitize your input."

### ✅ Verifies the fix
Reruns the relevant security check and normal tests when possible so "fixed" means more than changing a line and hoping.

### 🌐 Reviews your assets too
Can audit local Linux servers, authorized web apps, network exposure, Cloudflare protections, CI/CD, and deployment configuration.

### 🤖 Built for coding agents
Works as an Agent Skill for Claude Code, Codex, Cursor, GitHub Copilot, and other compatible clients.

</td>
</tr>
</table>

---

## The rule: KISS

**KISS means Keep It Simple, Stupid.**

AgentSec's first architecture rule is that security should be **strong without becoming obscure, brittle, or painful to use**.

Good security is usually boring in the best way:

- secure defaults instead of 30 optional switches
- least privilege instead of one god-mode credential
- server-side authorization instead of hiding `/admin`
- parameterized database queries instead of clever filtering
- standard cryptography instead of home-grown crypto
- a few meaningful rate limits instead of a maze of arbitrary rules
- removing a leaked backup instead of renaming it and hoping nobody finds it
- small, reviewable security changes instead of rewriting half the application without evidence

AgentSec can recommend sophisticated controls when the threat actually justifies them. Complexity itself is **not** treated as security.

---

## Using AgentSec

Once the skill is installed, the normal workflow is simply to talk to your coding agent:

```text
Use AgentSec to audit this repo. Start with the architecture, find the important security problems, and explain the fixes in plain English.
```

```text
Use AgentSec to review authentication and authorization. Tell me where least privilege or MFA would materially improve security.
```

```text
Use AgentSec to check our dependencies for vulnerable or compromised packages and safely fix the high-confidence issues.
```

```text
Use AgentSec to review this project, implement the safe high-priority fixes, and retest them.
```

The CLI can also be run directly:

```bash
./agentsec repo .
./agentsec server --local
./agentsec web https://staging.example.com --authorized
```

---

## Advanced

This is where AgentSec gets more technical.

### 🧠 Token-efficient repository reading

AgentSec does **not** tell the LLM to read every file in a repository.

It uses progressive review:

1. inspect the repo tree, manifests, lockfiles, framework configuration, routes, auth, database schema, CI, deployment, and infrastructure files
2. build a compact map of entry points, identities, trust boundaries, sensitive assets, and privileged actions
3. prioritize high-risk paths such as authentication, authorization, admin APIs, database access, command execution, uploads, payments, secrets, IAM, and deployment
4. use scanners, dependency graphs, search, and architecture evidence to decide what source needs deeper reading
5. keep generated/vendor trees such as `node_modules`, `.git`, `.venv`, `dist`, `build`, and `.next` out of the context unless evidence points there

See [`references/repo-reading.md`](references/repo-reading.md).

### 🛰️ Fresh security intelligence

Static prompts get old. A normal repository audit now refreshes **repository-specific** intelligence before running the deterministic checks.

AgentSec currently supports:

- GitHub Advisory Database malware advisories for npm packages actually present in the repository
- GitHub-reviewed vulnerability advisories for those packages
- ClamAV malware signature refresh through `freshclam` when ClamAV is installed
- ecosystem scanners such as `npm audit`, OSV-Scanner, Trivy, Semgrep, Gitleaks, pip-audit, and cargo-audit when available

The cache lives under `.agentsec/intel/`. AgentSec intentionally does not pour entire malware and vulnerability feeds into the LLM's context window. It stores the data and reads the records relevant to the repository or finding being investigated.

If current intelligence cannot be refreshed, AgentSec should say so instead of pretending cached data is current.

### Application security

AgentSec can reason about:

- SQL injection and unsafe database access
- XSS and output encoding
- SSRF and unsafe outbound requests
- command injection and path traversal
- CSRF, IDOR, broken authorization, and session weaknesses
- unsafe uploads, weak cryptography, and secret handling
- CORS, CSP, cookies, recovery flows, and security headers

### Architecture and least privilege

It looks for opportunities such as:

- narrowing database permissions
- separating runtime and migration/admin database identities
- limiting worker and service-account access
- reducing CI/CD and cloud IAM permissions
- narrowing OAuth/API scopes
- protecting tenant and object boundaries
- separating privileged operations from ordinary user paths

### Identity

For sensitive or high-impact actions it can evaluate:

- MFA
- passkeys / WebAuthn
- step-up authentication
- session lifetime and rotation
- account recovery abuse
- privileged account separation

If MFA or another control may exist in an external identity provider, AgentSec marks it **review needed** instead of claiming it is missing from source code alone.

### Cloudflare and edge security

When Cloudflare is detected, AgentSec can reason about:

- managed WAF rules
- route-specific rate limits
- Turnstile for abuse-sensitive forms
- Full (strict) TLS
- origin protection and direct-origin bypass
- Authenticated Origin Pulls where appropriate
- safe caching boundaries
- cache bypass for personalized or authorization-sensitive responses

### Server and exposure review

AgentSec can use deterministic tools for areas such as:

- Linux patch state
- SSH and firewall configuration
- listening services and unnecessary ports
- database/cache exposure
- Docker privileges and socket access
- Nginx/Apache configuration
- sensitive files under public web roots
- Nmap service discovery
- Gobuster/ffuf path discovery
- Nikto and OWASP ZAP checks

Active web testing remains explicit and authorized:

```bash
./agentsec web https://staging.example.com --authorized --active
```

---

## Finding quality

AgentSec separates findings so everything does not turn into a red siren:

| Class | Meaning |
| --- | --- |
| **Confirmed vulnerability** | Evidence shows an unsafe condition. |
| **Security design gap** | The architecture has a concrete weakness or missing control. |
| **Security opportunity** | A practical defense-in-depth improvement would reduce risk. |
| **Review needed** | Something may be wrong, but runtime/provider configuration or more evidence is required. |

`robots.txt` and `llms.txt` are crawler/discoverability files, not access control. A missing file is not treated as a vulnerability. `security.txt` is treated as a useful operational disclosure control.

---

## Documentation

| Document | What it covers |
| --- | --- |
| [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) | First audit and basic concepts |
| [`docs/QUICKSTART.md`](docs/QUICKSTART.md) | Fastest setup path |
| [`docs/INSTALLATION.md`](docs/INSTALLATION.md) | Installation and optional tools |
| [`docs/USAGE.md`](docs/USAGE.md) | Commands, modes, and examples |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How AgentSec is structured |
| [`docs/SECURITY_CONCEPTS.md`](docs/SECURITY_CONCEPTS.md) | Deeper security concepts |
| [`docs/REMEDIATION_GUIDE.md`](docs/REMEDIATION_GUIDE.md) | How fixes should be applied and verified |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Extending and contributing |

---

## Reports

Audit evidence is stored under:

```text
.agentsec/reports/<scope>-<timestamp>/
```

Fresh intelligence is cached under:

```text
.agentsec/intel/
```

Generated audit output is gitignored because it may contain sensitive information.

---

## Security and contributions

Read [SECURITY.md](SECURITY.md) for disclosure and scope boundaries. Contributions are welcome through [CONTRIBUTING.md](CONTRIBUTING.md).

<p align="center"><strong>Audit. Reason. Remediate. Verify.</strong></p>
