<p align="center">
  <img src="assets/agentsec-banner.jpg" alt="AgentSec - Spy on threats. Secure everything." width="100%" />
</p>

<h1 align="center">AgentSec</h1>
<p align="center"><strong>Agentic Security Auditing &amp; Remediation</strong></p>

<p align="center">
  AgentSec is an open-source security engineering skill and toolkit for AI coding agents. It audits applications, repositories, web surfaces, Linux servers, dependencies, architecture, identity, and deployment configuration, then helps reason about and implement defensive fixes.
</p>

<p align="center">
  <a href="docs/GETTING_STARTED.md">Docs</a> ·
  <a href="docs/QUICKSTART.md">Quick Start</a> ·
  <a href="#features">Features</a> ·
  <a href="docs/INSTALLATION.md">Installation</a> ·
  <a href="docs/USAGE.md">Usage</a> ·
  <a href="docs/ARCHITECTURE.md">Architecture</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="LICENSE">License</a>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" />
  <img alt="MIT License" src="https://img.shields.io/badge/License-MIT-555" />
  <a href="https://github.com/0xcryptj/AgentSec/actions/workflows/agentsec-ci.yml"><img alt="Build" src="https://github.com/0xcryptj/AgentSec/actions/workflows/agentsec-ci.yml/badge.svg" /></a>
  <img alt="Agent Skills" src="https://img.shields.io/badge/Agent%20Skills-Compatible-555" />
  <img alt="Security First" src="https://img.shields.io/badge/Security-First-b91c1c" />
</p>

> [!IMPORTANT]
> AgentSec is for defensive development and authorized security assessment. Only scan remote systems you own or are explicitly permitted to assess. Active web validation is opt-in.

---

## Features

<table>
<tr>
<td width="50%" valign="top">

✅ <strong>Application Security</strong> - OWASP-oriented review for injection, XSS, SSRF, CSRF, IDOR, auth/session flaws, unsafe uploads, and more.<br><br>
✅ <strong>Server &amp; Infrastructure Audits</strong> - Linux patch state, SSH, firewall, listeners, permissions, Docker, databases, web roots, and Lynis.<br><br>
✅ <strong>Network Scanning &amp; Enumeration</strong> - Authorized Nmap service discovery and defensive surface review.<br><br>
✅ <strong>Cloud &amp; Misconfiguration Checks</strong> - Cloudflare, edge controls, public exposure, TLS, caching boundaries, and deployment mistakes.<br><br>
✅ <strong>Supply Chain Security</strong> - npm advisories, dependency trees, package signatures, lockfiles, install scripts, OSV, Trivy, pip-audit, cargo-audit.<br><br>
✅ <strong>Secrets &amp; Sensitive Data Detection</strong> - credentials, keys, environment files, backups, database dumps, and deployment artifacts.

</td>
<td width="50%" valign="top">

✅ <strong>Threat Modeling &amp; Architecture Analysis</strong> - trust boundaries, identities, data flows, service separation, tenant isolation, and blast radius.<br><br>
✅ <strong>Principle of Least Privilege Advisor</strong> - database roles, workers, CI tokens, cloud IAM, OAuth/API scopes, and privileged paths.<br><br>
✅ <strong>Automated Remediation &amp; Hardening</strong> - conservative code/config fixes with focused verification and regression checks.<br><br>
✅ <strong>Directory / Path Exposure Discovery</strong> - Gobuster and ffuf findings are treated as deployment and access-control problems, not obscurity problems.<br><br>
✅ <strong>MFA / Passkey / Step-up Review</strong> - evaluates privileged workflows without falsely assuming external IdP controls are absent.<br><br>
✅ <strong>AI Agent Compatible</strong> - designed for Claude Code, Codex, Cursor, GitHub Copilot, and Agent Skills-compatible clients.

</td>
</tr>
</table>

---

## 🚀 Quick Start

### One-line install for coding agents

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec --agent '*' -g -y
```

### Repository audit

```bash
./agentsec repo .
```

### Repository audit with conservative fixes

```bash
./agentsec repo . --fix
```

### Local Linux server audit

```bash
./agentsec server --local
```

### Authorized remote server audit

```bash
./agentsec server --target server.example.com --authorized
```

### Authorized web audit

```bash
./agentsec web https://staging.example.com --authorized
```

### Explicitly authorized active validation

```bash
./agentsec web https://staging.example.com --authorized --active
```

---

## How AgentSec Works

```text
RECON  ->  MODEL  ->  ANALYZE  ->  VERIFY  ->  REMEDIATE  ->  RETEST
```

AgentSec combines deterministic security tools with architecture-aware reasoning. Scanner output is evidence, not a verdict. The agent is instructed to correlate findings with the code, configuration, runtime architecture, and external-provider boundaries before assigning severity or making changes.

<table>
<tr>
<td width="33%" align="center"><strong>🔍 AUDIT</strong><br><br>Application, server, network, cloud, dependencies, code</td>
<td width="33%" align="center"><strong>🕵️ THREAT MODEL</strong><br><br>Architecture, trust boundaries, identities, attack surface</td>
<td width="33%" align="center"><strong>🛡️ REMEDIATE</strong><br><br>Fix root causes, harden configuration, verify changes</td>
</tr>
</table>

### Security intelligence

AgentSec reasons about controls such as:

- least privilege for database users, workers, CI, cloud IAM, API keys, and service accounts
- MFA, passkeys, and step-up authentication for high-impact operations
- Cloudflare WAF, rate limiting, Turnstile, Full (strict) TLS, origin protection, and safe caching boundaries
- compromised or vulnerable npm and other ecosystem packages
- exposed directories, backups, dotfiles, source maps, logs, database dumps, and admin surfaces
- SQL injection, XSS, SSRF, path traversal, CSRF, IDOR, command injection, unsafe uploads, auth/session weaknesses, and secrets
- server hardening, SSH policy, firewalling, open services, Docker privilege, filesystem permissions, and database exposure

`robots.txt` and `llms.txt` are treated as crawler/discoverability policy, not access control. `security.txt` is treated as an operational disclosure control.

---

## 📖 Documentation

<table>
<tr>
<td width="50%" valign="top">

📘 <a href="docs/GETTING_STARTED.md"><strong>GETTING_STARTED.md</strong></a> - first steps and first audit<br><br>
⚡ <a href="docs/QUICKSTART.md"><strong>QUICKSTART.md</strong></a> - fastest install and usage path<br><br>
📦 <a href="docs/INSTALLATION.md"><strong>INSTALLATION.md</strong></a> - agent and scanner installation<br><br>
⌨️ <a href="docs/USAGE.md"><strong>USAGE.md</strong></a> - commands, flags, modes, examples

</td>
<td width="50%" valign="top">

🏗️ <a href="docs/ARCHITECTURE.md"><strong>ARCHITECTURE.md</strong></a> - system design and agent workflow<br><br>
🔐 <a href="docs/SECURITY_CONCEPTS.md"><strong>SECURITY_CONCEPTS.md</strong></a> - threat model and controls<br><br>
🛠️ <a href="docs/REMEDIATION_GUIDE.md"><strong>REMEDIATION_GUIDE.md</strong></a> - how fixes are applied and verified<br><br>
🧪 <a href="docs/DEVELOPMENT.md"><strong>DEVELOPMENT.md</strong></a> - extending and contributing

</td>
</tr>
</table>

---

## Reports

AgentSec writes audit evidence to:

```text
.agentsec/reports/<scope>-<timestamp>/
```

Each run preserves raw tool output plus `summary.json` and `summary.md`. Generated audit output is gitignored because it may contain sensitive information.

---

## Agent Skill

The repository follows the shared `SKILL.md` Agent Skills format. `SKILL.md` contains the security-engineering behavior, while `scripts/` provides deterministic evidence collection and `references/` provides progressively loaded security playbooks.

```text
AgentSec/
├── SKILL.md
├── agentsec
├── scripts/
├── references/
├── docs/
├── tests/
├── SECURITY.md
└── CONTRIBUTING.md
```

---

## Security & Contributions

Read [SECURITY.md](SECURITY.md) for the disclosure policy and security boundaries. Contributions are welcome through [CONTRIBUTING.md](CONTRIBUTING.md).

<p align="center"><strong>Audit. Reason. Remediate. Verify.</strong></p>
