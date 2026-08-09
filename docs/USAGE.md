# AgentSec Usage

## Core commands

```text
agentsec repo <path> [--fix]
agentsec server --local
agentsec server --target <host> --authorized
agentsec web <url> [--authorized] [--active]
agentsec url <url> [--authorized] [--active]
agentsec --version
agentsec update [--global|--local]
```

Use `./agentsec --help` for the current CLI help.

## Repository audit

```bash
./agentsec repo .
```

A repository audit should combine:

- architecture inventory
- sensitive artifact discovery
- dependency and supply-chain checks
- static-analysis tools when installed
- deployment and configuration review
- agent reasoning over the actual source and configuration

The scanner output is evidence. The coding agent should correlate it with the repository before declaring a finding confirmed.

### Dependency remediation

```bash
./agentsec repo . --fix
```

`--fix` allows conservative package-manager remediation where implemented. For npm projects, AgentSec may run a normal `npm audit fix`, followed by available tests/build scripts. It does not automatically use `npm audit fix --force`.

## Architecture inventory

```bash
python3 scripts/architecture_inventory.py . --output architecture.json
```

The inventory is designed to help the agent locate likely security boundaries and controls. It detects signals rather than asserting complete runtime truth.

Examples of signal groups include:

- authentication and authorization
- databases and ORMs
- queues and workers
- object storage
- Redis/caches
- Cloudflare/Wrangler
- payments
- webhooks
- GraphQL
- Terraform/IaC
- CSP and CSRF controls

The next step is source review and threat modeling.

## Local server audit

```bash
./agentsec server --local
```

The local server audit is intended to be read-only. It reviews host-level configuration and exposure such as:

- OS and package state
- listening TCP/UDP services
- SSH policy
- firewall state
- privileged files/binaries
- file permissions
- cron and systemd
- Docker configuration
- web server configuration
- public web roots
- databases and cache services
- Lynis output when available

Do not automatically modify server configuration based solely on a heuristic. Confirm service ownership, application requirements and recovery access before applying hardening changes.

## Remote server exposure

```bash
./agentsec server --target server.example.com --authorized
```

This is for an authorized external view of a server's attack surface. It cannot replace a local configuration audit because many host controls are not visible externally.

## Web application audit

Baseline:

```bash
./agentsec web https://staging.example.com --authorized
```

`url` is an alias for `web`:

```bash
./agentsec url https://staging.example.com --authorized
```

Recommended coding-agent prompt:

```text
This is my website: https://example.com. Take a look at misconfigurations and perform an overall security audit. Look for vulnerabilities we can patch and hardening opportunities.
```

The baseline audit records HTTP/TLS headers, safe service evidence, public exposure checks and available defensive scanners. When a local application repository is available, correlate the URL findings with source/configuration before proposing a patch. Treat DNS, CDN, WAF, hosting and server-provider changes as deployment work rather than silently editing application code.

The baseline can combine HTTP/TLS/header review, public metadata checks, safe service discovery, directory/path exposure checks, Nikto, ZAP baseline and related evidence.

## Active validation

```bash
./agentsec web https://staging.example.com --authorized --active
```

Active validation is deliberately opt-in. The goal is controlled confirmation of defensive findings on an authorized target, not exploitation for persistence or access.

For a fast, bounded web review that produces actionable black-box observations,
use `--authorized --baseline-only`. AgentSec checks response headers, CORS,
cookies, crawler/security contact files, common sensitive paths, SPA soft-404s,
technology/API indicators, and explicitly marks database security as requiring
source/provider review when it cannot be observed remotely.

## Directory exposure workflow

If Gobuster or ffuf finds a path:

1. confirm whether the resource exists
2. determine whether it is intended to be public
3. inspect authentication and authorization
4. check for directory listing
5. inspect the deployment path that created it
6. remove sensitive artifacts from the served tree where possible
7. deny unsafe file classes where appropriate
8. retest alternate hosts and routes

Do not treat an obscure filename as a control.

## Cloudflare-aware review

When Cloudflare is present, AgentSec should determine which controls are appropriate for the architecture rather than recommending every product feature.

Potential review areas:

- managed WAF coverage
- rate limits for auth and API abuse
- Turnstile on abuse-sensitive user flows
- bot controls where relevant
- TLS mode and certificate validation
- origin exposure and direct-origin bypass
- Authenticated Origin Pulls where appropriate
- cache rules for authenticated content
- public R2/bucket configuration

## Finding format

A useful AgentSec finding should contain:

```text
Title
Class: confirmed vulnerability | design gap | opportunity | review needed
Severity: critical | high | medium | low | informational
Confidence: high | medium | low
Affected component
Evidence
Why it matters
Root cause
Recommended remediation
Verification plan
```

When an agent implements the remediation, it should also report changed files and tests/checks run.

## Example prompts

```text
Use AgentSec to audit this repo. Start by mapping architecture and trust boundaries. Give me confirmed vulnerabilities first, then design gaps and opportunities.

For a complete audit response, always report the tested coverage and limitations:
which dependency, secret, SAST, web, architecture, authentication,
authorization, database, storage, CI/CD, cloud/edge, and exposed-path checks
actually ran. A clean exit code is not proof that untested controls are safe.
```

```text
Use AgentSec to review this Node/Next.js application for vulnerable npm dependencies, secrets, auth problems, XSS/SQLi/SSRF exposure, least-privilege gaps and Cloudflare hardening opportunities. Implement safe fixes and retest.
```

```text
Use AgentSec to review this Linux host and application deployment. Do not change server configuration until you show me the evidence, impact and rollback plan for each proposed hardening change.
```
