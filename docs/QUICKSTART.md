# AgentSec Quickstart

## Install in one line

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec --agent '*' -g -y
```

## Ask your coding agent

```text
Use AgentSec to audit this repository. Map the architecture first, then report confirmed vulnerabilities, security design gaps, security opportunities and anything that requires runtime verification. Implement safe fixes for confirmed issues and retest.
```

## Direct CLI

Repository:

```bash
./agentsec repo .
```

Local Linux server:

```bash
./agentsec server --local
```

Authorized remote server:

```bash
./agentsec server --target server.example.com --authorized
```

Authorized web application:

```bash
./agentsec web https://staging.example.com --authorized
```

Controlled active validation:

```bash
./agentsec web https://staging.example.com --authorized --active
```

## What to expect

AgentSec should:

1. understand the stack and architecture
2. map identities, data stores and trust boundaries
3. collect deterministic evidence
4. verify scanner findings against source/configuration
5. prioritize confirmed risk
6. propose or implement root-cause fixes
7. rerun tests and security checks
8. clearly identify anything it could not verify

## Useful follow-up prompts

```text
Focus on principle of least privilege across the database, workers, CI and cloud roles.
```

```text
Review authentication for MFA, passkeys, step-up auth, session risks and account recovery abuse.
```

```text
Review Cloudflare for WAF, rate limiting, Turnstile, origin protection and unsafe caching.
```

```text
Review npm dependencies for advisories, suspicious packages, install scripts, lockfile anomalies and compromised-package response.
```

```text
Audit public directories and routes as if they were enumerated with Gobuster or ffuf. Fix the exposure rather than relying on obscurity.
```

For the full workflow, continue with [Getting Started](GETTING_STARTED.md).
