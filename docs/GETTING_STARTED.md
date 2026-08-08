# Getting Started with AgentSec

AgentSec is an Agent Skills-compatible defensive security engineering toolkit. It gives coding agents a repeatable way to understand an application's architecture, audit its code and dependencies, inspect server and web exposure, propose security improvements, implement defensive fixes, and verify the result.

## 1. Install the skill

For a global install across supported coding agents:

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec --agent '*' -g -y
```

For Claude Code, Codex and Cursor only:

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec -g -a claude-code -a codex -a cursor -y
```

## 2. Give your agent a security task

Examples:

```text
Use AgentSec to audit this repository and give me the highest-impact fixes first.
```

```text
Use AgentSec to review the architecture for least-privilege problems, privileged account MFA opportunities, database exposure, Cloudflare hardening, and dependency risk.
```

```text
Use AgentSec to audit this application, implement safe fixes for confirmed findings, run the tests, and rerun the relevant security checks.
```

The skill should first understand the application and evidence available. It should not start by blindly launching every scanner.

## 3. Run the repository audit directly

From an AgentSec checkout:

```bash
./agentsec repo .
```

The audit records results under:

```text
.agentsec/reports/
```

If optional scanners are missing, AgentSec records them as unavailable and continues with the checks it can perform.

## 4. Build an architecture inventory

```bash
python3 scripts/architecture_inventory.py . --output architecture.json
```

This is a lightweight evidence map for the agent. It looks for signals such as frameworks, authentication providers, databases, queues, workers, object storage, CI, Cloudflare, payments, webhooks and common security controls.

The inventory is not a final verdict. It helps the agent decide where to investigate.

## 5. Audit a Linux host

Local host inspection:

```bash
./agentsec server --local
```

External exposure of an authorized host:

```bash
./agentsec server --target server.example.com --authorized
```

Use the local host audit when you need configuration-level findings such as SSH policy, firewall state, permissions, Docker exposure or web-root hygiene.

## 6. Audit a web application

Baseline authorized audit:

```bash
./agentsec web https://staging.example.com --authorized
```

Controlled active validation:

```bash
./agentsec web https://staging.example.com --authorized --active
```

The `--active` flag is deliberately separate. It is intended for systems you own or are explicitly authorized to assess.

## 7. Understand the output

AgentSec distinguishes four classes of result:

- **Confirmed vulnerability**: direct evidence demonstrates an unsafe condition.
- **Security design gap**: the architecture shows a concrete weakness or missing control.
- **Security opportunity**: defense-in-depth or resilience could be improved.
- **Review needed**: the repository suggests a possible issue, but external or runtime configuration must be checked.

This keeps an absent source-code signal from being mislabeled as a confirmed vulnerability. For example, MFA may be enforced by an external identity provider.

## 8. Remediate and retest

A proper AgentSec workflow is:

```text
DISCOVER -> MODEL -> AUDIT -> VERIFY -> REMEDIATE -> RETEST
```

After a fix, rerun the smallest relevant security check plus the application's normal tests. Record anything that remains unverified.

## Next reading

- [Installation](INSTALLATION.md)
- [Usage](USAGE.md)
- [Architecture](ARCHITECTURE.md)
- [Security Concepts](SECURITY_CONCEPTS.md)
- [Remediation Guide](REMEDIATION_GUIDE.md)
