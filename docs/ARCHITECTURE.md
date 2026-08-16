# AgentSec Architecture

AgentSec is deliberately split into three layers:

```text
AI coding agent
      |
      v
   SKILL.md
      |
      +--------------------+
      |                    |
      v                    v
security references     AgentSec CLI
      |                    |
      v                    v
reasoning/playbooks     deterministic tools
      |                    |
      +---------+----------+
                |
                v
evidence + findings
                |
                v
          remediation
                |
                v
retest
```

Every audit run also produces a normalized `findings.json` review queue. This
queue contains evidence that needs agent or human correlation; it deliberately
does not turn scanner exit codes into confirmed vulnerabilities.

## Layer 1: `SKILL.md`

`SKILL.md` is the portable agent-facing control plane. It tells a compatible coding agent when to use AgentSec and how to behave during a security task.

The skill defines:

- scope and authorization behavior
- repository audit workflow
- architecture/threat-model workflow
- server audit workflow
- web audit workflow
- evidence and finding classifications
- remediation rules
- output expectations

The skill should remain concise enough to load efficiently.

## Layer 2: Progressive references

The deeper security knowledge lives under `references/` and is loaded when relevant.

```text
references/
├── architecture-security.md
├── repository-security.md
├── web-security.md
├── server-security.md
└── remediation.md
```

This progressive-disclosure approach prevents every security concept from consuming agent context on every request.

## Layer 3: Deterministic execution

The `agentsec` CLI coordinates deterministic checks and preserves raw output.

```text
agentsec
  -> scripts/agentsec.py
       -> repository checks
       -> web checks
       -> server checks
       -> external scanners when available
       -> .agentsec/reports/
```

Architecture signals are collected by:

```text
scripts/architecture_inventory.py
```

Local Linux host checks are collected by:

```text
scripts/local_server_audit.sh
```

## Why separate reasoning from tools

Security scanners are strongest at deterministic evidence collection. Coding agents are strongest at connecting that evidence to architecture, source code and intended behavior.

AgentSec keeps those responsibilities separate:

### Scanner responsibility

- identify a dependency advisory
- enumerate a listening service
- show a missing header
- discover an exposed path
- report a suspicious source pattern
- preserve exact output

### Agent responsibility

- decide whether the finding is real
- locate the root cause
- determine architecture impact
- distinguish vulnerability from hardening opportunity
- propose a safe fix
- implement the fix when requested
- run tests and security verification

## Repository audit data flow

```text
Repository
   |
   +--> architecture inventory
   |
   +--> sensitive artifact scan
   |
   +--> package ecosystem checks
   |
   +--> optional SAST/SCA/secrets tools
   |
   v
.agentsec/reports/<run>/
   |
   +--> summary.json / summary.md
   +--> findings.json (unconfirmed review queue)
   +--> findings.sarif
   +--> raw scanner output
   +--> run.json / events.jsonl / agents.json
   |
   v
AI agent correlates evidence with source/config
   |
   v
prioritized findings + fixes + verification
```

`agentsec view` renders one run locally without a frontend build step. The
viewer binds to loopback, requires a random URL token, rejects path traversal,
escapes report content, and serves no external resources.

## Web audit data flow

```text
Authorized URL
   |
   +--> headers / metadata
   +--> service and TLS checks
   +--> path exposure enumeration
   +--> passive web scanners
   |
   +--> optional active validation
           only with --authorized --active
   |
   v
preserved evidence
```

## Server audit data flow

Local:

```text
Linux host
   |
   +--> package/patch state
   +--> sockets/listeners
   +--> SSH/firewall
   +--> permissions/SUID
   +--> systemd/cron
   +--> Docker
   +--> web server/web roots
   +--> database/cache exposure
   +--> Lynis when available
```

Remote:

```text
Authorized server
   |
   +--> externally visible services
   +--> version/TLS/network evidence
```

The remote view should not be mistaken for complete host hardening coverage.

## Architecture inventory philosophy

`architecture_inventory.py` detects evidence, not certainty.

For example:

- Auth0 references indicate an external IdP may exist.
- Cloudflare/Wrangler files indicate edge controls may exist.
- `admin` routes indicate privileged actions probably exist.
- Prisma/Postgres references indicate a database boundary exists.

The coding agent must then inspect how the component is actually configured and used.

This is why AgentSec supports a `review-needed` finding class.

## Security control graph

A useful way to reason about AgentSec is as a graph of identities, resources and boundaries.

```text
Identity
  |
  | permissions
  v
Service
  |
  | protocol / API / query
  v
Resource
```

For each edge, AgentSec asks:

- Is authentication required?
- Is authorization enforced server-side?
- Is privilege narrower than necessary?
- Is untrusted input validated?
- Is output encoded for its context?
- Is transport protected?
- Can abuse be rate-limited?
- Is the action auditable?
- What happens if this identity is compromised?

## Extension model

New security knowledge should usually be added in one of three places:

1. `references/` for reasoning/checklists
2. `scripts/` for deterministic evidence collection
3. `tests/` for behavior and false-positive prevention

Avoid turning `SKILL.md` into a giant encyclopedia.

## Safety boundary

Repository review and local defensive inspection are the default.

Remote active testing is intentionally gated. The skill and CLI should not be modified to silently bypass authorization controls.
