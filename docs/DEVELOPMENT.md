# AgentSec Development

This guide is for contributors extending AgentSec itself.

## Design goals

AgentSec should remain:

- portable across coding agents
- evidence-driven
- defensive by default
- architecture-aware
- conservative with destructive or high-impact changes
- easy to install
- easy to extend with new security knowledge

## Local checks

Python syntax:

```bash
python3 -m py_compile scripts/agentsec.py scripts/architecture_inventory.py
```

Shell syntax:

```bash
bash -n agentsec
bash -n install-deps.sh
bash -n scripts/local_server_audit.sh
```

Tests:

```bash
python3 -m unittest discover -s tests -v
```

CLI smoke test:

```bash
python3 scripts/agentsec.py --help
python3 scripts/architecture_inventory.py . --output /tmp/agentsec-architecture.json
```

## Skill architecture

AgentSec uses progressive disclosure:

- `SKILL.md` contains core behavior and routing
- `references/` contains deeper security playbooks
- `scripts/` collects deterministic evidence
- `docs/` explains the project to humans

Keep `SKILL.md` focused. Framework-specific or detailed knowledge should live in references so it is loaded only when useful.

## Adding a framework module

A framework-specific playbook should cover:

1. architecture signals
2. high-risk APIs and configuration
3. authentication/session behavior
4. authorization patterns
5. input/output risks
6. deployment/configuration risks
7. supply-chain concerns
8. common false positives
9. safe remediation patterns
10. verification steps

Potential future modules include Next.js, Express/Fastify, Prisma/Postgres, Supabase, Firebase, Nginx, Docker, GitHub Actions, Cloudflare and AWS.

## Adding architecture signals

Architecture detection should be conservative. A signal means "investigate this," not "this control definitely exists or is missing."

When adding detection:

- use specific markers
- avoid broad keywords that create noise
- add a regression test
- consider external-provider configuration
- prefer `review-needed` over a false confirmed finding

## Adding scanner integrations

External tools should be optional unless the core feature truly depends on them.

A scanner integration should:

- check whether the tool exists
- avoid shell interpolation when arguments can be passed directly
- set a reasonable timeout
- preserve stdout/stderr
- record unavailable tools cleanly
- avoid destructive modes by default
- never convert an exit code directly into vulnerability severity without interpretation

## Reports

New evidence should fit the existing report model under `.agentsec/reports/`.

Prefer machine-readable output from external tools when available, but preserve raw evidence for debugging and review.

## Safety gates

Do not weaken authorization gates to make testing more convenient.

Remote active vulnerability validation must remain explicitly authorized. Add new active checks only when they are controlled, defensive and narrowly scoped.

## CI

The GitHub Actions workflow checks:

- Python syntax
- shell syntax
- unit tests
- CLI smoke behavior
- Agent Skills specification validation

Changes should keep CI green.

## Documentation expectations

When adding a significant capability:

- update the README capability table when appropriate
- update or add a focused document in `docs/`
- update the relevant `references/` playbook
- add examples
- document limitations and false positives

## Release philosophy

AgentSec should favor small, reviewable improvements rather than large opaque rewrites. Security behavior benefits from being auditable.
