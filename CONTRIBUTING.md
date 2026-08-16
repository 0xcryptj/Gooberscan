# Contributing to AgentSec

Thanks for helping improve AgentSec.

AgentSec is a defensive security engineering project. Contributions should make audits more accurate, explainable, portable and useful to developers without turning the project into an exploitation framework.

## Good contribution areas

- framework-specific security playbooks
- dependency and supply-chain analysis
- server hardening checks
- cloud/IaC review
- Cloudflare edge-security guidance
- least-privilege analysis
- identity/authentication guidance
- false-positive reduction
- regression tests
- report formats such as SARIF
- documentation and examples
- Agent Skills compatibility

## Security boundary

Do not add workflows centered on:

- credential attacks
- persistence
- destructive exploitation
- data exfiltration
- denial-of-service testing
- post-exploitation
- bypassing AgentSec authorization gates

Controlled validation of vulnerabilities in explicitly authorized scope should remain defensive, non-destructive and narrowly targeted.

## Project structure

```text
SKILL.md                 agent-facing workflow
references/              progressive security knowledge
scripts/                 deterministic evidence collection
agentsec                 CLI entry point
tests/                   regression tests
docs/                    user/developer documentation
skills/                  modular capability playbooks and generated catalog
tools/                   capability validation and index-generation utilities
mappings/                framework metadata and interpretation notes
.github/workflows/       CI
```

## Development setup

Clone the repository:

```bash
git clone https://github.com/0xcryptj/AgentSec.git
cd AgentSec
```

Run the complete local check suite:

```bash
make check
```

Or run individual checks:

```bash
python3 -m py_compile scripts/agentsec.py scripts/architecture_inventory.py
bash -n agentsec
bash -n install-deps.sh
bash -n scripts/local_server_audit.sh
```

Run tests:

```bash
python3 -m unittest discover -s tests -v
python3 tools/validate_skills.py
python3 tools/build_skill_index.py
```

Smoke test:

```bash
python3 scripts/agentsec.py --help
python3 scripts/architecture_inventory.py . --output /tmp/agentsec-architecture.json
```

## Capability and Agent Skill validation

AgentSec CI validates the packaged skill against the Agent Skills reference tooling.

When changing `SKILL.md`:

- keep valid YAML frontmatter
- keep the skill name `agentsec`
- make the description specific enough for agent discovery
- preserve progressive disclosure into `references/`
- avoid stuffing large framework-specific material directly into `SKILL.md`

When changing a modular capability under `skills/`:

- keep its directory name and frontmatter `name` identical
- include `When to Use`, `Prerequisites`, `Workflow`, and `Verification`
- use framework mappings as navigation metadata, not compliance claims
- rebuild `skills/index.json` and run `python3 tools/validate_skills.py`

## Adding a deterministic check

A useful check should:

1. collect evidence reproducibly
2. avoid destructive side effects
3. preserve raw output
4. degrade gracefully if the tool is unavailable
5. have a clear relationship to a security question
6. avoid treating tool exit codes as final severity by themselves

## Adding security reasoning

Put broad architecture or methodology guidance in the appropriate `references/*.md` file.

Put framework-specific guidance in a focused new reference when it becomes large enough to justify progressive loading.

Good guidance explains:

- what evidence to look for
- why the issue matters
- common false positives
- safe remediation
- verification steps

## Tests

Add tests when changing architecture detection or logic that could create misleading findings.

Especially test:

- false-positive boundaries
- external-provider uncertainty
- classification behavior
- parsing edge cases
- safety gates

## Commit and PR style

Prefer focused commits and PRs with:

- problem statement
- security rationale
- implementation summary
- tests/checks run
- false-positive considerations
- screenshots/examples when documentation or output changes

## Reporting project vulnerabilities

Do not open a public issue for a vulnerability in AgentSec itself. Follow [`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contribution can be distributed under the project's MIT License.
