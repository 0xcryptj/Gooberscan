# AgentSec Installation

## Recommended: install as an Agent Skill

AgentSec follows the shared `SKILL.md` Agent Skills format. The easiest installation path is the open `skills` CLI.

### Global install across supported agents

Recommended one-line installer:

```bash
curl -fsSL --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/0xcryptj/AgentSec/main/install.sh | bash
```

The installer checks for `npx`, shows each installation phase, and verifies the global skill path. To inspect it before running:

```bash
git clone https://github.com/0xcryptj/AgentSec.git
cd AgentSec
./install.sh
```

Direct CLI equivalent:

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec --agent '*' -g -y
```

### Claude Code, Codex and Cursor

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec -g -a claude-code -a codex -a cursor -y
```

### Project-local install

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec --agent '*' -y
```

Project-local installation is useful when a team wants the security skill associated with one repository. Global installation makes AgentSec available across your projects.

### Update AgentSec

```bash
npx skills update agentsec -y
```

### Remove AgentSec

```bash
npx skills remove agentsec -y
```

## Agent locations

The `skills` CLI resolves the correct skill locations for supported agents. Examples include agent-specific skill directories for Claude Code, Codex, Cursor and other Agent Skills-compatible clients. Prefer the CLI instead of maintaining separate copies by hand.

If an agent does not discover the skill:

1. confirm `npx skills list` shows `agentsec`
2. confirm the agent supports Agent Skills
3. confirm the skill is installed at the scope you intended, project or global
4. restart/reload the coding-agent session if necessary
5. explicitly ask the agent to use AgentSec for a security audit

## Run AgentSec directly

Clone the repository if you also want the bundled CLI and scanner orchestration:

```bash
git clone https://github.com/0xcryptj/AgentSec.git
cd AgentSec
chmod +x agentsec install-deps.sh scripts/local_server_audit.sh
./agentsec --help
```

Python 3.10 or newer is recommended.

## Optional security tooling

AgentSec can reason about code and architecture without every external scanner, but deterministic tools provide stronger evidence.

On Debian, Ubuntu or WSL:

```bash
sudo ./install-deps.sh
```

The installer prepares commonly used defensive tools and isolated Python utilities where practical.

AgentSec can consume results from tools such as:

- Nmap
- Gobuster
- ffuf
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

Missing optional tools are reported and skipped.

## Docker note

AgentSec does not automatically add users to the Docker group. Membership in the Docker group can effectively grant root-equivalent control on a typical Docker host. Configure Docker permissions intentionally for your environment.

## npm and supply-chain checks

For JavaScript/TypeScript projects, Node.js and npm allow AgentSec to inspect:

- `npm audit`
- installed dependency trees
- package signatures when supported by the npm version and registry
- package lifecycle scripts
- lockfile changes

AgentSec does not automatically run `npm audit fix --force`.

## Permissions

Repository audits should generally run as the normal project user.

Some local server checks may need elevated permissions to inspect system configuration. Prefer targeted read access and avoid running an entire coding-agent session as root.

## Installation verification

After installation, ask your coding agent:

```text
Use AgentSec to explain its audit workflow for this repository. Do not change anything yet.
```

For the direct CLI:

```bash
./agentsec --help
python3 scripts/architecture_inventory.py . --output /tmp/agentsec-architecture.json
```

## Troubleshooting

### No skills found

Confirm the repository contains a valid root `SKILL.md` and use the exact skill name `agentsec`.

### AgentSec is installed but not invoked

Ask explicitly:

```text
Use the AgentSec skill to audit this repository.
```

The skill description is written to trigger on security auditing, hardening, dependency risk, server security, Cloudflare security, least privilege and related tasks.

### Scanner unavailable

Install the missing tool or continue with the remaining checks. AgentSec is designed to degrade gracefully rather than treating one missing scanner as a failed audit.

### Active scan blocked

Remote active validation requires both explicit authorization and active mode. For web audits:

```bash
./agentsec web https://staging.example.com --authorized --active
```

Do not bypass that guardrail.
