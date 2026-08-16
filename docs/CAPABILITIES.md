# AgentSec capabilities

AgentSec now separates its portable agent playbooks from its deterministic
execution engine. Each capability is a small `skills/<name>/SKILL.md` package
with discoverable metadata, workflow guidance, and verification criteria.

| Capability | Scope |
| --- | --- |
| `repository-security-review` | Source, dependencies, secrets, architecture, and deployment evidence |
| `web-application-baseline` | Authorized passive web and exposure baseline |
| `api-contract-review` | OpenAPI inventory and bounded API probes |
| `server-hardening-review` | Local or authorized remote host hardening evidence |
| `remediation-and-verification` | Root-cause fixes, regression tests, and retesting |
| `identity-and-access-review` | Authentication, authorization, sessions, and tenant boundaries |
| `secrets-and-sensitive-data-review` | Credentials, keys, artifacts, and privacy-sensitive data |
| `ci-cd-supply-chain-review` | Workflow permissions, build inputs, artifacts, and releases |
| `cloud-security-review` | Cloud IAM, storage, networks, managed services, and edge policy |
| `container-security-review` | Images, Docker/Kubernetes runtime, privileges, and exposure |
| `ai-agent-security-review` | Prompt injection, tool poisoning, MCP, and agent authority |
| `incident-response-triage` | Evidence preservation, containment, and recovery |
| `vulnerability-prioritization-review` | Correlation, prioritization, ownership, and verification |

The machine-readable catalog is [skills/index.json](../skills/index.json).
Rebuild it with:

```bash
python3 tools/build_skill_index.py
```

Validate all capability packages with:

```bash
python3 tools/validate_skills.py
```

These packages complement the main [SKILL.md](../SKILL.md); they do not replace
the authorization boundary or turn framework mappings into compliance claims.
