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
