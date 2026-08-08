# Install AgentSec

Open your coding agent and paste this command:

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec --agent '*' -g -y
```

That's it. Then ask your agent:

```text
Use AgentSec to audit this project, explain the biggest security risks, and propose the simplest safe fixes.
```

<p align="center">
  <img src="assets/agentsec-hero.png" alt="AgentSec - Spy on threats. Secure everything." width="100%" />
</p>

<h1 align="center">AgentSec</h1>
<p align="center"><strong>A senior security engineer for AI-built software.</strong></p>

AgentSec is an Agent Skill for vibe-coded and AI-assisted projects. It helps your coding agent understand the repo, find meaningful security problems, check current threat intelligence, explain what matters, and propose or implement safer code and configuration.

## What it does

- Reads the repo progressively instead of wasting context on every file.
- Reviews application code, authentication, authorization, dependencies, servers, CI/CD, cloud and edge configuration.
- Checks current package advisories and malware intelligence when network access is available.
- Looks for vulnerable or malicious dependencies, secrets, exposed files, weak permissions, injection flaws and risky architecture.
- Tells the coding agent how the code or configuration should change.
- Verifies fixes with focused security checks and normal project tests when possible.

## KISS

**Keep It Simple, Stupid.**

AgentSec prefers simple security that people can actually understand and maintain. Secure defaults, least privilege, server-side authorization, standard cryptography, parameterized queries and small reviewable fixes beat unnecessary complexity.

Complexity is only worth adding when the reduction in risk justifies it.

## Try it

```text
Use AgentSec to audit this repo and find the highest-priority security issues.
```

```text
Use AgentSec to review authentication and authorization and show me where least privilege or MFA would materially improve security.
```

```text
Use AgentSec to check our dependencies for vulnerable or compromised packages and safely fix the high-confidence issues.
```

```text
Use AgentSec to review this project, implement the safe high-priority fixes, and retest them.
```

## Advanced

AgentSec can also perform deeper architecture, application, supply-chain, server and authorized web security review.

- [Getting Started](docs/GETTING_STARTED.md)
- [Usage](docs/USAGE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security Concepts](docs/SECURITY_CONCEPTS.md)
- [Fresh Security Intelligence](docs/FRESH_INTELLIGENCE.md)
- [Remediation Guide](docs/REMEDIATION_GUIDE.md)
- [Installation](docs/INSTALLATION.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

> AgentSec is for defensive development and authorized security assessment. Only scan remote systems you own or have permission to test.

<p align="center"><strong>Audit. Reason. Remediate. Verify.</strong></p>
