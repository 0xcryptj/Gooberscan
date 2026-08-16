---
name: repository-security-review
description: Review a local repository for architecture risks, vulnerable dependencies, secrets, unsafe source patterns, and deployment weaknesses. Use this capability when a project needs a defensible source and supply-chain security baseline.
domain: cybersecurity
subdomain: devsecops
tags: [repository-audit, supply-chain, secrets, architecture]
version: "1.0"
author: 0xcryptj
license: MIT
mitre_attack: [T1195]
nist_csf: [ID.RA, PR.DS, DE.CM]
owasp: [ASVS-1, ASVS-14]
---

# Repository Security Review

## When to Use

Use this capability for a source repository, pull request, or AI-generated project where dependency, secret, configuration, and architecture risks need to be correlated instead of treated as raw scanner output.

## Prerequisites

- Authorized access to the repository and its build configuration.
- Python 3.10+ for AgentSec.
- A clean or intentionally scoped working tree.

## Workflow

1. Run `./agentsec repo . --scan-mode standard`.
2. Read `.agentsec/architecture-latest.json` before opening broad source areas.
3. Correlate dependency, secret, and source-security evidence with the actual trust boundary.
4. Separate confirmed vulnerabilities, design gaps, opportunities, and review-needed items.
5. Apply the smallest compatible remediation and rerun the focused check.

## Verification

Confirm that the report contains `summary.json`, `findings.json`, `findings.sarif`, and preserved raw evidence. Re-run project tests and verify that each changed finding has a new evidence-backed result.
