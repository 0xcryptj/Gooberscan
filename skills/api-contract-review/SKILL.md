---
name: api-contract-review
description: Inventory an OpenAPI or Swagger contract and safely probe bounded read-only endpoints for authentication, error handling, and exposure signals. Use when an API specification is available for an authorized service.
domain: cybersecurity
subdomain: api-security
tags: [openapi, api-security, authorization, error-handling]
version: "1.0"
author: 0xcryptj
license: MIT
mitre_attack: [T1190]
nist_csf: [ID.AM, PR.AC, DE.CM]
owasp: [API1, API8]
---

# API Contract Review

## When to Use

Use this capability when a team has an OpenAPI or Swagger document and needs a safe inventory of endpoints plus limited evidence about authentication and server-side error handling.

## Prerequisites

- An OpenAPI or Swagger JSON/YAML export.
- Authorization for the optional base URL probe.
- Test credentials only when the engagement explicitly requires authenticated validation.

## Workflow

1. Run `./agentsec api ./openapi.json` to inventory the contract.
2. If authorized, add `--base-url https://staging.example` for bounded read-only probes.
3. Review operations missing security declarations, server errors, and sensitive paths.
4. Confirm object-level authorization in source or an approved test plan; a contract cannot prove it.

## Verification

Verify the report includes every declared operation, the request cap, authorization state, and separate review-needed observations for behavior that cannot be proven from the contract.
