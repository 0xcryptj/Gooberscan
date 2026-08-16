---
name: identity-and-access-review
description: Review authentication, authorization, session, privilege, and tenant-boundary controls in an application or service. Use when identity paths or high-impact actions are in scope and least privilege must be verified.
domain: cybersecurity
subdomain: identity-access-management
tags: [authentication, authorization, least-privilege, sessions]
version: "1.0"
author: 0xcryptj
license: MIT
mitre_attack: [T1078, T1098]
nist_csf: [PR.AA, PR.AC]
owasp: [ASVS-2, ASVS-4, API1]
---

# Identity and Access Review

## When to Use

Use this capability when a system has users, administrators, service identities, tenants, or irreversible actions that require server-side authorization.

## Prerequisites

- Source, route, provider, or policy configuration in authorized scope.
- A role and resource inventory, even if incomplete.
- Test accounts only when authenticated behavior must be verified.

## Workflow

1. Map sign-in, recovery, session, MFA, service-account, and admin paths.
2. Trace each privileged action to a server-side authorization decision.
3. Check object ownership, tenant binding, role changes, session rotation, and logout/revocation.
4. Mark provider-managed controls as review-needed until their configuration is verified.
5. Add focused authorization regression tests for every confirmed boundary.

## Verification

Demonstrate that anonymous, cross-tenant, lower-privilege, and expired-session requests receive the intended result without relying on hidden routes or client-side checks.
