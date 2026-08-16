---
name: cloud-security-review
description: Review cloud identities, storage, networks, managed services, logging, and edge controls for least privilege and unintended exposure. Use when an application depends on AWS, Azure, GCP, Cloudflare, or managed backend services.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud, iam, storage, networking]
version: "1.0"
author: 0xcryptj
license: MIT
mitre_attack: [T1530, T1526]
nist_csf: [ID.AM, PR.AA, PR.IR]
owasp: [ASVS-4, ASVS-12]
---

# Cloud Security Review

## When to Use

Use this capability when application behavior crosses a cloud-provider trust boundary or depends on storage, queues, functions, databases, IAM, CDN, or edge policy.

## Prerequisites

- Authorized infrastructure, policy, and application configuration.
- Provider and account/tenant scope.
- Awareness of public versus private data and required service flows.

## Workflow

1. Build an identity-to-resource map for runtime, deploy, migration, and operator roles.
2. Check wildcard permissions, public storage, open security groups, exposed admin services, and missing audit logs.
3. Verify personalized responses bypass shared caches and origins cannot bypass the intended edge.
4. Review backups, key management, retention, recovery, and cross-account access.
5. Record provider-managed controls as confirmed only when configuration evidence exists.

## Verification

Re-run policy checks with least-privilege test identities and confirm public endpoints expose only intended data while required application flows remain available.
