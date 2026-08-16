---
name: secrets-and-sensitive-data-review
description: Find exposed secrets, credentials, private keys, sensitive artifacts, logs, backups, and unsafe data flows in a repository or deployment surface. Use before release or after suspected credential exposure.
domain: cybersecurity
subdomain: data-protection
tags: [secrets, credentials, privacy, artifacts]
version: "1.0"
author: 0xcryptj
license: MIT
mitre_attack: [T1552]
nist_csf: [PR.DS, PR.PS]
owasp: [ASVS-7, ASVS-12]
---

# Secrets and Sensitive Data Review

## When to Use

Use this capability when reviewing source control, build artifacts, public directories, logs, environment files, or storage paths for data that could grant access or expose users.

## Prerequisites

- Authorized repository and deployment evidence.
- A list of expected secret providers and public configuration values.
- A rotation contact for any confirmed credential exposure.

## Workflow

1. Run AgentSec sensitive-artifact and available secret scanners.
2. Distinguish public client identifiers from bearer tokens, signing keys, passwords, and private keys.
3. Trace suspected secrets through history, CI logs, images, reports, and public assets.
4. Revoke or rotate confirmed live credentials before removing copies.
5. Replace plaintext handling with scoped secret injection and least-privilege identities.

## Verification

Confirm the secret is revoked or rotated, absent from current artifacts and release outputs, and covered by a pre-commit or CI regression check.
