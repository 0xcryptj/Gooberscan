---
name: ci-cd-supply-chain-review
description: Review CI/CD workflows, build identities, third-party actions, artifacts, dependency installation, and deployment approvals for supply-chain risk. Use before trusting an automated build or release pipeline.
domain: cybersecurity
subdomain: devsecops
tags: [ci-cd, supply-chain, github-actions, provenance]
version: "1.0"
author: 0xcryptj
license: MIT
mitre_attack: [T1195, T1608]
nist_csf: [GV.SC, PR.PS, RS.MI]
owasp: [ASVS-14]
---

# CI/CD Supply-Chain Review

## When to Use

Use this capability when workflows build, test, publish, deploy, or execute code from pull requests, forks, package registries, containers, or external actions.

## Prerequisites

- Workflow files, reusable workflows, deployment configuration, and branch rules.
- Knowledge of trusted and untrusted code paths.
- Read-only access to CI settings where available.

## Workflow

1. Inventory triggers, permissions, secrets, environments, runners, artifacts, and deployment identities.
2. Check fork and pull-request execution for write tokens or exposed secrets.
3. Pin third-party actions and critical build inputs to immutable references where practical.
4. Separate untrusted build output from trusted release and deployment jobs.
5. Require review, provenance, and environment protection for production changes.

## Verification

Use a test pull request or workflow simulation to confirm untrusted code cannot read secrets, write protected branches, poison release artifacts, or deploy without the intended approval boundary.
