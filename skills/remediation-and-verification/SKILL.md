---
name: remediation-and-verification
description: Turn AgentSec evidence into small, root-cause fixes with focused regression tests and a retest record. Use after an audit identifies a confirmed issue, security design gap, or high-confidence dependency risk.
domain: cybersecurity
subdomain: vulnerability-management
tags: [remediation, verification, secure-coding, regression-testing]
version: "1.0"
author: 0xcryptj
license: MIT
mitre_attack: [T1588]
nist_csf: [RS.MI, PR.IP]
owasp: [ASVS-1, ASVS-2]
---

# Remediation and Verification

## When to Use

Use this capability when an AgentSec finding has enough evidence to change code, configuration, dependencies, or deployment policy and the result must be demonstrated rather than assumed.

## Prerequisites

- A specific finding with evidence and affected location.
- Understanding of the application trust boundary and intended behavior.
- A focused test or deterministic check that can be rerun.

## Workflow

1. State the root cause, attacker-controlled input or authority boundary, and impact.
2. Implement the smallest idiomatic fix in the existing stack.
3. Add or update a focused regression test where practical.
4. Run the relevant scanner plus normal project tests.
5. Record what was verified and any provider/runtime control that remains review-needed.

## Verification

The fix is complete only when the regression test passes, the focused security check no longer produces the same evidence, and the report or change notes explain residual risk and operational follow-up.
