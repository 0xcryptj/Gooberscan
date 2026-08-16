---
name: incident-response-triage
description: Triage suspected compromise using evidence preservation, scope assessment, containment planning, credential review, and recovery sequencing. Use when logs, alerts, package incidents, or runtime behavior suggest an active security event.
domain: cybersecurity
subdomain: incident-response
tags: [incident-response, triage, containment, evidence]
version: "1.0"
author: 0xcryptj
license: MIT
mitre_attack: [TA0001, TA0003, TA0040]
nist_csf: [DE.AE, RS.MA, RS.MI, RC.RP]
owasp: [ASVS-1, ASVS-14]
---

# Incident Response Triage

## When to Use

Use this capability when a dependency, credential, host, account, deployment, or application event may indicate compromise and decisions must preserve evidence while reducing harm.

## Prerequisites

- Incident owner, scope, authorization, and communication path.
- Access to relevant logs, deployment records, identity events, and immutable evidence storage.
- A containment plan that avoids destroying evidence or interrupting critical services blindly.

## Workflow

1. Record the timeline, affected assets, indicators, confidence, and immediate safety concerns.
2. Preserve logs, package versions, workflow runs, images, tokens, and relevant host artifacts.
3. Identify exposed identities and rotate/revoke the smallest necessary scope.
4. Contain affected services, block confirmed indicators, and inspect persistence or unauthorized changes.
5. Recover from trusted artifacts, validate controls, and document lessons and follow-up fixes.

## Verification

Confirm the incident record has evidence hashes or retention references, an owner, containment decisions, credential actions, recovery validation, and unresolved risk clearly assigned.
