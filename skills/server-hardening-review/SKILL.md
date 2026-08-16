---
name: server-hardening-review
description: Review a local Linux host or authorized server exposure for patch state, listening services, SSH, firewall, permissions, containers, and web roots. Use it when deployment or host hardening is part of the security scope.
domain: cybersecurity
subdomain: network-security
tags: [server-hardening, linux, containers, exposure]
version: "1.0"
author: 0xcryptj
license: MIT
mitre_attack: [T1046, T1611]
nist_csf: [PR.AC, PR.IP, DE.CM]
owasp: [ASVS-14]
---

# Server Hardening Review

## When to Use

Use this capability for a local Linux machine or an authorized externally reachable server where service exposure and host hardening may affect application risk.

## Prerequisites

- Local access, or explicit authorization for remote enumeration.
- Knowledge of required application services and maintenance windows.
- Permission to inspect host configuration without changing it.

## Workflow

1. Run `./agentsec server --local` for local evidence.
2. For an authorized remote target, use `./agentsec server --target host.example --authorized`.
3. Compare listeners, SSH, firewall, Docker, web roots, and database exposure with the intended architecture.
4. Fix unnecessary exposure at the service or network boundary and preserve required workload behavior.

## Verification

Repeat the relevant audit and confirm required services remain available, unnecessary ports are closed, and the report distinguishes externally observed evidence from controls that require host/provider access.
