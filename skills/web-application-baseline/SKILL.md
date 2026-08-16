---
name: web-application-baseline
description: Perform an authorized passive web baseline covering headers, cookies, CORS, metadata, sensitive paths, and API signals. Use it before active testing or code changes against an Internet-facing application.
domain: cybersecurity
subdomain: web-application-security
tags: [web-security, headers, cors, exposure]
version: "1.0"
author: 0xcryptj
license: MIT
mitre_attack: [T1190]
nist_csf: [DE.CM, PR.PT]
owasp: [WSTG-CONF, WSTG-INFO]
---

# Web Application Baseline

## When to Use

Use this capability when reviewing an authorized website or staging service and you need bounded, low-impact evidence before deciding whether deeper active validation is justified.

## Prerequisites

- Written authorization for the target.
- A reachable HTTP(S) URL.
- A clear rule of engagement for any optional active testing.

## Workflow

1. Run `./agentsec web https://target.example --authorized --baseline-only`.
2. Review headers, cookie attributes, CORS, robots/sitemap, security.txt, and bounded sensitive-path probes.
3. Treat missing controls as review-needed until application and provider configuration are confirmed.
4. Enable `--active` only when explicitly authorized and needed to validate a hypothesis.

## Verification

Confirm the report records the target, authorization mode, baseline observations, raw responses, and any soft-404 handling. Ensure no destructive or credential-testing action was performed.
