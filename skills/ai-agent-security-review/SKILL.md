---
name: ai-agent-security-review
description: Review AI agents, tool calls, MCP servers, prompts, retrieval, memory, and model-facing data for prompt injection, tool poisoning, excessive authority, and sensitive-data leakage. Use when security-sensitive automation is agentic.
domain: cybersecurity
subdomain: ai-security
tags: [ai-security, prompt-injection, mcp, tool-calling]
version: "1.0"
author: 0xcryptj
license: MIT
mitre_attack: [T1195, T1059]
nist_csf: [GV.OC, PR.AA, DE.CM]
owasp: [LLM01, LLM06]
---

# AI Agent Security Review

## When to Use

Use this capability when an agent can read untrusted content, call tools, access secrets, modify systems, or make decisions that affect users, code, infrastructure, or security findings.

## Prerequisites

- Agent instructions, tool schemas, MCP configuration, retrieval/memory design, and permission scope.
- A safe test environment and non-production credentials.
- Explicit authorization for any tool-driven validation.

## Workflow

1. Map untrusted inputs, instruction boundaries, memory writes, tool calls, approvals, and external side effects.
2. Test whether content can override policy, alter tool meaning, poison memory, or exfiltrate hidden context.
3. Enforce least privilege, server-side authorization, input/output boundaries, approval gates, and audit logs outside the model.
4. Pin tool descriptions and implementations; review MCP servers for shadowing, SSRF, and unauthenticated exposure.
5. Add adversarial regression prompts without using real secrets or destructive tools.

## Verification

Confirm untrusted content cannot grant authority, invoke high-impact tools without approval, read protected context, or persist malicious instructions across sessions.
