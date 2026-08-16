---
name: container-security-review
description: Review container images, Dockerfiles, runtime privileges, secrets, network exposure, and orchestration configuration for practical hardening gaps. Use when an application is built or deployed in containers.
domain: cybersecurity
subdomain: container-security
tags: [docker, kubernetes, images, runtime]
version: "1.0"
author: 0xcryptj
license: MIT
mitre_attack: [T1611, T1610]
nist_csf: [PR.PS, PR.IR]
owasp: [ASVS-14]
---

# Container Security Review

## When to Use

Use this capability for Dockerfiles, Compose, Kubernetes, image registries, or container hosts where build and runtime isolation affect application risk.

## Prerequisites

- Dockerfile, image metadata, Compose/Kubernetes manifests, and deployment scope.
- Permission to inspect images and runtime configuration without changing workloads.
- A list of required ports, volumes, capabilities, and service identities.

## Workflow

1. Check base-image provenance, pinned versions, package updates, and build secrets.
2. Review root users, privileged mode, host namespaces, capabilities, writable roots, host paths, and Docker socket mounts.
3. Check exposed ports, service-account tokens, network policy, health checks, and resource limits.
4. Scan images for vulnerabilities and correlate findings with shipped layers.
5. Reduce privileges while preserving required behavior and document exceptions.

## Verification

Rebuild the image, rerun the image scan, inspect the runtime spec, and confirm the service still works without privileged or host-level access it does not require.
