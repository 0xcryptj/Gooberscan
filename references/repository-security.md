# AgentSec Repository & Supply-Chain Security

Use this reference for source-code, dependency, CI/CD, secrets, and deployment audits.

## Contents

- Audit order
- JavaScript/npm supply-chain checks
- Other dependency ecosystems
- Source-code review
- Secrets and sensitive artifacts
- CI/CD and deployment configuration
- Containers and infrastructure as code
- Confirmation rules

## Audit order

1. Identify languages, frameworks, package managers, build system, database, authentication model, deployment target, and Internet-facing entry points.
2. Inspect lockfiles and dependency advisories before changing versions.
3. Run deterministic scanners where available.
4. Review high-risk code paths manually with framework context.
5. Confirm findings before reporting them as vulnerabilities.
6. Remediate root causes and run application tests plus the relevant security check.

## JavaScript/npm supply-chain checks

For a Node project, inspect `package.json` plus the exact lockfile.

Recommended checks:

```bash
npm audit --json
npm ls --all --json
npm audit signatures
```

`npm audit` is useful for known published advisories, but it does not prove every installed package is trustworthy. `npm audit signatures` can validate registry signatures when supported by the npm/registry combination, but a valid signature does not prove package code is non-malicious.

Also inspect:

- Newly added dependencies and unexpected transitive dependency changes.
- Typosquatting or packages whose names are visually similar to common libraries.
- Install lifecycle scripts such as `preinstall`, `install`, and `postinstall`.
- Packages pulling binaries or code from arbitrary external URLs during installation.
- Unmaintained packages, unexpected ownership/maintainer changes, or suspicious version jumps when that information is available.
- Git dependencies, raw URL dependencies, local path dependencies, and unpinned versions.
- Lockfile churn unrelated to the intended change.
- Dependency confusion risk for private package names.
- Packages that request capabilities far beyond their apparent purpose.

When Internet access is available, correlate suspicious packages and versions with official registry metadata, GitHub security advisories, OSV, vendor advisories, and package-maintainer notices. Do not label a package compromised based on rumor or a name match alone.

### npm remediation

Prefer this order:

1. Upgrade the direct dependency that introduces the vulnerable transitive package.
2. Upgrade to the nearest patched compatible version.
3. Use supported package-manager overrides/resolutions only when the upstream tree cannot yet be upgraded and compatibility is tested.
4. Run `npm audit fix` only after reviewing what it will change.
5. Never run `npm audit fix --force` automatically.
6. Rerun build/tests and `npm audit` after changes.

If a package is confirmed malicious or compromised, remove it or pin away from the affected version, rotate any credentials that installation/runtime could have accessed, inspect CI and developer machines for related indicators, and review the incident window rather than treating a version bump as the entire response.

## Other dependency ecosystems

Use ecosystem-native and cross-ecosystem scanners when available:

- Python: `pip-audit`, OSV-Scanner, lockfile review.
- Rust: `cargo audit` and `Cargo.lock` review.
- Go: `govulncheck` and `go.sum` review.
- Java/Maven/Gradle: dependency-tree review plus OSV/Trivy or the organization's SCA tool.
- Containers: Trivy/Grype or equivalent against the built image and base image.

Check dependencies actually shipped to production, not only declared manifests.

## Source-code review

Review framework-aware data flow from untrusted input to security-sensitive sinks.

High-priority categories:

- SQL/NoSQL/ORM injection and unsafe dynamic queries.
- XSS in HTML, attributes, JavaScript, CSS, URLs, templates, markdown/renderers, and DOM sinks.
- OS command injection and unsafe subprocess usage.
- Path traversal and arbitrary file read/write.
- Server-side request forgery.
- Unsafe deserialization and dynamic code execution.
- Authentication bypass, account recovery weaknesses, MFA mistakes, and session fixation.
- Broken object-level/function-level authorization, IDOR, tenant-boundary mistakes, and admin-route exposure.
- BaaS policy gaps: missing/weak RLS or security rules, broad anon/authenticated grants, unsafe RPCs, `SECURITY DEFINER`, storage policies, and service-role use in client code.
- Alternate identity paths: signup, invitations, OTP, verification, activation, password recovery, OAuth/OIDC/SSO and MFA routes that may not enforce the primary login policy.
- CSRF on state-changing cookie-authenticated requests.
- Open redirect and unsafe callback/return URLs.
- Insecure file uploads, content-type confusion, executable uploads, and public bucket/object ACLs.
- Weak cryptography, hard-coded keys, insecure random IDs/tokens, password hashing mistakes, and nonce/key reuse.
- Race conditions around balances, authorization, inventory, or one-time operations.
- Mass assignment and over-posting.
- GraphQL introspection/excessive data exposure, missing resolver authorization, and unbounded query cost where applicable.
- WebSocket authorization and origin validation.

Treat Semgrep/static-analysis hits as starting points. Trace the actual sanitization, parameterization, encoding, and authorization logic before confirmation.

For authorization, distinguish evidence from proof. A public client key or
application identifier may be intentionally public; determine the data and
operations it unlocks. Build an identity/action matrix and inspect both the
frontend caller and the server/data-layer enforcement. A route name or matching
authorization token is not enough to establish that the condition has the
intended truth table.

## Secrets and sensitive artifacts

Look for:

- `.env*`, `.npmrc`, `.pypirc`, cloud credentials, service-account JSON, SSH/private keys, TLS private keys, wallet/private signing keys, API tokens, OAuth secrets, database URLs, JWT signing secrets, webhook secrets, and CI credentials.
- Database dumps, SQLite files, logs, backups, archives, source maps, debug dumps, generated reports, and production configuration inside public/static directories.

If a real secret is committed, removal from the current file is not enough. Rotate/revoke it and evaluate whether history or build artifacts also contain it.

## CI/CD and deployment configuration

Review:

- Workflow triggers executing untrusted fork/PR code with write tokens or secrets.
- Over-broad CI token permissions.
- Unpinned third-party actions or build dependencies.
- Secrets echoed into logs or passed to untrusted commands.
- Production deploy jobs lacking environment protections.
- Artifact poisoning between untrusted and trusted jobs.
- Debug/development modes enabled in production.
- CORS wildcards with credentials.
- Missing secure cookie settings.
- Missing trusted-proxy configuration causing IP/HTTPS/auth mistakes behind a reverse proxy.
- Source maps, stack traces, or verbose error pages exposed publicly.

## Containers and infrastructure as code

Check:

- Running as root when unnecessary.
- Privileged containers, host PID/network namespaces, dangerous capabilities, writable root filesystems, and Docker socket mounts.
- Secrets baked into image layers or Docker build arguments.
- Mutable or untrusted base-image tags.
- Publicly exposed database/cache/admin ports.
- Security groups/firewall rules allowing `0.0.0.0/0` or `::/0` where not required.
- Storage buckets/objects unintentionally public.
- IAM roles with wildcard permissions.
- Kubernetes privileged pods, hostPath mounts, service-account token exposure, missing network policy, and externally exposed dashboards.

## Confirmation rules

A finding is confirmed only when evidence demonstrates the insecure behavior or configuration. Include:

- Affected file/component and relevant line/configuration when possible.
- The untrusted input or exposure path.
- The security-sensitive sink/control that fails.
- Existing mitigations and whether they are sufficient.
- Realistic impact.
- A concrete remediation and verification step.
