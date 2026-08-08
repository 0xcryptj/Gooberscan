# AgentSec Security Concepts

This document describes the security ideas AgentSec is expected to reason about when reviewing an application or infrastructure repository.

It is not a checklist that should be applied mechanically. Controls should match the architecture, threat model and operational requirements of the system under review.

## Threat modeling

AgentSec should identify:

- assets that matter
- entry points
- trust boundaries
- users and service identities
- sensitive data stores
- privileged operations
- third-party dependencies
- external control planes
- failure and recovery paths

A useful first question is:

> If one component or credential is compromised, what can the attacker reach next?

That question often exposes privilege and isolation problems that a vulnerability scanner cannot see.

## Principle of least privilege

Least privilege means giving each identity only the permissions required for its current job.

AgentSec should review least privilege across several layers.

### Application users

Check whether:

- ordinary users can reach admin functionality
- role checks occur server-side
- object ownership is enforced on every read/write path
- tenant boundaries are part of the query or policy layer
- dangerous actions require stronger verification

### Database identities

Ask whether:

- the runtime application user owns the schema
- migrations use the same credentials as normal traffic
- workers need access to every table
- read-only jobs have write access
- application roles can create extensions, users or schemas unnecessarily
- database connections are exposed beyond required networks

A common hardening pattern is to separate migration/admin credentials from runtime credentials.

### Cloud IAM

Review:

- wildcard actions
- wildcard resources
- long-lived keys
- unnecessary role chaining
- permissions inherited by all workloads
- overly broad CI/deployment credentials
- missing separation between production and development roles

### CI/CD

Review whether workflows have:

- write permissions when read is sufficient
- access to secrets for jobs that do not need them
- unpinned or untrusted third-party actions
- privileged deployment tokens exposed to pull-request workflows
- production credentials available in lower-trust environments

## Authentication and MFA

Authentication answers who the principal is. Authorization answers what the principal may do.

AgentSec should evaluate:

- password and login flows
- session issuance and rotation
- privileged session lifetime
- MFA or passkey support
- step-up authentication for sensitive actions
- account recovery
- email/phone verification where relevant
- brute-force and credential-stuffing controls
- logout/revocation behavior

### MFA and passkeys

MFA is especially valuable for:

- administrators
- billing and payout operations
- credential management
- security settings
- irreversible actions
- production control planes

Passkeys/WebAuthn can provide phishing-resistant authentication when the product and identity stack support them.

AgentSec must not declare MFA absent just because no MFA code appears in the repo. External identity providers may enforce the control outside source code.

## Step-up authentication

A user may be normally authenticated but still be required to prove identity again before a sensitive operation.

Examples:

- changing payout information
- rotating API keys
- deleting an account
- granting administrator privileges
- exporting sensitive data
- disabling MFA

Step-up authentication can reduce risk when a session cookie is stolen.

## Authorization and IDOR

Every protected object access should answer:

> Is this specific principal allowed to perform this specific action on this specific object?

AgentSec should look for:

- route-level role checks without object-level checks
- sequential IDs trusted without ownership validation
- tenant IDs supplied by the client and trusted directly
- admin checks implemented only in the frontend
- data queries that do not scope by user/tenant
- service-to-service endpoints without identity checks

## SQL injection

Preferred defenses:

- parameterized queries
- safe ORM/query builder APIs
- avoiding string concatenation for SQL fragments
- strict handling of dynamic identifiers and sorting fields
- database roles that limit blast radius

A WAF is not a substitute for parameterized queries.

## Cross-site scripting

AgentSec should reason about XSS by output context.

Review:

- HTML rendering
- client-side DOM sinks
- server-rendered templates
- rich-text/Markdown rendering
- URL attributes
- inline script/data injection
- unsafe HTML escape hatches

Preferred defenses include framework-safe rendering, context-aware output encoding, sanitization for intentionally allowed HTML, and a restrictive CSP as defense in depth.

## SSRF

Server-side request forgery becomes dangerous when user-controlled input can cause the server to access internal or privileged destinations.

Review:

- URL fetch/proxy endpoints
- webhook test features
- import-from-URL features
- image/PDF generation
- metadata/preview services
- cloud metadata access
- internal hostnames/IP ranges

Defenses may include destination allowlists, URL parsing and canonicalization, DNS/IP validation, egress controls and network segmentation.

## CSRF

Cookie-authenticated state-changing requests may require CSRF defenses depending on framework and request model.

Review:

- SameSite cookie policy
- CSRF tokens where needed
- Origin/Referer validation
- unsafe GET requests that mutate state
- JSON/API assumptions that can be bypassed by alternate content types

## File upload security

Review:

- extension and MIME validation
- file content validation where relevant
- randomized storage names
- storage outside executable/public roots
- image/document processing libraries
- size limits
- malware scanning where justified
- authorization to download the file

Do not rely only on a filename extension.

## Secrets management

AgentSec should distinguish between secret presence and secret exposure.

Review:

- committed `.env` files
- API tokens
- private keys
- cloud credentials
- database URLs
- package-registry tokens
- secrets in CI logs
- secrets embedded in frontend bundles
- build-time variables accidentally published

If a secret is confirmed exposed, remediation includes rotation/revocation, not just deleting the file from the latest commit.

## Software supply chain

Dependency security includes more than CVEs.

Review:

- direct/transitive advisories
- package provenance/signatures when available
- lockfile integrity
- suspicious new dependencies
- typosquatting
- abandoned/unmaintained packages
- lifecycle scripts
- Git dependencies
- prebuilt binaries
- compromised package response

If a dependency is confirmed malicious, determine what it could access during installation/build/runtime and rotate affected credentials.

## Server hardening

A server audit should consider:

- patch status
- unnecessary services
- exposed management ports
- SSH policy
- firewall/default-deny posture
- service user privileges
- file ownership and permissions
- SUID/SGID exposure
- systemd/cron jobs
- log access
- secrets on disk
- Docker socket and privileged containers
- public database/cache listeners
- reverse-proxy configuration

Hardening should preserve recovery access. Changes to SSH or firewall rules should have a rollback path.

## Directory/path exposure

Attackers do not need a link to guess a route.

AgentSec should assume paths can be enumerated through:

- crawling
- search-engine indexing
- wordlists
- source maps
- JavaScript bundles
- old links
- logs or documentation
- Gobuster/ffuf-style enumeration

Protection must come from authorization and deployment hygiene, not secrecy of the path name.

## Cloudflare and edge security

When Cloudflare is present, AgentSec may evaluate:

- WAF managed rules
- custom WAF rules
- rate limiting
- Turnstile
- bot controls
- TLS mode
- origin firewalling
- direct-origin bypass
- Authenticated Origin Pulls
- cache policy
- public R2/bucket exposure

### Origin protection

An application behind Cloudflare can still be vulnerable if attackers can connect directly to the origin and bypass edge controls.

Review whether the origin is restricted to intended traffic paths and whether direct access is actually required.

### Rate limiting

Rate limits should be endpoint-specific. Authentication, password reset, token creation, search, expensive queries and public APIs often need different limits.

Do not apply one arbitrary global rate limit without considering legitimate traffic.

### Caching

Authenticated or tenant-specific content requires careful cache behavior.

Review:

- cache keys
- cookie/header variation
- bypass rules
- authorization-sensitive responses
- private data accidentally marked cacheable

## Security headers

Common headers to evaluate include:

- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- frame protections through CSP `frame-ancestors`

Header recommendations should match actual application behavior and deployment.

## `robots.txt`

`robots.txt` controls cooperative crawler behavior. It is not a security boundary.

Do not use it to protect private routes or secrets.

## `llms.txt`

`llms.txt` is an optional convention for public AI-oriented site information. It may be useful for documentation/discovery but is not an access-control mechanism.

## `security.txt`

`/.well-known/security.txt` can provide security researchers with a clear disclosure contact and policy information.

Its absence is generally an operational recommendation, not a vulnerability.

## Logging and auditability

Security-sensitive actions should be observable without leaking secrets.

Review whether logs capture:

- privileged changes
- authentication events
- credential/key changes
- authorization failures
- high-risk data exports
- administrative actions

Logs should avoid passwords, raw tokens and other sensitive values.

## Backups and recovery

Security also includes recoverability.

Review:

- backup encryption
- backup access control
- restore testing
- retention
- separation from production credentials
- public exposure of dumps/archives
- ransomware/blast-radius considerations

## Defense in depth

No single control should carry the entire security model.

For example, a secure admin action might combine:

```text
MFA / step-up auth
        +
server-side authorization
        +
least-privilege database role
        +
audit logging
        +
rate limiting
        +
secure session controls
```

AgentSec should prefer layered controls when the risk justifies them.
