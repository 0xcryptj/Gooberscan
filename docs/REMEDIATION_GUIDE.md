# AgentSec Remediation Guide

AgentSec should not stop at finding problems. The expected workflow is to identify the root cause, implement the smallest safe fix, verify behavior, and rerun the relevant security check.

## Remediation sequence

```text
1. Confirm evidence
2. Identify root cause
3. Choose the smallest safe fix
4. Plan rollback for risky infrastructure changes
5. Implement
6. Run normal tests/build
7. Rerun the security check
8. Report what remains unverified
```

## Evidence first

Before changing code or infrastructure, capture:

- the affected file/component
- the unsafe behavior
- scanner output or source evidence
- the attack or failure condition
- confidence level

Do not change code just to silence a tool.

## Root-cause fixes

### SQL injection

Prefer parameterized queries or safe ORM APIs.

Do not "fix" SQL injection by:

- blocking a few characters
- hiding the endpoint
- relying only on a WAF
- escaping an entire query string manually

After the fix, rerun the application tests and the controlled injection check that reproduced the issue.

### XSS

Fix the unsafe output path according to context.

Potential remediation:

- use framework-safe rendering
- remove unnecessary raw-HTML rendering
- sanitize intentionally allowed HTML
- encode for the destination context
- add or tighten CSP as defense in depth

Retest the exact rendering path.

### IDOR / broken authorization

The fix belongs on the server-side access path.

Examples:

- scope the database query to the current user/tenant
- verify object ownership
- require the correct role/permission
- move authorization into a shared policy layer

Do not rely only on hiding buttons in the frontend.

### SSRF

Potential remediation:

- allowlist valid destinations
- canonicalize URLs before policy checks
- reject private/link-local/metadata destinations where not needed
- control DNS resolution and redirects
- use egress/network policy

Retest alternate URL forms and redirect behavior.

### Exposed files and directories

If a scan discovers a backup, `.env`, source-control metadata, log or other sensitive artifact:

1. remove it from the served tree
2. fix the build/deployment process that published it
3. add explicit web-server deny rules where appropriate
4. disable indexing
5. rotate credentials if exposure is confirmed
6. retest alternate hosts/routes

Do not merely rename the artifact.

### Vulnerable dependencies

Preferred order:

1. identify the direct dependency introducing the issue
2. upgrade to a compatible patched release
3. use a supported override/resolution only if needed
4. inspect breaking changes
5. run tests/build
6. rerun the advisory scan

Avoid automatic major-version jumps without review.

If a package is confirmed malicious or compromised, treat it as an incident. Determine what secrets, CI credentials, files or runtime permissions it could access and rotate/revoke affected credentials.

### Secrets

Deleting an exposed secret from the working tree is not enough.

Remediation may require:

- revoke/rotate the credential
- remove it from source
- migrate to a secret manager or deployment secret
- inspect logs/build artifacts/history for exposure
- constrain the replacement credential's permissions

### Least privilege

Prefer splitting identities by responsibility.

Examples:

- migration database role vs runtime role
- read-only analytics role vs application writer
- worker-specific bucket/table access
- CI build role vs production deploy role

Before removing permissions, identify required operations and have a rollback plan.

### MFA and privileged actions

If privileged users lack strong authentication and the identity provider supports it, consider:

- mandatory MFA for administrators
- WebAuthn/passkeys
- step-up authentication for sensitive actions
- shorter privileged session lifetime

Verify external IdP configuration before claiming a control is absent.

### Cloudflare

Cloudflare remediation should be targeted.

Examples:

- add WAF managed rules appropriate to the application
- apply rate limits to high-abuse endpoints
- add Turnstile to abuse-sensitive flows
- switch to strong origin TLS validation
- prevent direct-origin bypass
- restrict cache rules for authenticated/private content

Test legitimate traffic after edge-policy changes.

### SSH and firewall hardening

These changes can lock administrators out.

Before applying:

- preserve an existing working session
- verify alternate recovery/console access
- test config syntax
- stage rules before removing old access
- document rollback commands

AgentSec should be conservative with remote host configuration.

## Regression tests

When practical, add a test that would fail if the vulnerability returned.

Examples:

- unauthorized user cannot read another tenant's record
- dangerous HTML input is rendered safely
- admin route rejects an ordinary user
- dependency policy prevents known vulnerable version
- sensitive file is not copied to the public build directory

## Verification matrix

| Change | Minimum verification |
| --- | --- |
| dependency upgrade | package audit + project tests/build |
| auth/authz fix | targeted authorization test + project tests |
| XSS fix | rendering regression test + targeted security check |
| SQLi fix | query tests + controlled injection validation |
| web exposure fix | HTTP/path retest |
| server config | syntax/config validation + service health check |
| Cloudflare policy | expected allowed request + expected blocked/limited request |
| privilege reduction | normal application operation + denied unnecessary action |

## Reporting a completed fix

A remediation report should state:

```text
Finding:
Root cause:
Files/config changed:
Why this fixes the issue:
Tests run:
Security check rerun:
Result:
Remaining limitations:
Rollback notes, if applicable:
```

AgentSec should never claim a fix is verified when the relevant test could not be run.
