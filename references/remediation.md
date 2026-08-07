# AgentSec Remediation & Verification

Use this reference after a security issue has been confirmed.

## Contents

- Remediation principles
- Dependency remediation
- Injection and XSS
- Authentication and authorization
- Secrets
- Server and network hardening
- Directory exposure
- Verification checklist

## Remediation principles

1. Fix the root cause rather than suppressing the scanner finding.
2. Make the smallest change that reliably removes the vulnerability.
3. Preserve intended application behavior and compatibility.
4. Do not weaken another security control to make a test pass.
5. Add a regression test when the failure can be represented safely in the test suite.
6. Run normal tests/build plus the security check that originally detected the issue.
7. Clearly distinguish code changes performed from recommendations that still require an operator/deployment change.

## Dependency remediation

For vulnerable packages:

- Identify the vulnerable package, affected version range, dependency path and patched version.
- Prefer upgrading the direct dependency responsible for the vulnerable transitive package.
- Avoid unnecessary major-version jumps.
- Review lockfile changes before accepting them.
- Rerun tests/build and the dependency scanner.

For a confirmed compromised/malicious package incident, assume the issue can extend beyond dependency state. Remove the affected version and consider credential rotation, CI/developer-host review and incident response based on what the package could access.

Do not automatically use force flags that bypass peer compatibility or introduce breaking upgrades.

## Injection and XSS

### SQL injection

Replace dynamic SQL construction with parameterized queries/prepared statements. If user-controlled identifiers cannot be parameterized, map them through a strict allowlist. Preserve least-privilege database permissions.

### Command injection

Prefer library APIs over shell execution. When a subprocess is required, pass arguments as an array without invoking a shell and validate any value that selects a command/operation.

### XSS

Use the framework's escaped rendering primitives. Apply context-aware encoding for HTML/attributes/URLs/JavaScript. If the product intentionally accepts HTML, sanitize through a maintained allowlist-based sanitizer before rendering. Add CSP as defense in depth where appropriate.

## Authentication and authorization

Fix authorization server-side at the resource/action boundary. Do not rely on hidden UI, obscured URLs or client-side role checks.

For IDOR/tenant isolation issues, scope every object lookup to the authenticated principal/tenant or enforce equivalent policy before returning/mutating data.

For session/auth changes, verify login, logout, password reset, MFA/recovery, privilege changes and session invalidation behavior.

## Secrets

When a real credential/key has been exposed:

1. Revoke/rotate it at the source.
2. Replace application configuration with a secret manager or runtime-injected environment secret as appropriate.
3. Remove it from current source/build artifacts.
4. Assess repository history, CI logs, caches and published artifacts.
5. Update tests/examples to use obvious non-secret placeholders.

Deleting the string from the latest commit alone is not a complete fix.

## Server and network hardening

Before changing production server configuration:

- understand service ownership and availability impact
- preserve an administrative recovery path
- validate config syntax before reload/restart
- keep rollback instructions

Typical fixes include closing unnecessary listeners, binding internal services privately, narrowing firewall/security-group rules, patching supported versions, disabling unneeded SSH password/root access, least-privilege service users, and removing privileged container settings.

Do not blindly apply a generic hardening snippet if it can break required traffic or operations.

## Directory exposure

For a path found by Gobuster/ffuf:

1. Decide whether it should exist in the served tree.
2. If sensitive and unnecessary, remove it from the deployed web root.
3. If required but private, enforce authentication and authorization.
4. Disable directory indexing.
5. Deny source-control metadata, secret files, backups and logs where appropriate.
6. Review aliases/symlinks/static routing so an alternate route cannot expose the same file.
7. Fix deployment/build scripts that keep recreating the artifact.

Do not treat renaming `/admin` or a backup file as protection.

## Verification checklist

After each change verify:

- [ ] The original evidence no longer reproduces.
- [ ] Intended functionality still works.
- [ ] Unit/integration/build checks pass.
- [ ] Authorization is tested with at least the relevant unauthenticated/lower-privilege case.
- [ ] Dependency lockfiles are internally consistent after package changes.
- [ ] No new sensitive data was added to logs or reports.
- [ ] Server/reverse-proxy configuration validates successfully.
- [ ] External exposure matches the intended port/path inventory.
- [ ] Remaining assumptions or untestable conditions are documented.
