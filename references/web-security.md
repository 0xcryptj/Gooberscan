# AgentSec Web Application Security

Use this reference for authorized web-application review, external exposure checks, and remediation.

## Contents

- Baseline workflow
- Directory and file exposure
- XSS
- SQL injection
- Authentication and authorization
- Sessions, cookies, and CSRF
- Headers, CORS, and TLS
- APIs and uploads
- Verification

## Baseline workflow

1. Identify framework, reverse proxy/CDN, authentication model, API surface, and deployment environment.
2. Inspect response headers and TLS before active testing.
3. With authorization, enumerate exposed paths conservatively and run baseline scanners.
4. Correlate scanner findings with application source/configuration when available.
5. Use active SQLi/XSS validation only for explicitly authorized scope.
6. Remediate the root cause, then retest the exact route plus application tests.

## Directory and file exposure

Gobuster/ffuf findings are not vulnerabilities by themselves. For every discovered path determine whether an unauthenticated Internet user is supposed to see it.

Prioritize:

- `.git/`, `.svn/`, `.hg/`
- `.env`, environment backups, `.npmrc`, credentials and service-account files
- database dumps and SQLite files
- `.bak`, `.old`, `.backup`, editor swap files and archives
- logs, debug endpoints, profiler endpoints and trace files
- `/admin`, dashboards, control panels and management APIs
- `/server-status`, `/server-info`, `/phpinfo.php`
- source maps containing private source or secrets
- generated security reports
- internal API documentation if it exposes sensitive implementation details
- upload directories that permit script execution or content-type confusion
- cloud/storage proxy routes that expose private objects

### Hardening against directory enumeration

Do not rely on unguessable path names. Assume attackers can enumerate routes.

Use these controls instead:

- Keep secrets, backups, logs and databases outside the web/document root.
- Disable directory indexing/autoindex.
- Require authentication and authorization on every sensitive route, including direct child routes.
- Return deliberate 401/403/404 responses without leaking filesystem paths.
- Deny dotfiles and source-control metadata at the reverse proxy where appropriate.
- Separate public static assets from private application storage.
- Ensure backup/deploy tooling does not write archives into the served tree.
- Prevent symlink/alias configuration from escaping the intended document root.
- Test alternate hostnames and reverse-proxy routes so protections are not only applied on one virtual host.

Example Nginx concepts to review:

```nginx
autoindex off;

location ~ /\. {
    deny all;
}
```

Do not paste a generic deny rule blindly. Check framework requirements such as `.well-known` before applying it.

For Apache, review `Options Indexes`, `AllowOverride`, `<Directory>` blocks, aliases, and rewrite rules. Remove `Indexes` unless directory listing is deliberately required.

## XSS

Trace attacker-controlled data to output contexts.

Check:

- server-rendered templates
- React/Vue/Svelte escape hatches such as raw HTML directives
- DOM sinks such as `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, unsafe URL assignment, or dynamic script creation
- markdown/WYSIWYG renderers
- stored profile/content fields
- URL query/hash values rendered client-side
- error messages and search results

Prefer contextual output encoding and safe framework primitives. Sanitizers are appropriate when intentionally allowing a restricted HTML subset, but configure them strictly and keep them updated.

CSP is defense in depth, not a substitute for fixing the unsafe sink.

## SQL injection

Look for string concatenation, interpolation, dynamic fragments, raw ORM queries, stored procedure construction, and user-controlled identifiers/order clauses.

Preferred remediation:

- parameterized queries/prepared statements
- safe ORM query builders
- allowlists for identifiers or sort directions that cannot be parameterized
- least-privilege database credentials

Do not claim SQL injection solely because a scanner sees a database-like error. Confirm the input reaches a query in an unsafe way or controlled authorized validation demonstrates it.

## Authentication and authorization

Review:

- login rate limiting and lockout design
- MFA enrollment/recovery/bypass paths
- password reset token entropy, expiry, single-use enforcement and account binding
- session invalidation after password reset/security changes
- OAuth/OIDC `state`, PKCE, nonce, redirect URI and issuer/audience checks
- server-side authorization on every object/function, not just hidden UI controls
- horizontal and vertical privilege boundaries
- tenant scoping in database queries and caches
- admin APIs, background jobs and WebSockets

## Sessions, cookies, and CSRF

For sensitive session cookies prefer:

- `Secure`
- `HttpOnly`
- appropriate `SameSite`
- narrow `Domain` and `Path`
- rotation on authentication/privilege change
- server-side revocation or bounded lifetime where appropriate

Cookie-authenticated state-changing routes need CSRF defenses unless the architecture provides an equivalent robust control.

## Headers, CORS, and TLS

Review:

- Content-Security-Policy
- Strict-Transport-Security when the site is consistently HTTPS
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy where useful
- clickjacking protection through CSP `frame-ancestors` or legacy X-Frame-Options
- cache controls on sensitive responses

CORS must reflect the actual trust boundary. Never combine credentialed cross-origin requests with indiscriminate origin reflection or a broad trusted-origin pattern.

TLS review should flag obsolete protocols, weak ciphers, invalid/expired certificates, incomplete chains and unexpected plaintext listeners.

## APIs and uploads

Check APIs for:

- object/function-level authorization
- mass assignment
- excessive data exposure
- unsafe filtering/query features
- unbounded pagination/query complexity
- missing rate limits on expensive/sensitive actions
- webhook signature validation and replay protection

For uploads validate type by content where possible, rename server-side, store outside executable web roots, cap size, scan when appropriate, and serve user content with safe content-type/disposition behavior.

## Verification

After remediation:

1. Rerun the exact scanner/check that found the issue.
2. Test unauthenticated and lower-privilege access paths.
3. Test a valid expected workflow to catch regressions.
4. Confirm reverse-proxy/CDN configuration matches local application behavior.
5. Record any item that cannot be verified from the available environment.
