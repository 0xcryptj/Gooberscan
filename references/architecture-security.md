# AgentSec Architecture & Threat-Model Review

Use this reference before treating security as a list of scanner findings. The goal is to understand how the application is built, where trust changes, what identities exist, what data matters, and which security controls would reduce realistic risk.

## Architecture-first workflow

Start by running:

```bash
python3 scripts/architecture_inventory.py . --output .agentsec-architecture.json
```

Then inspect the actual repository to confirm or reject the inventory's hypotheses.

Create a compact architecture map covering:

- clients: browsers, mobile apps, CLIs, third-party integrations
- edge: DNS, CDN, Cloudflare, load balancers, reverse proxies
- application/API services
- authentication/identity provider
- privileged/admin interfaces
- background workers, queues, scheduled jobs
- databases, caches, object storage, search indexes
- payment/financial providers
- webhooks and external APIs
- CI/CD and deployment identities
- logging, monitoring, backups, alerting and incident-response paths

## Threat-model questions

For each trust boundary ask:

1. What untrusted input crosses this boundary?
2. Which identity is used on the other side?
3. What can that identity read, create, change or delete?
4. Can the caller choose another user's or tenant's object identifier?
5. Which actions have financial, privacy, administrative or irreversible impact?
6. What stops automated abuse or replay?
7. What is logged, and can an operator reconstruct a security event?
8. What happens if this component or credential is compromised?
9. Can the blast radius be reduced with narrower permissions, network boundaries or separate service identities?

## Principle of least privilege

Do not stop at application roles. Apply least privilege to every identity:

- anonymous users
- authenticated users
- moderators/operators/admins
- service accounts
- background workers
- CI/CD identities
- database users
- cache/storage credentials
- cloud IAM roles
- API tokens and OAuth scopes

Look specifically for:

- application runtime using schema-owner or database-superuser credentials
- one cloud credential shared by unrelated services
- workers that can access all data despite processing only one queue/domain
- CI jobs with write/admin tokens when read access is enough
- wildcard cloud/IAM permissions
- user-facing API tokens with scopes broader than the feature requires
- admin capabilities exposed to ordinary accounts through hidden UI rather than server authorization
- storage credentials capable of reading/writing every bucket

When proposing a fix, describe the intended permission boundary rather than merely saying "use least privilege."

## MFA, passkeys and step-up authentication

Do not blindly require MFA for every application. Evaluate it according to impact.

Strong candidates include:

- administrators and operators
- finance/refund/payout users
- developer/deployment accounts
- account recovery and security-setting changes
- destructive or high-value actions
- applications containing sensitive personal or regulated data

If the repository has authentication but no MFA markers, first verify whether MFA/passkeys are enforced by an external provider such as Auth0, Clerk, Firebase, Supabase, an enterprise IdP or SSO layer.

Possible improvements include:

- TOTP
- WebAuthn/security keys
- passkeys
- IdP-enforced MFA
- step-up authentication for dangerous actions

Recovery flows must receive the same scrutiny as the primary MFA flow. A weak recovery path can erase the value of strong authentication.

## Authorization architecture

Build an authorization matrix:

| Identity | Resource | Read | Create | Update | Delete | Administrative actions |
| --- | --- | --- | --- | --- | --- | --- |

Then verify the server enforces it.

Pay special attention to:

- multi-tenant object queries
- object ownership changes
- admin-only mutations
- APIs reachable outside the normal UI
- WebSockets and background jobs
- export/report endpoints
- billing/refund/payout actions
- invitation/team membership flows
- support impersonation features

Prefer centralized policy helpers/middleware when they reduce duplicated authorization logic, but keep resource-specific ownership and business rules close enough to the data operation that they cannot be skipped accidentally.

## Cloudflare-aware recommendations

If AgentSec detects Cloudflare or Wrangler configuration, treat Cloudflare as an available security control plane, not proof that protections are enabled.

Review the application's actual needs and plan before recommending features.

Potential controls:

- Cloudflare Managed WAF rules appropriate to the technology stack
- OWASP managed rules when available
- endpoint-specific rate limiting for login, signup, password reset, search, expensive APIs and destructive mutations
- Turnstile on abuse-sensitive forms with mandatory server-side token verification
- bot controls for scraping/automation abuse when appropriate
- Authenticated Origin Pulls and/or origin firewall rules so clients cannot bypass Cloudflare and hit the origin directly
- Full (strict) TLS to origin
- DNSSEC where operationally appropriate
- cache rules for public/static content
- explicit cache bypass for authenticated, personalized, authorization-sensitive or secret-bearing responses
- security headers at the application or edge, with one clearly owned source of truth

Never recommend "cache everything" for an authenticated application. A cache key that does not vary on the correct identity/authorization context can leak one user's response to another.

Cloudflare controls are defense in depth. Application-layer authorization, validation, parameterized queries and output encoding still matter.

## Rate limiting and anti-automation

Choose limits based on the action, not a global request number.

Different keys may be appropriate for different threats:

- account/user ID
- session ID
- API token
- IP address
- device/browser signal
- tenant ID
- a combination of identifiers

Prioritize:

- login attempts
- password reset/recovery
- account creation
- email/SMS verification sends
- MFA challenges
- invitation creation
- expensive search/report generation
- uploads
- checkout/payment mutations
- API key creation
- exports
- destructive actions

Consider both burst limits and longer abuse windows. Avoid designs that allow an attacker to trivially lock out a victim by exhausting a limit keyed only to the victim account.

## robots.txt, llms.txt and security.txt

### robots.txt

`robots.txt` is crawler policy and traffic-management metadata. It is not an access-control mechanism. Do not put a private route in `robots.txt` expecting it to become private; doing so can even advertise the route.

Recommend it only when crawler/SEO policy is useful.

### llms.txt

`llms.txt` is an emerging optional convention for giving AI systems a curated map of public website content. It is useful primarily for documentation and agent-readiness. It does not grant or deny access and should not contain private endpoints or secrets.

Treat a missing `llms.txt` as an optional product/operational recommendation, never as a security vulnerability.

### security.txt

For a public product, a well-maintained `/.well-known/security.txt` can provide a clear vulnerability-disclosure contact and policy. It improves security operations but is not itself a vulnerability-prevention control.

## Architecture-dependent security opportunities

### Background workers

Use separate service identities when workers have different jobs. Restrict queue publish/consume permissions, database access, object-storage access and secret availability to each worker's responsibility.

### Webhooks

Verify provider signatures over the exact/raw request body, enforce freshness/replay protections where available, use idempotency, and authorize any referenced internal object after signature verification.

### Payments

Treat server-side price/currency/entitlement state as authoritative. Verify webhooks, use idempotency, guard race conditions and ensure refunds/payouts require appropriate privilege and auditability.

### Object storage/uploads

Default private unless content is intentionally public. Validate uploads, isolate untrusted content from executable origins, scope credentials, bound signed-URL lifetime and prevent arbitrary object-key access across users/tenants.

### Redis/cache

Do not expose cache services publicly. Separate cache/session/queue use where blast radius matters. Never use untrusted values as raw cache keys without considering tenant/user isolation and cache poisoning.

### GraphQL

Review resolver-level authorization, object access, introspection policy, query depth/complexity, batching abuse and data over-fetching. Edge rate limits do not replace resolver authorization.

## Security architecture output

AgentSec should distinguish three classes:

### Confirmed vulnerability

Evidence proves an exploitable or unsafe condition exists.

### Security design gap

Architecture evidence shows a missing or weak control with a concrete risk, but it may not be directly exploitable by itself.

### Security opportunity

A defense-in-depth or operational improvement that would strengthen the system but should not be represented as a vulnerability.

For every recommendation include:

- evidence from the repo/runtime
- confidence level
- affected trust boundary or identity
- threat/risk reduced
- proposed control
- implementation location
- possible compatibility/operational cost
- verification method
