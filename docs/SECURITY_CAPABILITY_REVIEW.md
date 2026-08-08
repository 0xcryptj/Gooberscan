# AgentSec security capability review

Date: 2026-08-08

This is a repository-grounded capability review. The fixtures are local and
synthetic; no third-party system was scanned or contacted. The evaluation
prompt was:

> Use AgentSec to audit this project. Understand the architecture first,
> identify the highest-priority security problems, propose the simplest safe
> fixes, and explain how you would verify them.

## Assessment before the changes

AgentSec already had the right operating model: architecture-first review,
trust-boundary mapping, server-side authorization, least privilege, explicit
authorization boundaries, remediation guidance, and regression verification.
The references already called out IDOR, tenant isolation, admin-route exposure,
account recovery and authentication weaknesses.

The important gap was evidence routing. `architecture_inventory.py` detected
generic auth/database/role markers, but did not expose the BaaS-specific
surfaces needed to guide a coding agent toward RLS/security rules, policy
expressions, RPC grants, `SECURITY DEFINER`, storage policies, or public-client
credential context. It also did not enumerate alternate identity-changing
routes. In addition, the shell wrapper wrote architecture evidence for the
AgentSec checkout rather than the repository passed to `agentsec repo <path>`.

Therefore, before this review AgentSec handled these classes conceptually but
not reliably enough as a repeatable capability:

- Scenario 1: partial. It could recommend least-privilege database review, but
  did not reliably distinguish a normal anon key from the policy failure behind
  it.
- Scenario 2: partial. It could ask for server-side authorization, but had no
  deterministic evidence path for identity truth tables, function grants, or
  definer/invoker boundaries.
- Scenario 3: partial. It recognized authentication, but did not explicitly
  model alternate registration/verification/recovery paths against an SSO or
  invitation-only policy.

## Changes made

1. Extended `scripts/architecture_inventory.py` with line-numbered, bounded
   evidence for:
   - Supabase/Firebase/Appwrite/PocketBase indicators and migrations.
   - RLS enablement, policies, `auth.uid()`/`auth.role()`, RPC/functions,
     `SECURITY DEFINER`, grants/revokes and storage policy evidence.
   - Browser-visible publishable/anon client credential indicators.
   - Authentication and identity-changing routes plus SSO/private/invitation
     policy indicators.
   - Actual `TO anon/public` grants, avoiding false positives from names such
     as `public.change_grade`.
2. Added explicit AgentSec guidance for effective BaaS permissions, public
   credential versus secret distinction, authorization matrices and fail-closed
   semantics, and complete authentication state-machine review.
3. Updated architecture, repository-security and remediation references with
   the same generalized reasoning and negative-verification requirements.
4. Fixed `agentsec repo <path>` so architecture evidence is written for the
   target repository. Direct Python audits now record their own target-scoped
   architecture inventory too.
5. Avoided blocking source-only npm audits on `npm audit signatures` when no
   lockfile exists; the check is skipped with an explicit reason.
6. Added paired local vulnerable/secure fixtures and regression tests in
   `tests/fixtures/capability/` and `tests/test_security_capability.py`.

No vendor or incident names are used in the implementation. The signals are
generic evidence indexes; an agent must inspect policy semantics and runtime
configuration before calling a condition a confirmed vulnerability.

## Evaluation results

| Capability | Vulnerable fixture | Secure control | Result |
| --- | --- | --- | --- |
| Supabase effective permissions | Detected Supabase, public client key, missing RLS, anon grants, and a definer function | Preserved public client key, detected RLS/owner policies, no `TO anon` grant, no definer function | Distinguishes the real policy issue from key presence |
| Authorization inversion/RPC boundary | Detected `auth.role()`, a definer function, and anon `EXECUTE`; directs matrix/truth-table review | Detected authenticated identity checks and authenticated grant, with no anon grant or definer function | Surfaces the boundary without matching one exact vulnerable line |
| SSO/invitation alternate path | Detected policy plus registration, OTP verification and SSO routes | Detected the same routes and policy, correctly retaining review because route presence alone is not proof of a bypass | Guides complete path comparison; semantic confirmation remains agent work |

All six fixtures completed through the normal `./agentsec repo <path>` entry
point. Each generated a target-specific architecture inventory and report.
The deterministic regression suite passes 8/8 tests. Optional OSV-Scanner,
Trivy, Semgrep and Gitleaks were unavailable in this environment. npm advisory
refresh reported network errors for the synthetic fixtures and was not treated
as a security conclusion.

## Verification expectations

AgentSec should require negative tests, not just a successful login or query:

- anonymous callers cannot read or mutate protected records or invoke sensitive
  RPCs;
- User A cannot access User B or another tenant;
- non-admins cannot invoke admin/destructive operations;
- service-role credentials never reach browser/client code;
- direct storage/API/RPC calls enforce the same policy as the UI; and
- alternate registration, OTP, invitation, recovery, activation, OAuth/SSO and
  MFA paths cannot bypass the intended identity policy.

## Remaining blind spots

This is a reasoning aid, not a proof engine. It cannot infer deployed provider
settings, effective grants from a remote database, policy truth tables across
dynamic SQL, whether a route is actually mounted, or whether an external IdP
enforces a control. It can miss unconventional naming, generated routes,
framework-specific policy files and authorization assembled dynamically. The
coding agent must inspect surrounding code, deployment configuration and—when
authorized—run safe direct negative tests. A public client credential can also
be valid and safe, while a secret can be mislabeled; classification requires
context and rotation guidance when actual exposure is confirmed.

## Defensible product wording

> AgentSec is designed to help coding agents identify and remediate classes of
> application-security failures involving missing or overly permissive
> database/RLS controls, dangerously broad client-accessible permissions,
> authorization logic inversions, anonymous access to sensitive functions,
> object/tenant authorization gaps, and alternate authentication paths that
> bypass SSO, invitations, MFA, or private-app policies. It distinguishes
> public client identifiers from secrets, uses deterministic architecture
> evidence to focus review, and expects negative security tests to verify fixes.
> It does not guarantee detection or replace provider/runtime validation,
> authorized testing, or expert review.
