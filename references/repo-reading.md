# Token-Efficient Repository Reading

AgentSec is meant to live inside coding agents, where context is expensive. Do not read an entire repository line by line before forming a security model.

## Goal

Build the smallest useful security map first. Spend tokens only where architecture, risk, or scanner evidence justifies deeper inspection.

## KISS rule

Apply **KISS: Keep It Simple, Stupid.** Security should be understandable, maintainable, and difficult to misuse. Prefer the smallest control that materially reduces risk. Do not create obscure security architecture merely to make the system look sophisticated.

## Progressive repository workflow

### Pass 1: repository shape

Inspect names and metadata before file contents.

Prioritize:

- top-level tree and major directories
- `package.json`, lockfiles, `pyproject.toml`, `requirements.txt`, `go.mod`, `Cargo.toml`
- framework and runtime configuration
- Dockerfiles and compose files
- CI workflows
- IaC and cloud configuration
- reverse-proxy/server configuration
- auth/provider configuration
- database schema and migrations
- environment examples, never secret values
- public/static directories
- entry points and route definitions

Normally ignore generated/vendor trees unless a finding points there:

- `.git`
- `node_modules`
- `.venv`, `venv`
- `dist`, `build`, `.next`
- coverage output
- generated SDKs and vendored libraries
- `.agentsec` reports

### Pass 2: build the security map

Identify only what is needed to understand attack surface:

- public entry points and privileged routes
- authentication and session implementation
- authorization checks and role boundaries
- data stores and sensitive data
- external APIs and webhooks
- workers, jobs, queues, and automation
- cloud/edge providers
- deployment and CI identities
- file upload/storage paths

Do not recursively open every file. Search for framework- and risk-specific symbols, then inspect the surrounding implementation.

### Pass 3: prioritize hot paths

Spend most review tokens on code that can change authority, money, data, or execution:

- login, signup, reset, recovery, MFA, and sessions
- admin and internal APIs
- authorization middleware
- database query construction
- command/process execution
- template/HTML rendering
- URL fetchers and webhook handlers
- uploads and filesystem access
- payment or irreversible actions
- secret handling
- CI/deployment workflows
- IAM and infrastructure policy

### Pass 4: use evidence to fan out

Scanner output should narrow reading rather than force a full-repo reread.

Examples:

- a vulnerable npm package -> inspect the direct dependency path and whether the package executes in production/build/CI
- a possible SQL injection -> inspect only the route, validation, query builder, and affected data boundary
- an exposed backup path -> inspect public-root/deployment/proxy configuration
- an overbroad cloud role -> inspect the service using that identity and the resources it actually needs

### Pass 5: summarize before reading more

Maintain a compact working model:

- stack
- entry points
- identities
- trust boundaries
- sensitive assets
- high-risk files
- confirmed findings
- unresolved questions

If new reading does not answer one of those questions or validate a finding, it probably does not deserve context yet.

## Large repositories

For monorepos or very large repositories:

1. identify deployable applications/services first
2. audit internet-facing and privileged services before libraries
3. read shared auth/security packages early
4. sample generated/configured surfaces rather than indexing everything into context
5. review changed files first when auditing a PR or recent change
6. use manifests, dependency graphs, search, AST/static analysis, and scanner output as indexes into the codebase

## Expected outcome

The agent should be able to explain the system in a few paragraphs before deep review. If it cannot, it should gather targeted architecture evidence rather than reading more code indiscriminately.
