#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

IGNORE_DIRS = {
    ".git", "node_modules", ".next", "dist", "build", "coverage",
    ".venv", "venv", "__pycache__", ".agentsec", "vendor", "target"
}

TEXT_SUFFIXES = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rs",
    ".java", ".kt", ".rb", ".php", ".cs", ".json", ".toml", ".yaml", ".yml",
    ".md", ".html", ".htm", ".conf", ".ini", ".env", ".sh", ".tf", ".sql"
}

MAX_FILE_BYTES = 750_000
MAX_FILES = 5000


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def read_text(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def collect_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        base_path = Path(base)
        for name in names:
            p = base_path / name
            if p.suffix.lower() in TEXT_SUFFIXES or name in {
                "Dockerfile", "Procfile", "Caddyfile", "nginx.conf",
                "package.json", "wrangler.toml", "wrangler.jsonc",
                "robots.txt", "llms.txt", "security.txt",
            }:
                files.append(p)
                if len(files) >= MAX_FILES:
                    return files
    return files


def package_info(root: Path) -> tuple[dict, set[str]]:
    pj = root / "package.json"
    if not pj.exists():
        return {}, set()
    try:
        data = json.loads(pj.read_text(encoding="utf-8"))
    except Exception:
        return {}, set()
    deps = {}
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps.update(data.get(key, {}) or {})
    return data, set(deps)


def any_dep(deps: set[str], names: set[str]) -> bool:
    return any(d in deps for d in names)


def scan_patterns(files: list[Path], root: Path) -> dict[str, list[str]]:
    patterns = {
        "auth_markers": re.compile(r"\b(next-auth|authjs|passport|clerk|auth0|firebase.?auth|supabase.?auth|lucia|better-auth|oauth|openid|oidc|session|jwt)\b", re.I),
        "mfa_markers": re.compile(r"\b(mfa|2fa|two.?factor|totp|webauthn|passkey|passkeys|fido2|authenticator)\b", re.I),
        "admin_role_markers": re.compile(r"\b(admin|administrator|superuser|owner|moderator|role|permission|rbac|acl)\b", re.I),
        "rate_limit_markers": re.compile(r"\b(rate.?limit|ratelimit|rate_limit|throttl|upstash.?ratelimit|slowDown)\b", re.I),
        "cloudflare_markers": re.compile(r"\b(cloudflare|wrangler|cf-ray|cf-connecting-ip|turnstile)\b", re.I),
        "csp_markers": re.compile(r"\b(content-security-policy|helmet|frame-ancestors|script-src|default-src)\b", re.I),
        "csrf_markers": re.compile(r"\b(csrf|xsrf|sameSite)\b", re.I),
        "db_markers": re.compile(r"\b(prisma|drizzle|sequelize|typeorm|knex|mongoose|mongodb|postgres|postgresql|mysql|mariadb|sqlite|supabase)\b", re.I),
        "queue_worker_markers": re.compile(r"\b(bullmq|celery|sidekiq|worker|queue|cron|scheduler|background job)\b", re.I),
        "object_storage_markers": re.compile(r"\b(s3|r2|bucket|blob storage|cloudinary|supabase storage)\b", re.I),
        "payments_markers": re.compile(r"\b(stripe|braintree|adyen|checkout\.com|paypal|coinbase commerce)\b", re.I),
        "webhook_markers": re.compile(r"\b(webhook|svix)\b", re.I),
        "graphql_markers": re.compile(r"\b(graphql|apollo|urql)\b", re.I),
        "redis_markers": re.compile(r"\b(redis|upstash)\b", re.I),
        "terraform_markers": re.compile(r"\b(terraform|required_providers|resource\s+\")", re.I),
    }
    hits: dict[str, list[str]] = {k: [] for k in patterns}
    for p in files:
        text = read_text(p)
        if not text:
            continue
        rp = rel(p, root)
        for name, pattern in patterns.items():
            if pattern.search(text) and len(hits[name]) < 25:
                hits[name].append(rp)
    return hits


def detect_public_dirs(root: Path) -> list[Path]:
    candidates = [
        root / "public", root / "static", root / "www", root / "web",
        root / "src" / "main" / "resources" / "static"
    ]
    return [p for p in candidates if p.is_dir()]


def has_named_file(root: Path, name: str, public_dirs: list[Path]) -> list[str]:
    found = []
    direct = root / name
    if direct.exists():
        found.append(rel(direct, root))
    for d in public_dirs:
        p = d / name
        if p.exists():
            found.append(rel(p, root))
    return found


def add_opportunity(items, *, title, category, confidence, evidence, why, action, security=True):
    items.append({
        "title": title,
        "category": category,
        "confidence": confidence,
        "security_control": security,
        "evidence": evidence,
        "why": why,
        "recommended_action": action,
    })


def analyze(root: Path) -> dict:
    files = collect_files(root)
    package, deps = package_info(root)
    hits = scan_patterns(files, root)
    public_dirs = detect_public_dirs(root)

    frameworks = []
    framework_map = {
        "next": {"next"},
        "react": {"react"},
        "express": {"express"},
        "fastify": {"fastify"},
        "nestjs": {"@nestjs/core"},
        "nuxt": {"nuxt"},
        "sveltekit": {"@sveltejs/kit"},
        "remix": {"@remix-run/react"},
        "hono": {"hono"},
    }
    for name, markers in framework_map.items():
        if any_dep(deps, markers):
            frameworks.append(name)

    auth_deps = {
        "next-auth", "@auth/core", "passport", "@clerk/nextjs", "@clerk/clerk-sdk-node",
        "auth0", "@auth0/nextjs-auth0", "firebase", "@supabase/supabase-js",
        "lucia", "better-auth"
    }
    db_deps = {
        "@prisma/client", "prisma", "drizzle-orm", "sequelize", "typeorm", "knex",
        "mongoose", "mongodb", "pg", "mysql", "mysql2", "@supabase/supabase-js"
    }

    config_files = {
        "docker": [rel(p, root) for p in files if p.name == "Dockerfile" or p.name.startswith("docker-compose")],
        "cloudflare": [rel(p, root) for p in files if p.name in {"wrangler.toml", "wrangler.jsonc"}],
        "terraform": [rel(p, root) for p in files if p.suffix == ".tf"],
        "github_actions": [rel(p, root) for p in files if ".github/workflows/" in rel(p, root).replace("\\", "/")],
    }

    signals = {
        "frameworks": frameworks,
        "auth_present": bool(any_dep(deps, auth_deps) or hits["auth_markers"]),
        "mfa_or_passkey_markers": hits["mfa_markers"],
        "role_or_permission_markers": hits["admin_role_markers"],
        "database_present": bool(any_dep(deps, db_deps) or hits["db_markers"]),
        "cloudflare_present": bool(config_files["cloudflare"] or hits["cloudflare_markers"]),
        "rate_limit_markers": hits["rate_limit_markers"],
        "csp_markers": hits["csp_markers"],
        "csrf_markers": hits["csrf_markers"],
        "queue_or_worker_markers": hits["queue_worker_markers"],
        "object_storage_markers": hits["object_storage_markers"],
        "payment_markers": hits["payments_markers"],
        "webhook_markers": hits["webhook_markers"],
        "graphql_markers": hits["graphql_markers"],
        "redis_markers": hits["redis_markers"],
        "public_directories": [rel(p, root) for p in public_dirs],
        "robots_txt": has_named_file(root, "robots.txt", public_dirs),
        "llms_txt": has_named_file(root, "llms.txt", public_dirs),
        "security_txt": has_named_file(root, "security.txt", public_dirs)
                        + ([rel(root / ".well-known" / "security.txt", root)] if (root / ".well-known" / "security.txt").exists() else []),
        "config_files": config_files,
        "package_manager": "npm" if (root / "package-lock.json").exists() else ("pnpm" if (root / "pnpm-lock.yaml").exists() else ("yarn" if (root / "yarn.lock").exists() else None)),
    }

    opportunities = []

    if signals["auth_present"]:
        if not signals["mfa_or_passkey_markers"]:
            add_opportunity(
                opportunities,
                title="Evaluate MFA/passkeys for privileged and high-impact accounts",
                category="identity",
                confidence="review-needed",
                evidence=["Authentication indicators detected; no local MFA/passkey markers found."],
                why="A second factor can materially reduce account-takeover risk, especially for administrators, operators, finance users, and destructive actions.",
                action="Inspect the identity provider and account roles. If MFA is not already enforced upstream, add TOTP/WebAuthn/passkey support or require step-up authentication for sensitive actions."
            )
        if signals["role_or_permission_markers"]:
            add_opportunity(
                opportunities,
                title="Perform a least-privilege authorization pass",
                category="authorization",
                confidence="high-value-review",
                evidence=signals["role_or_permission_markers"][:8],
                why="Role/permission-bearing applications are prone to privilege creep and horizontal/vertical authorization gaps.",
                action="Map roles to required actions/resources, enforce authorization server-side at each boundary, remove unused permissions, and separate normal-user, admin, service, and background-worker privileges."
            )

    if signals["database_present"]:
        add_opportunity(
            opportunities,
            title="Verify least-privilege database identities",
            category="data",
            confidence="high-value-review",
            evidence=hits["db_markers"][:8] or ["Database dependency detected."],
            why="Applications usually do not need schema-owner or superuser privileges at runtime.",
            action="Separate migration/admin credentials from runtime credentials. Grant the runtime identity only required schemas/tables/actions and restrict database network exposure."
        )

    if signals["queue_or_worker_markers"]:
        add_opportunity(
            opportunities,
            title="Separate worker/service privileges",
            category="architecture",
            confidence="review-needed",
            evidence=signals["queue_or_worker_markers"][:8],
            why="Background workers often accumulate broad credentials even when each worker needs only a narrow subset.",
            action="Create task-specific service identities and secret scopes for workers; separate queue publish/consume permissions and database/storage access by job responsibility."
        )

    if signals["object_storage_markers"]:
        add_opportunity(
            opportunities,
            title="Review object-storage access boundaries",
            category="storage",
            confidence="review-needed",
            evidence=signals["object_storage_markers"][:8],
            why="Public buckets, broad write permissions, and long-lived signed URLs can expose user data or enable content abuse.",
            action="Classify public vs private objects, default private, scope bucket credentials, bound signed-URL lifetime, validate uploads, and separate user-controlled content from executable application assets."
        )

    if signals["webhook_markers"]:
        add_opportunity(
            opportunities,
            title="Verify webhook authenticity and replay protection",
            category="integrations",
            confidence="review-needed",
            evidence=signals["webhook_markers"][:8],
            why="Webhook endpoints are unauthenticated Internet ingress unless requests are cryptographically verified.",
            action="Verify provider signatures over the raw body, validate timestamp/nonce where supported, enforce replay windows, and make handlers idempotent."
        )

    if signals["payment_markers"]:
        add_opportunity(
            opportunities,
            title="Threat-model payment and financial state transitions",
            category="business-logic",
            confidence="high-value-review",
            evidence=signals["payment_markers"][:8],
            why="Payment systems need strong webhook validation, idempotency, authorization, amount/currency integrity, and race-condition controls beyond generic scanners.",
            action="Trace quote/order/payment/refund flows end-to-end and ensure server-side authority for price, currency, entitlement, refund, and settlement state."
        )

    if signals["cloudflare_present"]:
        add_opportunity(
            opportunities,
            title="Use Cloudflare as a security control plane",
            category="edge-security",
            confidence="stack-detected",
            evidence=(config_files["cloudflare"] + hits["cloudflare_markers"])[:8],
            why="When Cloudflare already fronts an application, WAF, rate limiting, bot controls, Turnstile, and origin protection can reduce attack traffic before it reaches the app.",
            action="Review plan-appropriate Managed WAF rules, rate limits for login/signup/password-reset/API abuse, Turnstile for abuse-sensitive forms, and origin lockdown/Authenticated Origin Pulls. Cache only content that is safe to share across users; bypass personalized or authorization-sensitive responses."
        )
        if not signals["rate_limit_markers"]:
            add_opportunity(
                opportunities,
                title="Add endpoint-specific abuse controls",
                category="edge-security",
                confidence="review-needed",
                evidence=["Cloudflare detected; no repository-local rate-limit markers found."],
                why="Authentication, signup, reset, expensive search, mutation, and API endpoints commonly need abuse controls.",
                action="Implement rate limits in Cloudflare and/or the application using a key appropriate to the action (account/session/API token/IP), with observability and safe failure behavior."
            )

    if not signals["csp_markers"] and frameworks:
        add_opportunity(
            opportunities,
            title="Evaluate a Content Security Policy",
            category="browser-security",
            confidence="review-needed",
            evidence=[f"Web framework detected: {', '.join(frameworks)}; no obvious CSP marker found."],
            why="A well-designed CSP limits the impact of script injection and unsafe third-party content.",
            action="Inventory required script/style/connect/frame origins, start with report-only if needed, remove unsafe inline/eval dependencies where practical, then enforce a nonce/hash-based policy."
        )

    if public_dirs:
        if not signals["robots_txt"]:
            add_opportunity(
                opportunities,
                title="Consider robots.txt for crawler policy",
                category="operational-hygiene",
                confidence="optional",
                evidence=[f"Public directory detected: {rel(public_dirs[0], root)}; robots.txt not found."],
                why="robots.txt can communicate crawl preferences and reduce unwanted crawler load, but it is not an access-control or secrecy mechanism.",
                action="Add robots.txt only for crawler-management/SEO goals. Protect private content with authentication/authorization or remove it from public hosting.",
                security=False,
            )
        if not signals["llms_txt"]:
            add_opportunity(
                opportunities,
                title="Consider llms.txt for AI-readable documentation",
                category="agent-readiness",
                confidence="optional",
                evidence=[f"Public directory detected: {rel(public_dirs[0], root)}; llms.txt not found."],
                why="llms.txt is an emerging optional convention for giving AI agents a curated map of public site content. It does not control access.",
                action="For documentation-heavy or developer-facing products, consider a concise public llms.txt. Never list secrets or private endpoints and do not treat omission as protection.",
                security=False,
            )

    if not signals["security_txt"]:
        add_opportunity(
            opportunities,
            title="Consider a security.txt disclosure contact",
            category="security-operations",
            confidence="optional",
            evidence=["No obvious security.txt file found in common repository locations."],
            why="A published vulnerability-disclosure contact gives researchers a clear path to report security issues.",
            action="If the project has a public website, consider RFC 9116-style `/.well-known/security.txt` with a monitored security contact and policy URL.",
            security=False,
        )

    return {
        "tool": "AgentSec architecture inventory",
        "root": str(root),
        "files_considered": len(files),
        "signals": signals,
        "opportunities": opportunities,
        "agent_review_required": [
            "Map trust boundaries: browser/client, edge/CDN, app, API, workers, database, cache, object storage, third parties, admin plane, CI/CD.",
            "Identify identities: anonymous users, normal users, privileged users, service accounts, workers, deployers, database roles, cloud identities.",
            "Classify sensitive assets and destructive/high-value actions.",
            "Trace authorization at every resource/action boundary, including tenant isolation.",
            "Compare each identity's permissions with the minimum required for its function.",
            "Assess MFA/step-up authentication based on account privilege and action impact.",
            "Review recovery flows, sessions, rate limits, abuse controls, audit logs, secrets, backups, and incident-response hooks.",
            "Distinguish architecture improvements from confirmed vulnerabilities. Do not claim a missing control without checking external identity/edge configuration when it may live outside the repo."
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory a repository so AgentSec can perform architecture-aware security review.")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--output", default="-", help="JSON output path, or - for stdout")
    args = parser.parse_args()
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        parser.error(f"not a directory: {root}")
    data = analyze(root)
    text = json.dumps(data, indent=2)
    if args.output == "-":
        print(text)
    else:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
