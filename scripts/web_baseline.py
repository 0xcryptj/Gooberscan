#!/usr/bin/env python3
"""Bounded, low-rate black-box web baseline checks."""

from __future__ import annotations

import json
import hashlib
from collections import Counter
from pathlib import Path
import re
import subprocess
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener


USER_AGENT = "AgentSec/1.2 (+authorized defensive security audit)"
PATHS = {
    "/robots.txt": "crawler-policy",
    "/sitemap.xml": "site-map",
    "/.well-known/security.txt": "security-contact",
    "/.git/HEAD": "git-metadata",
    "/.env": "environment-file",
    "/server-status": "server-status",
    "/actuator/env": "actuator-environment",
    "/phpinfo.php": "php-info",
    "/backup.zip": "backup-archive",
    "/config.json": "configuration-file",
    "/api": "api-root",
    "/graphql": "graphql-endpoint",
    "/swagger.json": "openapi-spec",
    "/openapi.json": "openapi-spec",
}


def _curl_fetch(url: str, timeout: int) -> dict[str, Any] | None:
    """Fallback for environments where Python's TLS path cannot reach a site."""
    try:
        headers = subprocess.run(
            ["curl", "-sSIL", "--location", "--max-time", str(timeout), "--connect-timeout", "5", url],
            capture_output=True, text=True, timeout=timeout + 2, check=False,
        )
        body = subprocess.run(
            ["curl", "-sSL", "--max-time", str(timeout), "--connect-timeout", "5", url],
            capture_output=True, text=True, timeout=timeout + 2, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if headers.returncode != 0 and body.returncode != 0:
        return None
    header_blocks = re.split(r"\r?\n\r?\n", headers.stdout.strip())
    block = header_blocks[-1] if header_blocks else headers.stdout
    status_lines = re.findall(r"HTTP/\S+\s+(\d+)", block)
    status = int(status_lines[-1]) if status_lines else None
    parsed_headers: dict[str, str] = {}
    for line in block.splitlines()[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            parsed_headers[key.lower()] = value.strip()
    return {"url": url, "final_url": url, "status": status, "headers": parsed_headers, "body_sample": body.stdout[:100_000], "error": None}


def _fetch(opener, url: str, timeout: int = 8) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(100_000)
            return {
                "url": url,
                "final_url": response.geturl(),
                "status": response.status,
                "headers": {k.lower(): v for k, v in response.headers.items()},
                "body_sample": body.decode("utf-8", errors="replace"),
                "error": None,
            }
    except HTTPError as exc:
        return {
            "url": url,
            "final_url": exc.geturl(),
            "status": exc.code,
            "headers": {k.lower(): v for k, v in exc.headers.items()},
            "body_sample": "",
            "error": str(exc),
        }
    except (OSError, URLError) as exc:
        fallback = _curl_fetch(url, timeout)
        if fallback is not None:
            return fallback
        return {"url": url, "final_url": url, "status": None, "headers": {}, "body_sample": "", "error": str(exc)}


def _observation(title: str, category: str, status: str, detail: str, recommendation: str, *, security_control: bool = True) -> dict[str, Any]:
    return {
        "title": title,
        "category": category,
        "status": status,
        "security_control": security_control,
        "detail": detail,
        "recommendation": recommendation,
    }


def analyze_responses(root: dict[str, Any], paths: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    headers = root.get("headers", {})
    root_body = root.get("body_sample", "")
    if root.get("status") is None and root.get("error"):
        return [_observation(
            "Target baseline unavailable", "availability", "review-needed",
            f"The root request did not complete: {root.get('error')}",
            "Verify DNS, TLS, routing, and the authorized assessment path before interpreting endpoint results.",
        )]
    root_fingerprint = hashlib.sha256(root_body.encode("utf-8", errors="replace")).hexdigest() if root_body else None
    # SPA hosts frequently return HTTP 200 plus the same HTML shell for every
    # unknown path. If the root body was unavailable (for example, a proxy
    # returned headers separately), infer the shared shell from repeated probe
    # responses instead of treating every path as exposed.
    html_probe_fingerprints = Counter(
        hashlib.sha256(str(response.get("body_sample", "")).encode("utf-8", errors="replace")).hexdigest()
        for response in paths.values()
        if response.get("status") == 200
        and "html" in str((response.get("headers") or {}).get("content-type", "")).lower()
        and response.get("body_sample")
    )
    shared_html_fingerprints = {fingerprint for fingerprint, count in html_probe_fingerprints.items() if count >= 2}
    expected_headers = {
        "content-security-policy": "Define a CSP appropriate to the application and enforce it server-side.",
        "x-content-type-options": "Send X-Content-Type-Options: nosniff.",
        "referrer-policy": "Set an explicit restrictive Referrer-Policy.",
        "permissions-policy": "Set Permissions-Policy for browser capabilities the app does not use.",
    }
    missing = [name for name in expected_headers if name not in headers]
    if missing:
        observations.append(_observation(
            "Missing browser security headers", "headers", "review-needed",
            "Not observed: " + ", ".join(missing),
            "Add the missing headers at the application or edge layer, then verify routes with different content types.",
        ))
    else:
        observations.append(_observation("Baseline browser security headers present", "headers", "observed", "The selected baseline headers were present on the final response.", "Keep them covered by regression tests."))

    if headers.get("access-control-allow-origin", "").strip() == "*":
        observations.append(_observation(
            "Wildcard CORS policy observed", "cors", "review-needed",  # agentsec: ignore
            "The final response sends Access-Control-Allow-Origin: *.",  # agentsec: ignore
            "Confirm that every public response can be shared cross-origin; restrict origins and credentials for authenticated APIs.",
        ))

    cookies = headers.get("set-cookie", "")
    if cookies:
        cookie_text = cookies.lower()
        weak = []
        if "secure" not in cookie_text:
            weak.append("Secure")
        if "httponly" not in cookie_text:
            weak.append("HttpOnly")
        if "samesite" not in cookie_text:
            weak.append("SameSite")
        if weak:
            observations.append(_observation(
                "Cookie attributes need review", "cookies", "review-needed",
                "A response cookie did not visibly include: " + ", ".join(weak),
                "Inspect session and state-changing cookies individually and set Secure, HttpOnly, and an appropriate SameSite policy.",
            ))
    else:
        observations.append(_observation("No response cookie observed", "cookies", "not-observed", "The selected response did not set a cookie.", "Review authenticated routes separately; this does not prove session cookies are safe."))

    for path, response in paths.items():
        status = response.get("status")
        final_url = response.get("final_url", path)
        body = response.get("body_sample", "")
        content_type = response.get("headers", {}).get("content-type", "").lower()
        soft_404 = bool(
            status == 200
            and root_fingerprint
            and hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest() == root_fingerprint
        )
        if not soft_404 and status == 200 and "html" in content_type and body:
            soft_404 = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest() in shared_html_fingerprints
        if path == "/robots.txt":
            if status == 200 and not soft_404 and "html" not in content_type and body.strip():
                observations.append(_observation("robots.txt present", "crawler-policy", "observed", "A crawler policy is published.", "Keep disallowed paths free of secrets; robots.txt is not an access-control mechanism.", security_control=False))
            else:
                observations.append(_observation("robots.txt not observed", "crawler-policy", "opportunity", f"The request returned HTTP {status or 'no response'}.", "Add robots.txt if crawler guidance is useful; do not rely on it to protect private paths.", security_control=False))
            continue
        if path == "/sitemap.xml":
            valid_sitemap = status == 200 and not soft_404 and ("xml" in content_type or "<urlset" in body.lower() or "<sitemapindex" in body.lower())
            observations.append(_observation("sitemap.xml " + ("present" if valid_sitemap else "not observed"), "discovery", "observed" if valid_sitemap else "opportunity", f"The request returned HTTP {status or 'no response'}.", "Publish a sitemap when search discovery matters; it is not a security control.", security_control=False))
            continue
        if path == "/.well-known/security.txt":
            valid_security = status == 200 and not soft_404 and "contact:" in body.lower()
            observations.append(_observation("security.txt " + ("present" if valid_security else "not validated"), "security-contact", "observed" if valid_security else "opportunity", f"The final URL was {final_url} and returned HTTP {status or 'no response'}.", "Publish a valid security.txt with a monitored Contact field.", security_control=False))
            continue
        if status == 200 and not soft_404:
            label = PATHS[path].replace("-", " ").title()
            marker = ""
            if path == "/.git/HEAD" and body.startswith("ref:"):
                marker = " Git metadata content was returned."
            elif path == "/.env" and re.search(r"(?:API_KEY|SECRET|PASSWORD|DATABASE_URL)", body, re.I):
                marker = " Environment-style secret names were visible in the response sample."
            observations.append(_observation(
                f"Potentially exposed {label}", "exposure", "review-needed",
                f"{path} returned HTTP 200.{marker}",
                "Confirm whether this endpoint/file is intentionally public; remove or restrict it if it exposes configuration, metadata, backups, or operational endpoints.",
            ))
        elif status == 200 and soft_404:
            observations.append(_observation(
                f"No public {PATHS[path].replace('-', ' ')} response observed", "exposure", "not-observed",
                f"{path} returned HTTP 200 with the shared HTML application shell (soft-404 behavior).",
                "Confirm the route remains a non-sensitive application fallback and does not expose data for alternate methods or content types.",
            ))
        elif status in {401, 403}:
            observations.append(_observation(f"Protected {PATHS[path].replace('-', ' ')} path", "exposure", "observed", f"{path} returned HTTP {status}.", "Keep authorization server-side and verify the response does not leak sensitive metadata."))
        else:
            observations.append(_observation(f"No public {PATHS[path].replace('-', ' ')} response observed", "exposure", "not-observed", f"{path} returned HTTP {status or 'no response'}.", "Recheck authenticated and application-specific routes; this bounded probe is not exhaustive."))

    body = root.get("body_sample", "")
    markers = [name for name in ("supabase", "firebase", "graphql", "swagger", "openapi", "prisma", "drizzle", "mongodb", "postgres") if re.search(rf"\b{name}\b", body, re.I)]
    if markers:
        observations.append(_observation("Technology and data-layer signals observed", "architecture", "review-needed", "The public HTML contained indicators for: " + ", ".join(markers) + ".", "Review database/API authorization, exposed client configuration, and provider policies in source and deployment settings."))
    else:
        observations.append(_observation("Database security not observable from public HTML", "architecture", "needs-source-review", "No direct database technology signal was visible in the selected public response.", "Review database credentials, network exposure, least-privilege roles, backups, migrations, and authorization policies in the application and provider configuration."))
    return observations


def run_baseline(url: str, outdir: Path, *, authorized: bool = False) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    base = url.rstrip("/") + "/"
    opener = build_opener()
    root = _fetch(opener, base)
    probe_paths = PATHS if authorized else {path: PATHS[path] for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")}
    paths = {path: _fetch(opener, urljoin(base, path.lstrip("/"))) for path in probe_paths}
    observations = analyze_responses(root, paths)
    payload = {"root": {key: value for key, value in root.items() if key != "body_sample"}, "paths": paths, "observations": observations}
    (outdir / "web-baseline.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    check = {
        "name": "web baseline analysis",
        "available": True,
        "returncode": 0,
        "output": "web-baseline.json",
        "observation_count": len(observations),
        "review_needed_count": sum(item["status"] in {"review-needed", "needs-source-review"} for item in observations),
    }
    return check, observations
