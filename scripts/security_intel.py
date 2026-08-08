#!/usr/bin/env python3
"""Refresh compact security intelligence for an AgentSec repository audit.

The goal is freshness without flooding an LLM context window. AgentSec stores
machine-readable evidence locally, then the agent reads only records that match
the repository or a confirmed scanner finding.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_MAX_AGE_HOURS = 6
GITHUB_API_VERSION = "2026-03-10"
USER_AGENT = "AgentSec/1.1 (+https://github.com/0xcryptj/AgentSec)"


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def age_hours(path: Path) -> float | None:
    if not path.exists():
        return None
    modified = dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)
    return (utc_now() - modified).total_seconds() / 3600


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def npm_inventory(repo: Path) -> list[dict[str, str | None]]:
    """Return a compact npm package inventory, preferring exact lockfile versions."""
    found: dict[str, str | None] = {}

    lock_path = repo / "package-lock.json"
    if lock_path.exists():
        try:
            lock = read_json(lock_path)
            if isinstance(lock, dict):
                packages = lock.get("packages")
                if isinstance(packages, dict):
                    for key, meta in packages.items():
                        if not isinstance(key, str) or not key.startswith("node_modules/"):
                            continue
                        if not isinstance(meta, dict):
                            continue
                        name = key[len("node_modules/") :]
                        version = meta.get("version")
                        if name:
                            found[name] = str(version) if version else None
        except Exception:
            pass

    package_path = repo / "package.json"
    if package_path.exists():
        try:
            package = read_json(package_path)
            if isinstance(package, dict):
                for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                    values = package.get(section, {})
                    if not isinstance(values, dict):
                        continue
                    for name in values:
                        found.setdefault(str(name), None)
        except Exception:
            pass

    return [
        {"name": name, "version": version}
        for name, version in sorted(found.items(), key=lambda item: item[0].lower())
    ]


def fetch_json(url: str, timeout: int = 30) -> object:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": USER_AGENT,
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def compact_advisory(item: dict) -> dict:
    vulnerabilities = []
    for vuln in item.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        package = vuln.get("package") or {}
        vulnerabilities.append(
            {
                "package": package.get("name"),
                "ecosystem": package.get("ecosystem"),
                "vulnerable_version_range": vuln.get("vulnerable_version_range"),
                "first_patched_version": vuln.get("first_patched_version"),
            }
        )
    return {
        "ghsa_id": item.get("ghsa_id"),
        "cve_id": item.get("cve_id"),
        "type": item.get("type"),
        "severity": item.get("severity"),
        "summary": item.get("summary"),
        "published_at": item.get("published_at"),
        "updated_at": item.get("updated_at"),
        "html_url": item.get("html_url"),
        "vulnerabilities": vulnerabilities,
    }


def github_advisories(packages: list[dict[str, str | None]], advisory_type: str) -> list[dict]:
    """Query only advisories that affect packages actually present in the repo."""
    if not packages:
        return []

    affects = [
        f"{p['name']}@{p['version']}" if p.get("version") else str(p["name"])
        for p in packages
    ]
    seen: dict[str, dict] = {}

    # Keep URLs comfortably below common client/proxy limits.
    for start in range(0, len(affects), 60):
        chunk = affects[start : start + 60]
        query = urllib.parse.urlencode(
            {
                "type": advisory_type,
                "ecosystem": "npm",
                "affects": ",".join(chunk),
                "per_page": 100,
                "sort": "updated",
                "direction": "desc",
            }
        )
        url = f"https://api.github.com/advisories?{query}"
        payload = fetch_json(url)
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            key = str(item.get("ghsa_id") or item.get("cve_id") or item.get("html_url"))
            seen[key] = compact_advisory(item)

    return sorted(
        seen.values(),
        key=lambda item: str(item.get("updated_at") or item.get("published_at") or ""),
        reverse=True,
    )


def service_active(name: str) -> bool:
    if not shutil.which("systemctl"):
        return False
    proc = subprocess.run(
        ["systemctl", "is-active", "--quiet", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    return proc.returncode == 0


def refresh_clamav(outdir: Path) -> dict:
    """Best-effort update of ClamAV signatures. Never fail the overall audit."""
    result = {
        "installed": bool(shutil.which("clamscan")),
        "freshclam_available": bool(shutil.which("freshclam")),
        "updated": False,
        "returncode": None,
        "output": "freshclam.txt",
    }
    output_path = outdir / "freshclam.txt"

    if service_active("clamav-freshclam"):
        result["managed_by_service"] = True
        result["updated"] = True
        output_path.write_text(
            "clamav-freshclam service is active; signature updates are managed by the system service.\n",
            encoding="utf-8",
        )
        return result

    if not result["freshclam_available"]:
        output_path.write_text(
            "freshclam is not installed. Install ClamAV to enable malware signature refresh.\n",
            encoding="utf-8",
        )
        return result

    try:
        proc = subprocess.run(
            ["freshclam"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=600,
        )
        result["returncode"] = proc.returncode
        result["updated"] = proc.returncode == 0
        output_path.write_text(proc.stdout or "", encoding="utf-8", errors="replace")
    except Exception as exc:
        result["error"] = str(exc)
        output_path.write_text(f"freshclam could not update signatures: {exc}\n", encoding="utf-8")

    return result


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refresh compact, repository-specific security intelligence for AgentSec"
    )
    parser.add_argument("path", nargs="?", default=".", help="repository path")
    parser.add_argument(
        "--max-age-hours",
        type=float,
        default=DEFAULT_MAX_AGE_HOURS,
        help="reuse cached intel newer than this many hours (default: 6)",
    )
    parser.add_argument("--force", action="store_true", help="refresh even when cache is fresh")
    parser.add_argument("--offline", action="store_true", help="never use the network")
    parser.add_argument(
        "--skip-clamav",
        action="store_true",
        help="do not run freshclam even if ClamAV is installed",
    )
    args = parser.parse_args()

    repo = Path(args.path).expanduser().resolve()
    if not repo.is_dir():
        print(f"AgentSec intel: repository path does not exist: {repo}", file=sys.stderr)
        return 2

    outdir = repo / ".agentsec" / "intel"
    outdir.mkdir(parents=True, exist_ok=True)
    metadata_path = outdir / "metadata.json"

    current_age = age_hours(metadata_path)
    if (
        not args.force
        and not args.offline
        and current_age is not None
        and current_age <= args.max_age_hours
    ):
        print(
            f"[AgentSec] Security intelligence cache is fresh "
            f"({current_age:.1f}h old, max {args.max_age_hours:g}h)."
        )
        return 0

    packages = npm_inventory(repo)
    write_json(outdir / "npm-packages.json", packages)

    metadata: dict[str, object] = {
        "tool": "AgentSec security intelligence",
        "updated_at": utc_now().isoformat(),
        "repository": str(repo),
        "cache_policy_hours": args.max_age_hours,
        "sources": {},
        "notes": [
            "Keep full feeds out of the LLM context. Read only records matching this repository or a confirmed finding.",
            "Absence from a feed is not proof that a package or file is safe.",
        ],
    }

    if args.offline:
        metadata["notes"].append(
            "Offline mode used. Existing cached advisory/signature data may be stale."
        )
    else:
        try:
            malware = github_advisories(packages, "malware")
            write_json(outdir / "github-npm-malware.json", malware)
            metadata["sources"]["github_npm_malware"] = {
                "status": "ok",
                "matching_advisories": len(malware),
                "packages_queried": len(packages),
            }
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            metadata["sources"]["github_npm_malware"] = {
                "status": "error",
                "error": str(exc),
            }

        try:
            reviewed = github_advisories(packages, "reviewed")
            write_json(outdir / "github-npm-reviewed.json", reviewed)
            metadata["sources"]["github_npm_reviewed"] = {
                "status": "ok",
                "matching_advisories": len(reviewed),
                "packages_queried": len(packages),
            }
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            metadata["sources"]["github_npm_reviewed"] = {
                "status": "error",
                "error": str(exc),
            }

        if not args.skip_clamav:
            metadata["sources"]["clamav"] = refresh_clamav(outdir)

    write_json(metadata_path, metadata)

    print(f"[AgentSec] Security intelligence: {outdir}")
    print(f"[AgentSec] npm packages inventoried: {len(packages)}")
    for source, status in metadata["sources"].items():
        if isinstance(status, dict):
            print(f"[AgentSec] {source}: {status.get('status', 'ok')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
