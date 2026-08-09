#!/usr/bin/env python3
"""AgentSec defensive security audit orchestrator.

This CLI coordinates established security tools and records their raw output for an
AI coding agent or human reviewer. It intentionally separates baseline inspection
from authorized active vulnerability validation.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import textwrap
from urllib.parse import urlparse

try:
    from scripts.finding_model import write_findings
except ModuleNotFoundError:  # direct ``python scripts/agentsec.py`` invocation
    from finding_model import write_findings

ROOT = Path(__file__).resolve().parent.parent
REPORT_ROOT = ROOT / ".agentsec" / "reports"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip() if (ROOT / "VERSION").exists() else "development"


def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def slug(value: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in value)[:100]


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_cmd(
    name: str,
    cmd: list[str],
    outdir: Path,
    *,
    cwd: Path | None = None,
    timeout: int = 900,
    env: dict[str, str] | None = None,
) -> dict:
    """Run one deterministic check and save stdout/stderr without using a shell."""
    result = {
        "name": name,
        "command": cmd,
        "available": True,
        "returncode": None,
        "timed_out": False,
        "output": f"{slug(name)}.txt",
    }
    output_path = outdir / result["output"]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=env,
            check=False,
        )
        result["returncode"] = proc.returncode
        output_path.write_text(proc.stdout or "", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        result["available"] = False
        output_path.write_text(f"Tool not installed: {cmd[0]}\n", encoding="utf-8")
    except subprocess.TimeoutExpired as exc:
        result["timed_out"] = True
        text = exc.stdout or ""
        if isinstance(text, bytes):
            text = text.decode(errors="replace")
        output_path.write_text(str(text) + "\n[AgentSec] timed out\n", encoding="utf-8")
    except Exception as exc:  # record failures instead of destroying the audit run
        output_path.write_text(f"AgentSec could not run this check: {exc}\n", encoding="utf-8")
        result["error"] = str(exc)
    return result


def skipped(name: str, reason: str) -> dict:
    return {"name": name, "skipped": True, "reason": reason}


def save_summary(outdir: Path, scope: str, checks: list[dict], notes: list[str], observations: list[dict] | None = None) -> None:
    observations = observations or []
    findings = write_findings(outdir, checks)
    data = {
        "tool": "AgentSec",
        "version": VERSION,
        "scope": scope,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "checks": checks,
        "finding_count": len(findings),
        "findings_file": "findings.json",
        "observations": observations,
        "notes": notes,
    }
    (outdir / "summary.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    lines = [f"# AgentSec audit: {scope}", "", "## Checks", ""]
    for check in checks:
        if check.get("skipped"):
            lines.append(f"- ⏭️ **{check['name']}**: {check['reason']}")
        elif not check.get("available", True):
            lines.append(f"- ⚪ **{check['name']}**: tool unavailable")
        else:
            rc = check.get("returncode")
            suffix = " (timed out)" if check.get("timed_out") else ""
            lines.append(f"- **{check['name']}**: exit {rc}{suffix} → `{check.get('output', '')}`")
    lines.extend(["", "## Review queue", ""])
    if findings:
        lines.extend(
            f"- **{finding['title']}** — `{finding['status']}`; evidence: `{finding['evidence']}`"
            for finding in findings
        )
    else:
        lines.append("- No deterministic checks currently require follow-up.")
    lines.extend(["", "## Baseline observations", ""])
    if observations:
        for item in observations:
            marker = "security control" if item.get("security_control", True) else "product/discovery opportunity"
            lines.append(f"- **{item['title']}** — `{item['status']}` ({marker}): {item['detail']} Recommended action: {item['recommendation']}")
    else:
        lines.append("- No structured baseline observations were collected.")
    if notes:
        lines.extend(["", "## Notes", ""] + [f"- {note}" for note in notes])
    lines.extend([
        "",
        "## Review guidance",
        "",
        "Scanner output is evidence, not a verdict. Correlate findings with source/configuration,",
        "rank confirmed issues by impact and exploitability, remediate root causes, and rerun the",
        "relevant check plus normal application tests.",
    ])
    (outdir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def create_run(scope: str) -> Path:
    outdir = REPORT_ROOT / f"{slug(scope)}-{now_stamp()}"
    outdir.mkdir(parents=True, exist_ok=False)
    return outdir


def find_sensitive_artifacts(path: Path, outdir: Path) -> dict:
    """Find deployment artifacts that are commonly dangerous if served or committed."""
    names = {
        ".env", ".env.local", ".env.production", ".npmrc", ".pypirc", ".htpasswd",
        "id_rsa", "id_ed25519", "credentials", "credentials.json", "service-account.json",
    }
    suffixes = {".pem", ".key", ".p12", ".pfx", ".bak", ".backup", ".old", ".sql", ".sqlite", ".db"}
    ignore_parts = {".git", "node_modules", ".venv", "venv", "dist", "build", ".next", ".agentsec"}
    findings: list[str] = []
    for base, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ignore_parts]
        base_path = Path(base)
        for filename in files:
            p = base_path / filename
            if filename in names or p.suffix.lower() in suffixes:
                try:
                    findings.append(str(p.relative_to(path)))
                except ValueError:
                    findings.append(str(p))
            if len(findings) >= 500:
                findings.append("[truncated after 500 paths]")
                break
        if len(findings) >= 501:
            break
    output = outdir / "sensitive-artifacts.txt"
    output.write_text("\n".join(findings) + ("\n" if findings else ""), encoding="utf-8")
    return {
        "name": "sensitive-artifact inventory",
        "available": True,
        "returncode": 1 if findings else 0,
        "output": output.name,
        "finding_count": max(0, len(findings) - (1 if findings and findings[-1].startswith("[truncated") else 0)),
    }


def audit_repo(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser().resolve()
    if not path.is_dir():
        print(f"AgentSec: repository path does not exist: {path}", file=sys.stderr)
        return 2
    outdir = create_run(f"repo-{path.name}")
    checks: list[dict] = []
    notes: list[str] = []

    # Keep direct Python invocations equivalent to the wrapper: architecture
    # evidence must describe the target repository, not AgentSec itself.
    architecture_output = outdir / "architecture.json"
    checks.append(run_cmd(
        "architecture inventory",
        [sys.executable, str(ROOT / "scripts" / "architecture_inventory.py"), str(path), "--output", str(architecture_output)],
        outdir,
        cwd=path,
    ))

    checks.append(find_sensitive_artifacts(path, outdir))

    package_json = path / "package.json"
    if package_json.exists() and command_exists("npm"):
        checks.append(run_cmd("npm-audit", ["npm", "audit", "--json"], outdir, cwd=path))
        checks.append(run_cmd("npm-package-tree", ["npm", "ls", "--all", "--json"], outdir, cwd=path))
        # Signature auditing is not supported by every npm release/registry and
        # requires lockfile/package metadata in practice. Do not make a normal
        # source-only audit wait on a registry operation that cannot add evidence.
        if (path / "package-lock.json").exists() or (path / "npm-shrinkwrap.json").exists():
            checks.append(run_cmd("npm-signatures", ["npm", "audit", "signatures"], outdir, cwd=path, timeout=300))
        else:
            checks.append(skipped("npm signatures", "no npm lockfile found"))
        if args.fix:
            checks.append(run_cmd("npm-audit-fix", ["npm", "audit", "fix"], outdir, cwd=path))
            try:
                package_data = json.loads(package_json.read_text(encoding="utf-8"))
                if "test" in package_data.get("scripts", {}):
                    checks.append(run_cmd("npm-tests-after-fix", ["npm", "test"], outdir, cwd=path, timeout=1200))
                if "build" in package_data.get("scripts", {}):
                    checks.append(run_cmd("npm-build-after-fix", ["npm", "run", "build"], outdir, cwd=path, timeout=1200))
            except Exception as exc:
                notes.append(f"Could not inspect package.json scripts after npm remediation: {exc}")
    elif package_json.exists():
        checks.append(skipped("npm audit", "package.json found but npm is not installed"))

    # Cross-ecosystem scanners are optional. AgentSec consumes whichever are available.
    if command_exists("osv-scanner"):
        checks.append(run_cmd("osv-scanner", ["osv-scanner", "scan", "--recursive", str(path)], outdir, cwd=path))
    else:
        checks.append(skipped("OSV-Scanner", "optional tool not installed"))

    if command_exists("trivy"):
        checks.append(run_cmd(
            "trivy-filesystem",
            ["trivy", "fs", "--scanners", "vuln,misconfig,secret", "--format", "json", str(path)],
            outdir,
            cwd=path,
            timeout=1200,
        ))
    else:
        checks.append(skipped("Trivy filesystem scan", "optional tool not installed"))

    if command_exists("semgrep"):
        checks.append(run_cmd(
            "semgrep-auto",
            ["semgrep", "scan", "--config", "auto", "--json", str(path)],
            outdir,
            cwd=path,
            timeout=1200,
        ))
    else:
        checks.append(skipped("Semgrep", "optional tool not installed"))

    if command_exists("gitleaks"):
        checks.append(run_cmd(
            "gitleaks",
            ["gitleaks", "detect", "--source", str(path), "--no-banner", "--report-format", "json"],
            outdir,
            cwd=path,
            timeout=600,
        ))
    else:
        checks.append(skipped("Gitleaks", "optional tool not installed"))

    if (path / "requirements.txt").exists() or (path / "pyproject.toml").exists():
        if command_exists("pip-audit"):
            cmd = ["pip-audit", "--format", "json"]
            if (path / "requirements.txt").exists():
                cmd += ["-r", "requirements.txt"]
            checks.append(run_cmd("pip-audit", cmd, outdir, cwd=path))
        else:
            checks.append(skipped("pip-audit", "Python project detected but pip-audit is not installed"))

    if (path / "Cargo.lock").exists():
        if command_exists("cargo-audit"):
            checks.append(run_cmd("cargo-audit", ["cargo-audit", "audit", "--json"], outdir, cwd=path))
        else:
            checks.append(skipped("cargo-audit", "Rust project detected but cargo-audit is not installed"))

    save_summary(outdir, f"repository {path}", checks, notes)
    print(f"AgentSec repository audit complete: {outdir}")
    print(f"Review: {outdir / 'summary.md'}")
    return 0


def url_parts(raw: str) -> tuple[str, str]:
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must include http:// or https:// and a hostname")
    return raw.rstrip("/"), parsed.hostname


def audit_web(args: argparse.Namespace) -> int:
    try:
        url, host = url_parts(args.url)
    except ValueError as exc:
        print(f"AgentSec: {exc}", file=sys.stderr)
        return 2
    if args.active and not args.authorized:
        print("AgentSec: --active requires --authorized. Active vulnerability validation was not run.", file=sys.stderr)
        return 2

    outdir = create_run(f"web-{host}")
    checks: list[dict] = []
    notes: list[str] = []
    observations: list[dict] = []

    try:
        from scripts.web_baseline import run_baseline
    except ModuleNotFoundError:  # direct ``python scripts/agentsec.py`` invocation
        from web_baseline import run_baseline
    baseline_check, observations = run_baseline(url, outdir, authorized=args.authorized)
    checks.append(baseline_check)

    if args.baseline_only:
        notes.append("Baseline-only mode selected; optional network surface scanners were not run.")
        save_summary(outdir, f"web {url}", checks, notes, observations)
        print(f"AgentSec web baseline complete: {outdir}")
        return 0

    if command_exists("curl"):
        checks.append(run_cmd("http-response-headers", ["curl", "-sSIL", "--max-time", "20", url], outdir, timeout=30))
        checks.append(run_cmd("security-txt", ["curl", "-sS", "--max-time", "20", f"{url}/.well-known/security.txt"], outdir, timeout=30))
    else:
        checks.append(skipped("HTTP header inspection", "curl is not installed"))

    if not args.authorized:
        notes.append("Remote enumeration/scanning skipped because --authorized was not supplied.")
        notes.append("Use --authorized only for a system you own or are explicitly permitted to assess.")
        save_summary(outdir, f"web {url}", checks, notes, observations)
        print(f"AgentSec baseline inspection complete: {outdir}")
        return 0

    if command_exists("nmap"):
        checks.append(run_cmd(
            "nmap-web-surface",
            ["nmap", "-sT", "-sV", "--top-ports", "1000", "--script", "default,safe,http-security-headers,ssl-enum-ciphers", host],
            outdir,
            timeout=1200,
        ))
    else:
        checks.append(skipped("Nmap web surface", "nmap is not installed"))

    if command_exists("nikto"):
        checks.append(run_cmd("nikto", ["nikto", "-h", url, "-maxtime", "10m"], outdir, timeout=700))
    else:
        checks.append(skipped("Nikto", "nikto is not installed"))

    wordlist = Path("/usr/share/seclists/Discovery/Web-Content/common.txt")
    if command_exists("gobuster") and wordlist.exists():
        checks.append(run_cmd(
            "gobuster-exposure",
            ["gobuster", "dir", "-u", url, "-w", str(wordlist), "-t", "10", "--timeout", "10s", "-x", "txt,log,bak,old,zip,json,env"],
            outdir,
            timeout=1200,
        ))
    elif command_exists("ffuf") and wordlist.exists():
        checks.append(run_cmd(
            "ffuf-exposure",
            ["ffuf", "-w", str(wordlist), "-u", f"{url}/FUZZ", "-t", "10", "-rate", "20", "-of", "json"],
            outdir,
            timeout=1200,
        ))
    else:
        checks.append(skipped("directory exposure enumeration", "Gobuster/ffuf or the SecLists common wordlist is unavailable"))

    if command_exists("docker"):
        checks.append(run_cmd(
            "zap-baseline",
            [
                "docker", "run", "--rm", "-t", "ghcr.io/zaproxy/zaproxy:stable",
                "zap-baseline.py", "-t", url, "-J", "/tmp/agentsec-zap.json",
            ],
            outdir,
            timeout=1200,
        ))
    else:
        checks.append(skipped("ZAP baseline", "Docker is not installed"))

    if args.active:
        notes.append("Active mode enabled for explicitly authorized scope.")
        if command_exists("sqlmap"):
            checks.append(run_cmd(
                "sqlmap-controlled-validation",
                ["sqlmap", "-u", url, "--batch", "--crawl=2", "--level=2", "--risk=1", "--smart"],
                outdir,
                timeout=1800,
            ))
        else:
            checks.append(skipped("SQL injection validation", "sqlmap is not installed"))

        if command_exists("docker"):
            checks.append(run_cmd(
                "zap-active-scan",
                [
                    "docker", "run", "--rm", "-t", "ghcr.io/zaproxy/zaproxy:stable",
                    "zap-full-scan.py", "-t", url, "-m", "5",
                ],
                outdir,
                timeout=1800,
            ))
        else:
            checks.append(skipped("ZAP active scan", "Docker is not installed"))

    save_summary(outdir, f"web {url}", checks, notes, observations)
    print(f"AgentSec web audit complete: {outdir}")
    print(f"Review: {outdir / 'summary.md'}")
    return 0


def audit_server(args: argparse.Namespace) -> int:
    if args.local:
        outdir = create_run("server-local")
        script = ROOT / "scripts" / "local_server_audit.sh"
        checks = [run_cmd("local-server-hardening", ["bash", str(script)], outdir, timeout=1200)]
        notes = ["Some checks are more complete when AgentSec has permission to read system configuration; do not elevate automatically."]
        save_summary(outdir, "local server", checks, notes)
        print(f"AgentSec local server audit complete: {outdir}")
        return 0

    target = args.target
    if not target:
        print("AgentSec: server mode needs --local or --target <host>", file=sys.stderr)
        return 2
    if not args.authorized:
        print("AgentSec: remote server scanning requires --authorized.", file=sys.stderr)
        return 2
    try:
        socket.getaddrinfo(target, None)
    except socket.gaierror as exc:
        print(f"AgentSec: cannot resolve {target}: {exc}", file=sys.stderr)
        return 2

    outdir = create_run(f"server-{target}")
    checks: list[dict] = []
    notes = ["External scanning shows network exposure; run `server --local` on the host for configuration and patch-state checks."]
    if command_exists("nmap"):
        checks.append(run_cmd(
            "nmap-server-surface",
            ["nmap", "-sT", "-sV", "-O", "--top-ports", "2000", "--script", "default,safe,ssl-enum-ciphers", target],
            outdir,
            timeout=1800,
        ))
    else:
        checks.append(skipped("Nmap server surface", "nmap is not installed"))
    save_summary(outdir, f"server {target}", checks, notes)
    print(f"AgentSec server audit complete: {outdir}")
    return 0


def view_reports(args: argparse.Namespace) -> int:
    try:
        from scripts.viewer import serve
    except ModuleNotFoundError:  # direct ``python scripts/agentsec.py`` invocation
        from viewer import serve

    return serve(REPORT_ROOT, args.run_name, port=args.port, open_browser=not args.no_browser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentsec",
        description="AgentSec: agentic defensive security auditing and remediation support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              agentsec repo .
              agentsec repo . --fix
              agentsec server --local
              agentsec server --target app.example.com --authorized
              agentsec web https://app.example.com --authorized
              agentsec url https://app.example.com --authorized
              agentsec web https://staging.example.com --authorized --active
            """
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    view = sub.add_parser("view", help="open a private local viewer for an audit report")
    view.add_argument("run_name", nargs="?", help="specific report directory; defaults to the latest run")
    view.add_argument("--port", type=int, default=0, help="local port; defaults to an available port")
    view.add_argument("--no-browser", action="store_true", help="print the tokened URL without opening a browser")
    view.set_defaults(func=view_reports)

    repo = sub.add_parser("repo", help="audit source, dependencies, secrets, and deployment configuration")
    repo.add_argument("path", nargs="?", default=".")
    repo.add_argument("--fix", action="store_true", help="apply conservative package-manager remediation where supported")
    repo.set_defaults(func=audit_repo)

    web = sub.add_parser("web", aliases=["url"], help="audit a web application or URL")
    web.add_argument("url")
    web.add_argument("--authorized", action="store_true", help="confirm you own or have permission to assess the target")
    web.add_argument("--active", action="store_true", help="run controlled active SQLi/XSS validation; requires --authorized")
    web.add_argument("--baseline-only", action="store_true", help="run bounded web checks and skip long optional surface scanners")
    web.set_defaults(func=audit_web)

    server = sub.add_parser("server", help="audit local hardening or an authorized server's external attack surface")
    group = server.add_mutually_exclusive_group(required=True)
    group.add_argument("--local", action="store_true")
    group.add_argument("--target")
    server.add_argument("--authorized", action="store_true", help="confirm authorization for remote scanning")
    server.set_defaults(func=audit_server)
    return parser


def main() -> int:
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
