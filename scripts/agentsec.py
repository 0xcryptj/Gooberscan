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
    from scripts.agent_graph import AgentGraph, AgentTask
    from scripts.scan_session import ScanSession
except ModuleNotFoundError:  # direct ``python scripts/agentsec.py`` invocation
    from finding_model import write_findings
    from agent_graph import AgentGraph, AgentTask
    from scan_session import ScanSession

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


def architecture_observations(path: Path) -> list[dict]:
    """Convert architecture inventory opportunities into report observations."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    observations = []
    for item in data.get("opportunities", []):
        if not isinstance(item, dict) or not item.get("title"):
            continue
        security_control = bool(item.get("security_control", True))
        observations.append({
            "title": item["title"],
            "category": item.get("category", "architecture"),
            "status": "review-needed" if security_control else "opportunity",
            "security_control": security_control,
            "detail": item.get("why", "Architecture evidence suggests a follow-up review."),
            "recommendation": item.get("recommended_action", "Inspect the relevant source and runtime configuration."),
            "evidence": item.get("evidence", []),
        })
    return observations


def save_summary(outdir: Path, scope: str, checks: list[dict], notes: list[str], observations: list[dict] | None = None, metadata: dict | None = None) -> None:
    observations = observations or []
    findings = write_findings(outdir, checks, observations)
    status_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for finding in findings:
        status = str(finding.get("status", "unclassified"))
        category = str(finding.get("category", "unclassified"))
        status_counts[status] = status_counts.get(status, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1
    data = {
        "tool": "AgentSec",
        "version": VERSION,
        "scope": scope,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "checks": checks,
        "finding_count": len(findings),
        "finding_status_counts": status_counts,
        "finding_category_counts": category_counts,
        "findings_file": "findings.json",
        "observations": observations,
        "notes": notes,
    }
    if metadata:
        data.update(metadata)
    (outdir / "summary.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    lines = [f"# AgentSec audit: {scope}", "", "## Overview", ""]
    if status_counts:
        lines.extend(f"- **{status}**: {count}" for status, count in sorted(status_counts.items()))
    else:
        lines.append("- No findings or observations were recorded.")
    lines.extend(["", "## Checks", ""])
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


def read_instruction(args: argparse.Namespace, notes: list[str]) -> str:
    instruction = str(getattr(args, "instruction", "") or "").strip()
    instruction_file = getattr(args, "instruction_file", None)
    if instruction_file:
        try:
            instruction = (instruction + "\n\n" + Path(instruction_file).read_text(encoding="utf-8")).strip()
        except (OSError, UnicodeError) as exc:
            notes.append(f"Instruction file could not be read: {exc}")
    if instruction:
        notes.append("Custom instructions were recorded for agent-led correlation.")
    return instruction


def changed_files(path: Path, diff_base: str | None) -> list[str]:
    if not diff_base or not (path / ".git").exists() or not command_exists("git"):
        return []
    try:
        proc = subprocess.run(["git", "diff", "--name-only", f"{diff_base}...HEAD"], cwd=path, text=True, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def should_fail(findings: list[dict], threshold: str) -> bool:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unclassified": 5}
    minimum = order.get(threshold, 1)
    return any(finding.get("status") in {"confirmed", "evidence-backed"} and order.get(str(finding.get("severity")), 5) <= minimum for finding in findings)


def create_run(scope: str) -> Path:
    outdir = REPORT_ROOT / f"{slug(scope)}-{now_stamp()}"
    outdir.mkdir(parents=True, exist_ok=False)
    ScanSession.start(outdir, scope)
    return outdir


def run_specialist_graph(outdir: Path, checks: list[dict], observations: list[dict]) -> dict[str, dict]:
    """Coordinate deterministic specialists over preserved evidence."""
    session = ScanSession(outdir)
    task_data = {
        "architecture": {"observations": len(observations)},
        "dependency": {"checks": sum("audit" in str(item.get("name", "")).lower() or "osv" in str(item.get("name", "")).lower() for item in checks)},
        "misconfiguration": {"checks": sum("trivy" in str(item.get("name", "")).lower() or "baseline" in str(item.get("name", "")).lower() for item in checks)},
        "secrets": {"checks": sum("secret" in str(item.get("name", "")).lower() or "gitleaks" in str(item.get("name", "")).lower() for item in checks)},
        "reporting": {"preserved_checks": len(checks)},
    }
    graph = AgentGraph(session)
    tasks = [AgentTask(name, f"Specialist review of {name} evidence", lambda value=value: {"ok": True, **value}) for name, value in task_data.items()]
    return graph.run(tasks)


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
    notes.append(f"Scan profile: {args.scan_mode}.")
    instruction = read_instruction(args, notes)
    if getattr(args, "scope_mode", "auto") == "diff":
        files = changed_files(path, getattr(args, "diff_base", None))
        notes.append(f"Diff scope selected; {len(files)} changed file(s) were discovered." if files else "Diff scope selected, but changed files could not be resolved; full deterministic checks were retained.")

    # Keep direct Python invocations equivalent to the wrapper: architecture
    # evidence must describe the target repository, not AgentSec itself.
    architecture_output = outdir / "architecture.json"
    checks.append(run_cmd(
        "architecture inventory",
        [sys.executable, str(ROOT / "scripts" / "architecture_inventory.py"), str(path), "--output", str(architecture_output)],
        outdir,
        cwd=path,
    ))
    observations = architecture_observations(architecture_output)

    checks.append(find_sensitive_artifacts(path, outdir))

    source_output = outdir / "source-security.json"
    source_check = run_cmd(
        "source-security-patterns",
        [sys.executable, str(ROOT / "scripts" / "source_security.py"), str(path), "--output", str(source_output)]
        + (["--include-tests"] if getattr(args, "include_tests", False) else []),
        outdir,
        cwd=path,
        timeout=600,
    )
    source_check["output"] = str(source_output)
    checks.append(source_check)

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

    quick = args.scan_mode == "quick"
    deep = args.scan_mode == "deep"

    # Cross-ecosystem scanners are optional. AgentSec consumes whichever are available.
    if quick:
        checks.append(skipped("OSV-Scanner", "quick profile skips optional cross-ecosystem scanners"))
    elif command_exists("osv-scanner"):
        checks.append(run_cmd("osv-scanner", ["osv-scanner", "scan", "--recursive", str(path)], outdir, cwd=path))
    else:
        checks.append(skipped("OSV-Scanner", "optional tool not installed"))

    if quick:
        checks.append(skipped("Trivy filesystem scan", "quick profile skips filesystem SAST/SCA scanning"))
    elif command_exists("trivy"):
        trivy_scanners = "vuln,misconfig,secret,license" if deep else "vuln,misconfig,secret"
        checks.append(run_cmd(
            "trivy-filesystem",
            ["trivy", "fs", "--scanners", trivy_scanners, "--format", "json", str(path)],
            outdir,
            cwd=path,
            timeout=1200,
        ))
    else:
        checks.append(skipped("Trivy filesystem scan", "optional tool not installed"))

    if quick:
        checks.append(skipped("Semgrep", "quick profile skips optional SAST scanning"))
    elif command_exists("semgrep"):
        checks.append(run_cmd(
            "semgrep-auto",
            ["semgrep", "scan", "--config", "auto", "--json", str(path)],
            outdir,
            cwd=path,
            timeout=1200,
        ))
    else:
        checks.append(skipped("Semgrep", "optional tool not installed"))

    if quick:
        checks.append(skipped("Gitleaks", "quick profile skips optional secret scanning"))
    elif command_exists("gitleaks"):
        checks.append(run_cmd(
            "gitleaks",
            ["gitleaks", "detect", "--source", str(path), "--no-banner", "--report-format", "json"],
            outdir,
            cwd=path,
            timeout=600,
        ))
    else:
        checks.append(skipped("Gitleaks", "optional tool not installed"))

    if quick and ((path / "requirements.txt").exists() or (path / "pyproject.toml").exists()):
        checks.append(skipped("pip-audit", "quick profile skips optional Python dependency scanning"))
    elif (path / "requirements.txt").exists() or (path / "pyproject.toml").exists():
        if command_exists("pip-audit"):
            cmd = ["pip-audit", "--format", "json"]
            if (path / "requirements.txt").exists():
                cmd += ["-r", "requirements.txt"]
            checks.append(run_cmd("pip-audit", cmd, outdir, cwd=path))
        else:
            checks.append(skipped("pip-audit", "Python project detected but pip-audit is not installed"))

    if quick and (path / "Cargo.lock").exists():
        checks.append(skipped("cargo-audit", "quick profile skips optional Rust dependency scanning"))
    elif (path / "Cargo.lock").exists():
        if command_exists("cargo-audit"):
            checks.append(run_cmd("cargo-audit", ["cargo-audit", "audit", "--json"], outdir, cwd=path))
        else:
            checks.append(skipped("cargo-audit", "Rust project detected but cargo-audit is not installed"))

    specialists = run_specialist_graph(outdir, checks, observations)
    save_summary(outdir, f"repository {path}", checks, notes, observations, {"scan_mode": args.scan_mode, "scope_mode": getattr(args, "scope_mode", "auto"), "diff_base": getattr(args, "diff_base", None), "instruction": instruction, "specialists": specialists})
    ScanSession(outdir).finish()
    print(f"AgentSec repository audit complete: {outdir}")
    print(f"Review: {outdir / 'summary.md'}")
    try:
        findings = json.loads((outdir / "findings.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        findings = []
    return 2 if should_fail(findings, getattr(args, "fail_on", "high")) else 0


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
    if getattr(args, "browser", False) and not args.active:
        print("AgentSec: --browser requires --active --authorized.", file=sys.stderr)
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

        if getattr(args, "browser", False):
            try:
                from scripts.browser_probe import command as browser_command
            except ModuleNotFoundError:
                from browser_probe import command as browser_command
            browser = browser_command()
            if browser:
                checks.append(run_cmd("browser-open", [browser, "open", url], outdir, timeout=120))
                checks.append(run_cmd("browser-snapshot", [browser, "snapshot"], outdir, timeout=120))
            else:
                checks.append(skipped("browser baseline", "Playwright CLI is not installed"))

    save_summary(outdir, f"web {url}", checks, notes, observations)
    print(f"AgentSec web audit complete: {outdir}")
    print(f"Review: {outdir / 'summary.md'}")
    return 0


def audit_api(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).expanduser().resolve()
    if not spec_path.is_file():
        print(f"AgentSec: API specification does not exist: {spec_path}", file=sys.stderr)
        return 2
    if args.base_url and not args.authorized:
        print("AgentSec: API probing requires --authorized.", file=sys.stderr)
        return 2
    outdir = create_run(f"api-{spec_path.stem}")
    checks: list[dict] = []
    notes: list[str] = ["API contract inventory is passive; state-changing and templated endpoints are not probed."]
    observations: list[dict] = []
    try:
        from scripts.api_probe import inventory, load_spec, probe
    except ModuleNotFoundError:
        from api_probe import inventory, load_spec, probe
    try:
        spec = load_spec(spec_path)
        endpoints = inventory(spec)
        (outdir / "api-inventory.json").write_text(json.dumps({"spec": str(spec_path), "endpoints": endpoints}, indent=2), encoding="utf-8")
        checks.append({"name": "OpenAPI inventory", "available": True, "returncode": 0, "output": "api-inventory.json", "endpoint_count": len(endpoints)})
        if args.base_url:
            results, observations = probe(spec, args.base_url)
            (outdir / "api-probe.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
            checks.append({"name": "authorized API probe", "available": True, "returncode": 0, "output": "api-probe.json", "probed_count": len(results)})
    except ValueError as exc:
        checks.append({"name": "OpenAPI inventory", "available": True, "returncode": 1, "output": "api-inventory.json", "error": str(exc)})
    run_specialist_graph(outdir, checks, observations)
    save_summary(outdir, f"API specification {spec_path}", checks, notes, observations, {"base_url": args.base_url, "authorized": args.authorized})
    ScanSession(outdir).finish()
    print(f"AgentSec API audit complete: {outdir}")
    return 0 if not any(item.get("returncode") not in (0, None) for item in checks) else 1


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


def audit_scan(args: argparse.Namespace) -> int:
    """Run the bounded audit appropriate to each Strix-style target."""
    targets = list(args.target or [])
    for target_file in args.target_list or []:
        try:
            targets.extend(line.strip() for line in Path(target_file).read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#"))
        except (OSError, UnicodeError) as exc:
            print(f"AgentSec: could not read target list {target_file}: {exc}", file=sys.stderr)
            return 2
    if not targets:
        print("AgentSec: scan requires --target or --target-list", file=sys.stderr)
        return 2
    exit_code = 0
    for target in targets:
        parsed = urlparse(target)
        if parsed.scheme in {"http", "https"}:
            child = argparse.Namespace(url=target, authorized=args.authorized, active=args.active, baseline_only=args.baseline_only, browser=False)
            exit_code = max(exit_code, audit_web(child))
        else:
            path = Path(target).expanduser().resolve()
            if not path.is_dir():
                print(f"AgentSec: unsupported or missing local target: {target}", file=sys.stderr)
                exit_code = max(exit_code, 2)
                continue
            child = argparse.Namespace(path=str(path), scan_mode=args.scan_mode, fix=False, instruction=args.instruction, instruction_file=args.instruction_file, scope_mode=args.scope_mode, diff_base=args.diff_base, fail_on=args.fail_on)
            exit_code = max(exit_code, audit_repo(child))
    return exit_code


def view_reports(args: argparse.Namespace) -> int:
    try:
        from scripts.viewer import list_runs, serve
    except ModuleNotFoundError:  # direct ``python scripts/agentsec.py`` invocation
        from viewer import list_runs, serve

    if args.list_runs:
        runs = list_runs(REPORT_ROOT)
        if not runs:
            print("No AgentSec report runs found.")
            return 0
        for run in runs:
            print(run.name)
        return 0
    return serve(REPORT_ROOT, args.run_name, port=args.port, open_browser=not args.no_browser)


def list_capabilities(args: argparse.Namespace) -> int:
    """List or search the portable AgentSec capability catalog."""
    catalog_path = ROOT / "skills" / "index.json"
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"AgentSec: capability catalog unavailable: {exc}", file=sys.stderr)
        return 1
    query = str(getattr(args, "query", "") or "").lower().strip()
    capabilities = catalog.get("capabilities", [])
    if query:
        capabilities = [item for item in capabilities if query in json.dumps(item).lower()]
    if not capabilities:
        print("No matching AgentSec capabilities.")
        return 0
    print(f"AgentSec capabilities ({len(capabilities)}):")
    for item in capabilities:
        print(f"- {item['name']} [{item.get('subdomain', 'uncategorized')}] — {item.get('description', '')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentsec",
        description="AgentSec: agentic defensive security auditing and remediation support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              agentsec capabilities
              agentsec capabilities web
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
    view.add_argument("--list", dest="list_runs", action="store_true", help="list saved report runs newest first")
    view.set_defaults(func=view_reports)

    capabilities = sub.add_parser("capabilities", help="list or search modular AgentSec security playbooks")
    capabilities.add_argument("query", nargs="?", help="case-insensitive name, tag, domain, or framework search")
    capabilities.set_defaults(func=list_capabilities)

    repo = sub.add_parser("repo", help="audit source, dependencies, secrets, and deployment configuration")
    repo.add_argument("path", nargs="?", default=".")
    repo.add_argument("--fix", action="store_true", help="apply conservative package-manager remediation where supported")
    repo.add_argument("--scan-mode", choices=("quick", "standard", "deep"), default="standard", help="quick skips optional heavy scanners; deep adds license scanning")
    repo.add_argument("-n", "--non-interactive", action="store_true", help="run headlessly and return a CI-friendly exit code")
    repo.add_argument("--instruction", help="custom focus or rules of engagement for agent-led review")
    repo.add_argument("--instruction-file", help="file containing custom focus or rules of engagement")
    repo.add_argument("--scope-mode", choices=("auto", "diff", "full"), default="auto", help="record full or changed-file review scope")
    repo.add_argument("--diff-base", help="git base ref used for diff scope metadata")
    repo.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info"), default="high", help="CI exits 2 for confirmed findings at or above this severity")
    repo.add_argument("--include-tests", action="store_true", help="include test and fixture directories in source-pattern review")
    repo.set_defaults(func=audit_repo)

    web = sub.add_parser("web", aliases=["url"], help="audit a web application or URL")
    web.add_argument("url")
    web.add_argument("--authorized", action="store_true", help="confirm you own or have permission to assess the target")
    web.add_argument("--active", action="store_true", help="run controlled active SQLi/XSS validation; requires --authorized")
    web.add_argument("--browser", action="store_true", help="run an optional Playwright browser baseline; requires --authorized --active")
    web.add_argument("--baseline-only", action="store_true", help="run bounded web checks and skip long optional surface scanners")
    web.set_defaults(func=audit_web)

    api = sub.add_parser("api", help="inventory an OpenAPI/Swagger JSON contract and optionally probe safe read-only endpoints")
    api.add_argument("spec", help="OpenAPI/Swagger JSON file")
    api.add_argument("--base-url", help="live API base URL for bounded read-only probing")
    api.add_argument("--authorized", action="store_true", help="confirm permission to probe the supplied API")
    api.set_defaults(func=audit_api)

    server = sub.add_parser("server", help="audit local hardening or an authorized server's external attack surface")
    group = server.add_mutually_exclusive_group(required=True)
    group.add_argument("--local", action="store_true")
    group.add_argument("--target")
    server.add_argument("--authorized", action="store_true", help="confirm authorization for remote scanning")
    server.set_defaults(func=audit_server)

    scan = sub.add_parser("scan", help="audit multiple local repositories and authorized web targets")
    scan.add_argument("-t", "--target", action="append", help="local directory or http(s) URL; may be repeated")
    scan.add_argument("--target-list", action="append", help="file containing one target per non-empty, non-comment line")
    scan.add_argument("-n", "--non-interactive", action="store_true", help="run headlessly")
    scan.add_argument("--authorized", action="store_true", help="authorize remote baseline/scanning for supplied web targets")
    scan.add_argument("--active", action="store_true", help="enable controlled active web checks; requires --authorized")
    scan.add_argument("--baseline-only", action="store_true", help="only run bounded web baseline checks")
    scan.add_argument("--scan-mode", choices=("quick", "standard", "deep"), default="standard")
    scan.add_argument("--instruction")
    scan.add_argument("--instruction-file")
    scan.add_argument("--scope-mode", choices=("auto", "diff", "full"), default="auto")
    scan.add_argument("--diff-base")
    scan.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info"), default="high")
    scan.set_defaults(func=audit_scan)
    return parser


def main() -> int:
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    try:
        args = build_parser().parse_args()
        return int(args.func(args))
    except KeyboardInterrupt:
        print("AgentSec: interrupted; preserved artifacts remain available in .agentsec/reports.", file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError) as exc:
        # CLI failures should be actionable without dumping a traceback or
        # hiding the distinction between a failed check and a failed run.
        print(f"AgentSec: audit could not complete safely: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
