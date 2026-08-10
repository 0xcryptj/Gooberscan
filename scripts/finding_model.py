#!/usr/bin/env python3
"""Normalize deterministic audit evidence into reviewable AgentSec findings."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json


SEVERITIES = {"critical", "high", "medium", "low", "info", "unclassified"}


def _severity(value: Any) -> str:
    normalized = str(value or "").lower().strip()
    return normalized if normalized in SEVERITIES else "unclassified"


def _fingerprint(*values: Any) -> str:
    payload = "|".join(str(value or "").strip().lower() for value in values)
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]


def _parsed_scanner_findings(check: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize common JSON scanner schemas into actionable report records."""
    output = check.get("output")
    if not output:
        return []
    output_path = Path(str(output))
    if not output_path.is_absolute() and check.get("output_dir"):
        output_path = Path(str(check["output_dir"])) / output_path
    try:
        data = json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
        return []
    records: list[dict[str, Any]] = []
    name = str(check.get("name", "scanner"))
    if name.startswith("trivy") and isinstance(data, dict):
        for result in data.get("Results", []):
            target = result.get("Target", "")
            for item in result.get("Vulnerabilities", []) + result.get("Misconfigurations", []) + result.get("Secrets", []):
                identifier = item.get("VulnerabilityID") or item.get("ID") or item.get("RuleID") or item.get("Title")
                records.append({"title": item.get("Title") or item.get("PkgName") or identifier, "severity": _severity(item.get("Severity")), "cve": item.get("VulnerabilityID") if str(item.get("VulnerabilityID", "")).upper().startswith("CVE-") else None, "location": target, "reason": item.get("Description") or item.get("Message") or f"{name} reported {identifier}.", "recommendation": item.get("Resolution") or "Apply the scanner's recommended remediation and retest.", "raw": item, "source": name, "category": "misconfiguration" if "Misconfigurations" in result else "vulnerability"})
    elif name.startswith("semgrep") and isinstance(data, dict):
        for item in data.get("results", []):
            extra = item.get("extra") or {}
            start = item.get("start") or {}
            records.append({"title": extra.get("message") or item.get("check_id"), "severity": _severity(extra.get("severity")), "location": f"{item.get('path', '')}:{start.get('line', '')}", "reason": extra.get("message") or "Semgrep reported a rule match.", "recommendation": "Review the data flow and apply the rule-specific remediation.", "cwe": (extra.get("metadata") or {}).get("cwe"), "raw": item, "source": name, "category": "sast"})
    elif name == "npm-audit" and isinstance(data, dict):
        for package, item in (data.get("vulnerabilities") or {}).items():
            for via in item.get("via", []):
                via = via if isinstance(via, dict) else {"title": str(via)}
                records.append({"title": via.get("title") or f"Vulnerable dependency: {package}", "severity": _severity(via.get("severity") or item.get("severity")), "cve": via.get("cve"), "location": package, "reason": via.get("url") or f"npm audit reported a vulnerability in {package}.", "recommendation": via.get("recommendation") or f"Upgrade {package} to a compatible patched version.", "raw": {"package": package, "advisory": via}, "source": name, "category": "dependency"})
    elif name == "source-security-patterns" and isinstance(data, dict):
        for item in data.get("findings", []):
            if not isinstance(item, dict):
                continue
            records.append({"title": item.get("title") or item.get("rule"), "severity": _severity(item.get("severity")), "location": item.get("location"), "reason": item.get("reason"), "recommendation": item.get("recommendation"), "cwe": item.get("cwe"), "raw": item, "source": name, "category": "source-security", "status": "review-needed", "confidence": "unconfirmed"})
    return records


def finding_from_check(check: dict[str, Any]) -> dict[str, Any] | None:
    """Return a review item for a check that needs human/agent follow-up.

    A non-zero scanner exit is evidence, not a confirmed vulnerability. The
    explicit ``review-needed`` status prevents the report layer from turning
    tool exit codes into security verdicts.
    """
    if check.get("skipped") or not check.get("available", True):
        return None
    if check.get("returncode") in (None, 0) and not check.get("timed_out"):
        return None

    name = str(check.get("name", "unknown-check"))
    slug = "".join(c.lower() if c.isalnum() else "-" for c in name).strip("-")
    reason = "timed out" if check.get("timed_out") else "reported a non-zero result"
    return {
        "id": f"check-{slug}",
        "title": f"Review {name} output",
        "source": "deterministic-check",
        "category": "evidence-review",
        "status": "review-needed",
        "confidence": "unconfirmed",
        "severity": "unclassified",
        "evidence": check.get("output"),
        "reason": reason,
        "returncode": check.get("returncode"),
    }


def findings_from_check(check: dict[str, Any]) -> list[dict[str, Any]]:
    parsed = _parsed_scanner_findings(check)
    findings: list[dict[str, Any]] = []
    for index, item in enumerate(parsed, start=1):
        title = str(item.get("title") or "Scanner finding")
        source = str(item.get("source") or check.get("name") or "scanner")
        fingerprint = _fingerprint(source, title, item.get("location"), item.get("cve"))
        finding = {
            "id": f"finding-{fingerprint}",
            "fingerprint": fingerprint,
            "title": title,
            "source": source,
            "category": item.get("category", "vulnerability"),
            "status": item.get("status", "evidence-backed"),
            "confidence": item.get("confidence", "evidence-backed"),
            "severity": _severity(item.get("severity")),
            "evidence": check.get("output"),
            "reason": item.get("reason"),
            "recommendation": item.get("recommendation"),
            "location": item.get("location"),
            "cwe": item.get("cwe"),
            "cve": item.get("cve"),
            "raw": item.get("raw"),
            "fix_effort": "medium",
        }
        findings.append(finding)
    if findings:
        return findings
    fallback = finding_from_check(check)
    return [fallback] if fallback else []


def finding_from_observation(observation: dict[str, Any], index: int) -> dict[str, Any] | None:
    """Turn one architecture/web observation into an actionable finding."""
    title = str(observation.get("title", "Untitled observation")).strip()
    if not title:
        return None
    slug = "".join(c.lower() if c.isalnum() else "-" for c in title).strip("-")
    status = str(observation.get("status", "review-needed"))
    evidence = observation.get("evidence") or "summary.json"
    return {
        "id": f"observation-{slug}-{index}",
        "title": title,
        "source": observation.get("source", "deterministic-observation"),
        "category": observation.get("category", "security-review"),
        "status": status,
        "confidence": observation.get("confidence", "unconfirmed"),
        "severity": observation.get("severity", "unclassified"),
        "security_control": observation.get("security_control", True),
        "evidence": evidence,
        "reason": observation.get("detail", "Correlate this observation with source and runtime context."),
        "recommendation": observation.get("recommendation", "Inspect the relevant source and runtime configuration."),
    }


def collect_findings(checks: list[dict[str, Any]], observations: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Collect normalized check and observation findings in report order."""
    findings = [finding for check in checks for finding in findings_from_check(check)]
    findings.extend(
        finding for index, observation in enumerate(observations or [], start=1)
        if (finding := finding_from_observation(observation, index))
    )
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        key = _fingerprint(finding.get("cve"), finding.get("location"), finding.get("title"), finding.get("category"))
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def write_findings(outdir: Path, checks: list[dict[str, Any]], observations: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Write the machine-readable finding index for a completed audit run."""
    import json

    checks = [dict(check, output_dir=str(outdir)) for check in checks]
    findings = collect_findings(checks, observations)
    try:
        from scripts.sarif import write_sarif
    except ModuleNotFoundError:  # direct ``python scripts/agentsec.py`` invocation
        from sarif import write_sarif

    (outdir / "findings.json").write_text(
        json.dumps(findings, indent=2),
        encoding="utf-8",
    )
    write_sarif(outdir, findings)
    try:
        from scripts.report_writer import write_reports
    except ModuleNotFoundError:
        from report_writer import write_reports
    summary_path = outdir / "summary.json"
    scope = "AgentSec audit"
    metadata: dict[str, Any] = {}
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            scope = str(summary.get("scope", scope))
            metadata = {"scan_mode": summary.get("scan_mode"), "finding_count": len(findings)}
        except (OSError, json.JSONDecodeError):
            pass
    write_reports(outdir, findings, scope=scope, metadata=metadata)
    return findings
