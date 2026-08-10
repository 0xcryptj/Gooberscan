#!/usr/bin/env python3
"""Safe, dependency-free report artifacts for AgentSec findings."""

from __future__ import annotations

import csv
import io
import json
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unclassified": 5}


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.replace(path)


def safe_fence(content: str) -> str:
    longest = max((len(match.group()) for match in re.finditer(r"`+", content)), default=0)
    return "`" * max(3, longest + 1)


def render_finding(finding: dict[str, Any]) -> str:
    lines = [
        f"# {finding.get('title', 'Security finding')}",
        "",
        f"- **ID:** `{finding.get('id', 'unknown')}`",
        f"- **Status:** `{finding.get('status', 'review-needed')}`",
        f"- **Severity:** `{finding.get('severity', 'unclassified')}`",
        f"- **Confidence:** `{finding.get('confidence', 'unconfirmed')}`",
    ]
    for label, key in (("Category", "category"), ("CWE", "cwe"), ("CVSS", "cvss"), ("Evidence", "evidence"), ("Location", "location")):
        value = finding.get(key)
        if value:
            lines.append(f"- **{label}:** {value}")
    lines += ["", "## Description", "", str(finding.get("reason") or finding.get("description") or "Evidence requires review."), ""]
    if finding.get("impact"):
        lines += ["## Impact", "", str(finding["impact"]), ""]
    if finding.get("recommendation"):
        lines += ["## Remediation", "", str(finding["recommendation"]), ""]
    if finding.get("fix_effort"):
        lines += [f"**Fix effort:** {finding['fix_effort']}", ""]
    raw = finding.get("raw")
    if raw:
        text = json.dumps(raw, indent=2, ensure_ascii=False) if isinstance(raw, (dict, list)) else str(raw)
        fence = safe_fence(text)
        lines += ["## Evidence detail", "", f"{fence}json", text, fence, ""]
    return "\n".join(lines) + "\n"


def write_reports(outdir: Path, findings: list[dict[str, Any]], *, scope: str, metadata: dict[str, Any] | None = None) -> None:
    """Write stable JSON/CSV/Markdown artifacts without exposing raw secrets in HTML."""
    ordered = sorted(findings, key=lambda item: (SEVERITY_ORDER.get(str(item.get("severity")), 5), str(item.get("title", ""))))
    vulnerability_dir = outdir / "vulnerabilities"
    vulnerability_dir.mkdir(parents=True, exist_ok=True)
    for finding in ordered:
        _atomic_write(vulnerability_dir / f"{finding.get('id', 'finding')}.md", render_finding(finding))

    _atomic_write(outdir / "vulnerabilities.json", json.dumps(ordered, indent=2, ensure_ascii=False, default=str) + "\n")
    csv_buffer = io.StringIO()
    writer = csv.DictWriter(csv_buffer, fieldnames=["id", "title", "status", "severity", "confidence", "category", "cwe", "cvss", "file"], lineterminator="\n")
    writer.writeheader()
    for finding in ordered:
        writer.writerow({key: finding.get(key, "") for key in ("id", "title", "status", "severity", "confidence", "category", "cwe", "cvss")} | {"file": f"vulnerabilities/{finding.get('id', 'finding')}.md"})
    _atomic_write(outdir / "vulnerabilities.csv", csv_buffer.getvalue())

    counts: dict[str, int] = {}
    for finding in ordered:
        severity = str(finding.get("severity", "unclassified"))
        counts[severity] = counts.get(severity, 0) + 1
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = ["# AgentSec Security Assessment", "", f"**Scope:** {scope}", f"**Generated:** {generated}", "", "## Executive summary", ""]
    lines.append(f"AgentSec recorded **{len(ordered)}** normalized findings and review items.")
    if counts:
        lines.append("Severity breakdown: " + ", ".join(f"{key}={value}" for key, value in sorted(counts.items(), key=lambda pair: SEVERITY_ORDER.get(pair[0], 5))) + ".")
    else:
        lines.append("No findings were produced by the available checks.")
    lines += ["", "## Prioritized findings", ""]
    for finding in ordered:
        lines.append(f"- **{finding.get('title', 'Security finding')}** — `{finding.get('status', 'review-needed')}`, `{finding.get('severity', 'unclassified')}`; {finding.get('recommendation', 'Correlate evidence with source and runtime configuration.')}")
    if metadata:
        lines += ["", "## Run metadata", "", "```json", json.dumps(metadata, indent=2, default=str), "```"]
    _atomic_write(outdir / "penetration_test_report.md", "\n".join(lines) + "\n")
