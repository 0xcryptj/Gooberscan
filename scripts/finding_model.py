#!/usr/bin/env python3
"""Normalize deterministic audit evidence into reviewable AgentSec findings."""

from __future__ import annotations

from pathlib import Path
from typing import Any


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
    findings = [finding for check in checks if (finding := finding_from_check(check))]
    findings.extend(
        finding for index, observation in enumerate(observations or [], start=1)
        if (finding := finding_from_observation(observation, index))
    )
    return findings


def write_findings(outdir: Path, checks: list[dict[str, Any]], observations: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Write the machine-readable finding index for a completed audit run."""
    import json

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
    return findings
