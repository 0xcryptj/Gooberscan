#!/usr/bin/env python3
"""Write conservative AgentSec review items as SARIF 2.1.0."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _rule_id(finding: dict[str, Any]) -> str:
    return str(finding.get("id") or "agentsec-review-needed")


def _level(finding: dict[str, Any]) -> str:
    return "warning" if finding.get("status") in {"review-needed", "needs-source-review"} else "note"


def build_sarif(findings: list[dict[str, Any]], *, version: str = "development") -> dict[str, Any]:
    """Build a SARIF document without claiming unconfirmed findings are vulnerabilities."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rules: set[str] = set()

    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id not in seen_rules:
            rules.append({
                "id": rule_id,
                "name": str(finding.get("title", rule_id)),
                "shortDescription": {"text": "Deterministic security evidence requires review"},
                "defaultConfiguration": {"level": _level(finding)},
            })
            seen_rules.add(rule_id)

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _level(finding),
            "kind": "review" if _level(finding) == "warning" else "informational",
            "message": {
                "text": (
                    f"{finding.get('title', 'Security evidence requires review')}: "
                    f"{finding.get('reason', 'correlate the evidence with source and runtime context')}. "
                    f"Recommended action: {finding.get('recommendation', 'correlate with source and runtime context')}. "
                    + ("This is evidence-backed and should be validated before remediation is merged." if finding.get("status") == "evidence-backed" else "This is not a confirmed vulnerability.")
                ),
            },
            "properties": {
                "agentsec.status": finding.get("status", "review-needed"),
                "agentsec.confidence": finding.get("confidence", "unconfirmed"),
                "agentsec.severity": finding.get("severity", "unclassified"),
            },
        }
        evidence = finding.get("evidence")
        if isinstance(evidence, list):
            evidence = "summary.json"
        if evidence:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(evidence)},
                },
            }]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AgentSec",
                    "version": version,
                    "informationUri": "https://github.com/0xcryptj/AgentSec",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }


def write_sarif(outdir: Path, findings: list[dict[str, Any]], *, version: str = "development") -> Path:
    """Write ``findings.sarif`` beside the JSON and Markdown report artifacts."""
    path = outdir / "findings.sarif"
    path.write_text(json.dumps(build_sarif(findings, version=version), indent=2) + "\n", encoding="utf-8")
    return path
