#!/usr/bin/env python3
"""Conservative source-pattern index for high-risk security flows."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


IGNORE = {".git", ".agentsec", "node_modules", "venv", ".venv", "dist", "build", ".next", "__pycache__"}
TEST_DIRS = {"test", "tests", "fixtures", "__tests__"}
TEXT_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".php", ".rs", ".yml", ".yaml", ".json", ".env", ".conf", ".tf", ".sql"}
RULES = [
    # Argument-vector subprocess calls are not command injection by themselves.
    # Require an explicit shell or inherently shell-backed API before raising a
    # high-signal source finding.
    ("command-execution", re.compile(r"\b(?:os\.(?:system|popen)|child_process\.exec(?:Sync)?|subprocess\.(?:run|Popen|call)\([^\n]*(?:shell\s*=\s*True|shell=True)|exec\s*\()"), "Potential command execution sink.", "Validate input, avoid shell interpretation, and use an allowlisted argument vector.", "high", "CWE-78"),  # agentsec: ignore
    ("sql-interpolation", re.compile(r"(?i)(select|insert|update|delete)\b[^\n]*(%\(|\.format\(|f['\"]|\+\s*[A-Za-z_])"), "Potential SQL query construction from interpolated input.", "Use parameterized queries or the framework's safe query builder.", "high", "CWE-89"),
    ("wildcard-cors", re.compile(r"(?i)(access-control-allow-origin|cors|allow_origins)[^\n]*(\*|['\"]\*['\"])"), "Wildcard cross-origin policy detected.", "Restrict origins and never combine wildcard origins with credentialed requests.", "medium", "CWE-942"),
    ("unsafe-tls", re.compile(r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*[:=]\s*false|InsecureSkipVerify\s*:\s*true)"), "TLS certificate verification appears disabled.", "Keep certificate verification enabled and use a trusted CA/configured test certificate.", "high", "CWE-295"),
    ("hardcoded-secret", re.compile(r"(?i)\b(api[_-]?key|secret|password|token)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]"), "Possible hardcoded credential or secret.", "Move credentials to a secret manager or environment injection and rotate exposed values.", "high", "CWE-798"),
    ("auth-bypass-route", re.compile(r"(?i)(app\.(?:get|post|put|patch|delete)|router\.(?:get|post|put|patch|delete))\s*\([^\n]*(?:admin|auth|account|role|permission|reset|verify)"), "Sensitive route requires an explicit authorization review.", "Verify authentication, object-level authorization, tenant checks, and abuse controls at the server boundary.", "medium", "CWE-862"),
]


def scan(path: Path, *, include_tests: bool = False) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for base, dirs, files in os.walk(path):
        dirs[:] = [name for name in dirs if name not in IGNORE]
        if not include_tests:
            dirs[:] = [name for name in dirs if name not in TEST_DIRS]
        for filename in files:
            file_path = Path(base) / filename
            if file_path.suffix.lower() not in TEXT_SUFFIXES and filename not in {"Dockerfile", "Makefile"}:
                continue
            try:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            relative = str(file_path.relative_to(path))
            for line_number, line in enumerate(lines, start=1):
                if "agentsec: ignore" in line.lower():
                    continue
                for rule, pattern, title, recommendation, severity, cwe in RULES:
                    if pattern.search(line):
                        findings.append({"rule": rule, "title": title, "severity": severity, "cwe": cwe, "location": f"{relative}:{line_number}", "reason": f"{title} Evidence: {line.strip()[:240]}", "recommendation": recommendation})
                        break
                if len(findings) >= 500:
                    return findings
    return findings


def write(path: Path, output: Path, *, include_tests: bool = False) -> int:
    findings = scan(path, include_tests=include_tests)
    output.write_text(json.dumps({"findings": findings, "truncated": len(findings) >= 500}, indent=2), encoding="utf-8")
    return len(findings)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--output", required=True)
    parser.add_argument("--include-tests", action="store_true", help="include test and fixture directories in source-pattern review")
    args = parser.parse_args()
    raise SystemExit(0 if write(Path(args.path), Path(args.output), include_tests=args.include_tests) == 0 else 1)
