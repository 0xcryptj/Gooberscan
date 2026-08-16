#!/usr/bin/env python3
"""Build the discoverable AgentSec capability catalog."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = ROOT / "skills"


def frontmatter(text: str) -> dict[str, str | list[str]]:
    match = re.match(r"^---\n(.*?)\n---(?:\n|$)", text, re.DOTALL)
    if not match:
        raise ValueError("missing YAML frontmatter")
    data: dict[str, str | list[str]] = {}
    for line in match.group(1).splitlines():
        parsed = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if not parsed:
            continue
        key, raw = parsed.groups()
        raw = raw.strip().strip("'\"")
        data[key] = [item.strip().strip("'\"") for item in raw[1:-1].split(",") if item.strip()] if raw.startswith("[") and raw.endswith("]") else raw
    return data


def main() -> int:
    entries = []
    subdomains: Counter[str] = Counter()
    frameworks: Counter[str] = Counter()
    for directory in sorted(SKILLS_ROOT.iterdir()):
        skill_md = directory / "SKILL.md"
        if not skill_md.is_file():
            continue
        data = frontmatter(skill_md.read_text(encoding="utf-8"))
        tags = data.get("tags", [])
        subdomain = str(data.get("subdomain", "uncategorized"))
        subdomains[subdomain] += 1
        for key in ("mitre_attack", "nist_csf", "owasp"):
            if data.get(key):
                frameworks[key] += 1
        entries.append({
            "name": str(data.get("name", directory.name)),
            "description": str(data.get("description", "")),
            "domain": str(data.get("domain", "security")),
            "subdomain": subdomain,
            "tags": tags if isinstance(tags, list) else [],
            "version": str(data.get("version", "1.0")),
            "path": str(directory.relative_to(ROOT)),
        })
    catalog = {
        "schema_version": "1.0.0",
        "project": "AgentSec",
        "repository": "https://github.com/0xcryptj/AgentSec",
        "total_capabilities": len(entries),
        "capabilities": entries,
        "coverage": {"subdomains": dict(sorted(subdomains.items())), "framework_mappings": dict(sorted(frameworks.items()))},
    }
    output = SKILLS_ROOT / "index.json"
    output.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output} with {len(entries)} capabilities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
