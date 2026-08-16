#!/usr/bin/env python3
"""Validate AgentSec capability playbooks."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = ROOT / "skills"
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REQUIRED = ("name", "description", "domain", "subdomain", "tags", "version", "author", "license")
SECTIONS = ("When to Use", "Prerequisites", "Workflow", "Verification")


def parse_frontmatter(text: str) -> dict[str, str | list[str]] | None:
    match = re.match(r"^---\n(.*?)\n---(?:\n|$)", text, re.DOTALL)
    if not match:
        return None
    values: dict[str, str | list[str]] = {}
    current: str | None = None
    for line in match.group(1).splitlines():
        if line.startswith((" ", "\t")) and current and isinstance(values.get(current), list):
            item = line.strip()
            if item.startswith("-"):
                values[current].append(item[1:].strip().strip("'\""))
            continue
        key_match = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if not key_match:
            continue
        current, raw = key_match.groups()
        raw = raw.strip().strip("'\"")
        if raw.startswith("[") and raw.endswith("]"):
            values[current] = [item.strip().strip("'\"") for item in raw[1:-1].split(",") if item.strip()]
        else:
            values[current] = raw
    return values


def validate(path: Path) -> list[str]:
    errors: list[str] = []
    skill_md = path / "SKILL.md"
    if not skill_md.is_file():
        return ["missing SKILL.md"]
    text = skill_md.read_text(encoding="utf-8")
    frontmatter = parse_frontmatter(text)
    if frontmatter is None:
        return ["missing YAML frontmatter"]
    for field in REQUIRED:
        if not frontmatter.get(field):
            errors.append(f"missing required field: {field}")
    name = str(frontmatter.get("name", ""))
    if name != path.name:
        errors.append(f"name {name!r} does not match directory {path.name!r}")
    if not NAME_RE.fullmatch(name):
        errors.append("name must use lowercase kebab-case")
    if len(str(frontmatter.get("description", ""))) < 50:
        errors.append("description must be at least 50 characters")
    tags = frontmatter.get("tags", [])
    if not isinstance(tags, list) or len(tags) < 2:
        errors.append("tags must contain at least two values")
    for section in SECTIONS:
        if not re.search(rf"^##\s+{re.escape(section)}\s*$", text, re.MULTILINE):
            errors.append(f"missing section: {section}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="skill directories; defaults to all skills")
    args = parser.parse_args()
    paths = args.paths or sorted(path for path in SKILLS_ROOT.iterdir() if path.is_dir() and not path.name.startswith("."))
    failed = False
    names: set[str] = set()
    for path in paths:
        errors = validate(path)
        if path.name in names:
            errors.append("duplicate skill directory")
        names.add(path.name)
        if errors:
            failed = True
            print(f"FAIL {path}: " + "; ".join(errors))
        else:
            print(f"PASS {path}")
    print(f"Validated {len(paths)} AgentSec capabilities")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
