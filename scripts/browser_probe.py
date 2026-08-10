#!/usr/bin/env python3
"""Optional Playwright CLI browser baseline for authorized web scans."""

from __future__ import annotations

import shutil
from pathlib import Path


PLAYWRIGHT_WRAPPER = Path("/home/nano/.codex/skills/playwright/scripts/playwright_cli.sh")


def command() -> str | None:
    if shutil.which("playwright-cli"):
        return "playwright-cli"
    if PLAYWRIGHT_WRAPPER.is_file():
        return str(PLAYWRIGHT_WRAPPER)
    return None
