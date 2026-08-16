#!/usr/bin/env python3
"""Small local specialist-agent graph used by deterministic AgentSec scans."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable

try:
    from scripts.scan_session import ScanSession
except ModuleNotFoundError:
    from scan_session import ScanSession


@dataclass(frozen=True)
class AgentTask:
    name: str
    description: str
    run: Callable[[], dict[str, Any]]


class AgentGraph:
    """Run independent specialist tasks in parallel and persist every state change."""

    def __init__(self, session: ScanSession, *, max_workers: int = 4) -> None:
        self.session = session
        self.max_workers = max(1, max_workers)

    def run(self, tasks: list[AgentTask]) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        for task in tasks:
            self.session.agent(task.name, "started", detail=task.description)
        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(1, len(tasks)))) as executor:
            futures = {executor.submit(task.run): task for task in tasks}
            for future in as_completed(futures):
                task = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # each specialist fails independently
                    result = {"ok": False, "error": str(exc)}
                    self.session.agent(task.name, "failed", detail="Specialist task failed", result=result)
                else:
                    results[task.name] = result
                    self.session.agent(task.name, "completed", result=result)
        return results
