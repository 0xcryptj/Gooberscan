#!/usr/bin/env python3
"""Persistent, local-only scan state and event history."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


class ScanSession:
    """A resumable run record with append-only events and agent state."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.record_path = run_dir / "run.json"
        self.events_path = run_dir / "events.jsonl"
        self.agents_path = run_dir / "agents.json"

    @classmethod
    def start(cls, run_dir: Path, scope: str, *, metadata: dict[str, Any] | None = None) -> "ScanSession":
        session = cls(run_dir)
        record = {"run_id": run_dir.name, "scope": scope, "status": "running", "started_at": _now(), "metadata": metadata or {}}
        _atomic_json(session.record_path, record)
        _atomic_json(session.agents_path, [])
        session.emit("scan_started", {"scope": scope})
        return session

    def _read(self, path: Path, fallback: Any) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return fallback

    def emit(self, event: str, payload: dict[str, Any] | None = None) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"timestamp": _now(), "event": event, "payload": payload or {}}, ensure_ascii=False, default=str) + "\n")

    def agent(self, name: str, status: str, *, detail: str = "", result: dict[str, Any] | None = None) -> None:
        agents = self._read(self.agents_path, [])
        if not isinstance(agents, list):
            agents = []
        current = next((item for item in agents if isinstance(item, dict) and item.get("name") == name), None)
        value = {"name": name, "status": status, "detail": detail, "updated_at": _now()}
        if result is not None:
            value["result"] = result
        if current is None:
            agents.append(value)
        else:
            current.update(value)
        _atomic_json(self.agents_path, agents)
        self.emit("agent_" + status, {"name": name, "detail": detail, "result": result or {}})

    def finish(self, status: str = "completed", *, error: str | None = None) -> None:
        record = self._read(self.record_path, {})
        if not isinstance(record, dict):
            record = {}
        record.update({"status": status, "ended_at": _now()})
        if error:
            record["error"] = error
        _atomic_json(self.record_path, record)
        self.emit("scan_finished", {"status": status, "error": error or ""})
