#!/usr/bin/env python3
"""Bounded OpenAPI/Swagger inventory and explicitly authorized API probing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


METHODS = ("get", "post", "put", "patch", "delete", "options", "head")


def load_spec(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"API specification is not readable JSON: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("paths"), dict):
        raise ValueError("API specification must be an OpenAPI/Swagger JSON document with paths")
    return value


def inventory(spec: dict[str, Any]) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    for path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method in METHODS:
            operation = item.get(method)
            if isinstance(operation, dict):
                endpoints.append({"method": method.upper(), "path": str(path), "operation_id": operation.get("operationId", ""), "auth": operation.get("security", spec.get("security", []))})
    return endpoints


def probe(spec: dict[str, Any], base_url: str, *, max_requests: int = 50) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    endpoints = inventory(spec)[:max_requests]
    observations: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for endpoint in endpoints:
        path = endpoint["path"]
        if "{" in path or endpoint["method"] not in {"GET", "HEAD", "OPTIONS"}:
            results.append({**endpoint, "status": "not-probed", "reason": "Template or state-changing endpoint; inventory only."})
            continue
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            request = Request(url, method=endpoint["method"], headers={"User-Agent": "AgentSec/authorized-api-audit"})
            with urlopen(request, timeout=8) as response:  # noqa: S310 - URL is explicit user scope
                status = response.status
        except HTTPError as exc:
            status = exc.code
        except (OSError, URLError) as exc:
            results.append({**endpoint, "url": url, "status": "error", "reason": str(exc)})
            continue
        results.append({**endpoint, "url": url, "status": status})
        if status >= 500:
            observations.append({"title": f"API endpoint returned server error: {endpoint['method']} {path}", "category": "api", "status": "review-needed", "detail": f"The declared endpoint returned HTTP {status} to a bounded unauthenticated request.", "recommendation": "Review error handling, authentication boundaries, and whether sensitive exception details are exposed."})
    return results, observations
