#!/usr/bin/env python3
"""Private localhost viewer for AgentSec report artifacts."""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import threading
import webbrowser
from typing import Any
from urllib.parse import parse_qs, urlparse


def _read_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback


def _text(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _finding_card(finding: dict[str, Any]) -> str:
    title = _text(finding.get("title", "Review item"))
    status = _text(finding.get("status", "review-needed"))
    confidence = _text(finding.get("confidence", "unconfirmed"))
    severity = _text(finding.get("severity", "unclassified"))
    evidence = _text(finding.get("evidence", "No evidence path recorded"))
    reason = _text(finding.get("reason", "Review the preserved scanner output"))
    return f"""
      <article class="finding">
        <div class="finding-top"><span class="pill">{status}</span><span>{severity}</span></div>
        <h3>{title}</h3>
        <p>{reason}</p>
        <dl><dt>Confidence</dt><dd>{confidence}</dd><dt>Evidence</dt><dd><code>{evidence}</code></dd></dl>
      </article>
    """


def render_dashboard(run_dir: Path) -> str:
    """Render one report run as escaped, dependency-free HTML."""
    summary = _read_json(run_dir / "summary.json", {})
    findings = _read_json(run_dir / "findings.json", [])
    if not isinstance(findings, list):
        findings = []
    scope = _text(summary.get("scope", run_dir.name))
    created = _text(summary.get("created_at", "unknown"))
    finding_markup = "".join(
        _finding_card(item) for item in findings if isinstance(item, dict)
    )
    if not finding_markup:
        finding_markup = '<div class="empty">No deterministic checks currently require review.</div>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentSec · {_text(run_dir.name)}</title>
<style>
:root {{ color-scheme: dark; --bg:#0b0c0f; --panel:#15171c; --line:#2b2e36; --text:#f4f5f7; --muted:#a5a9b3; --red:#e1261c; --green:#42d392; }}
* {{ box-sizing:border-box }} body {{ margin:0; background:radial-gradient(circle at 10% 0%,#231315 0,#0b0c0f 36%); color:var(--text); font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif; }}
main {{ max-width:1080px; margin:0 auto; padding:42px 22px 72px; }} header {{ display:flex; gap:18px; align-items:center; border-bottom:1px solid var(--line); padding-bottom:24px; }}
header img {{ width:58px; height:58px; border-radius:14px; }} h1 {{ margin:0; font-size:28px; letter-spacing:-.03em }} h2 {{ margin:34px 0 14px; font-size:18px }} h3 {{ margin:12px 0 8px; font-size:17px }}
.eyebrow {{ color:var(--red); font-weight:700; letter-spacing:.12em; text-transform:uppercase; font-size:11px }} .meta {{ color:var(--muted); margin:4px 0 0; }}
.grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-top:24px }} .stat,.finding {{ background:color-mix(in srgb,var(--panel) 92%,transparent); border:1px solid var(--line); border-radius:14px; padding:18px; }}
.stat strong {{ display:block; font-size:25px }} .stat span {{ color:var(--muted); font-size:12px }} .findings {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:12px }}
.finding-top {{ display:flex; justify-content:space-between; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em }} .pill {{ color:var(--green); }} .finding p {{ color:var(--muted); min-height:48px }}
dl {{ border-top:1px solid var(--line); padding-top:12px; margin-bottom:0 }} dt {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.08em }} dd {{ margin:2px 0 10px; overflow-wrap:anywhere }} code {{ color:#ff9d96 }} .empty {{ border:1px dashed var(--line); border-radius:14px; padding:28px; color:var(--muted); }}
@media(max-width:700px) {{ .grid {{ grid-template-columns:1fr }} main {{ padding-top:24px }} }}
</style></head><body><main>
<header><img src="/agentsec-logo.png" alt="AgentSec"><div><div class="eyebrow">Audit · Reason · Remediate · Verify</div><h1>AgentSec report</h1><p class="meta">{scope}<br>Created {created}</p></div></header>
<section class="grid"><div class="stat"><strong>{len(findings)}</strong><span>Review items</span></div><div class="stat"><strong>{_text(summary.get("version", "unknown"))}</strong><span>AgentSec version</span></div><div class="stat"><strong>Local</strong><span>Report stays on this machine</span></div></section>
<h2>Review queue</h2><section class="findings">{finding_markup}</section>
<h2>Artifacts</h2><p class="meta"><code>summary.json</code> · <code>findings.json</code> · <code>findings.sarif</code> · preserved scanner output</p>
</main></body></html>"""


def latest_run(report_root: Path) -> Path | None:
    if not report_root.is_dir():
        return None
    runs = [path for path in report_root.iterdir() if path.is_dir()]
    return max(runs, key=lambda path: path.stat().st_mtime) if runs else None


def select_run(report_root: Path, run_name: str | None) -> Path:
    report_root = report_root.resolve()
    run_dir = latest_run(report_root) if not run_name else (report_root / run_name).resolve()
    if run_dir is None or not run_dir.is_dir() or report_root not in run_dir.parents:
        raise ValueError("No valid AgentSec report run was found")
    return run_dir


def serve(report_root: Path, run_name: str | None = None, *, port: int = 0, open_browser: bool = True) -> int:
    run_dir = select_run(report_root, run_name)
    token = secrets.token_urlsafe(24)
    logo_path = report_root.parent.parent / "assets" / "agentsec-logo.png"
    html_page = render_dashboard(run_dir).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            query = parse_qs(urlparse(self.path).query)
            supplied = query.get("token", [""])[0]
            if not secrets.compare_digest(supplied, token):
                self.send_error(403, "A valid viewer token is required")
                return
            path = urlparse(self.path).path
            if path == "/" or path == "/index.html":
                payload = html_page
                content_type = "text/html; charset=utf-8"
            elif path == "/agentsec-logo.png" and logo_path.is_file():
                payload = logo_path.read_bytes()
                content_type = "image/png"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; base-uri 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{server.server_port}/?token={token}"
    print(f"AgentSec viewer: {url}")
    print("Press Ctrl-C to stop.")
    if open_browser:
        threading.Timer(0.15, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0
