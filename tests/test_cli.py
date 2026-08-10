import os
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.agentsec import architecture_observations, build_parser, save_summary, url_parts
from scripts.finding_model import finding_from_check, finding_from_observation, findings_from_check, write_findings
from scripts.sarif import build_sarif
from scripts.viewer import list_runs, render_dashboard, select_run
from scripts.web_baseline import analyze_responses
from scripts.scan_session import ScanSession
from scripts.api_probe import inventory, load_spec
from scripts.source_security import scan, write as write_source


class CliTests(unittest.TestCase):
    def test_url_alias_uses_web_audit(self):
        args = build_parser().parse_args(["url", "https://example.com", "--authorized"])
        self.assertEqual(args.url, "https://example.com")
        self.assertTrue(args.authorized)
        self.assertEqual(args.func.__name__, "audit_web")

    def test_url_validation_rejects_non_http_urls(self):
        with self.assertRaises(ValueError):
            url_parts("example.com")

    def test_nonzero_check_becomes_unconfirmed_review_item(self):
        finding = finding_from_check({
            "name": "Semgrep",
            "available": True,
            "returncode": 1,
            "output": "semgrep.txt",
        })
        self.assertEqual(finding["status"], "review-needed")
        self.assertEqual(finding["confidence"], "unconfirmed")
        self.assertEqual(finding["severity"], "unclassified")

    def test_clean_and_skipped_checks_are_not_findings(self):
        self.assertIsNone(finding_from_check({"name": "clean", "returncode": 0}))
        self.assertIsNone(finding_from_check({"name": "missing", "skipped": True}))

    def test_observation_becomes_an_individual_finding(self):
        finding = finding_from_observation({
            "title": "Missing CSP",
            "category": "headers",
            "status": "review-needed",
            "detail": "CSP was not observed",
            "recommendation": "Add a CSP",
        }, 1)
        self.assertEqual(finding["title"], "Missing CSP")
        self.assertEqual(finding["category"], "headers")
        self.assertEqual(finding["recommendation"], "Add a CSP")

    def test_findings_index_is_written(self):
        with TemporaryDirectory() as directory:
            findings = write_findings(
                Path(directory),
                [{"name": "Gitleaks", "returncode": 1, "output": "gitleaks.txt"}],
            )
            self.assertEqual(len(findings), 1)
            self.assertTrue((Path(directory) / "findings.json").exists())
            self.assertTrue((Path(directory) / "findings.sarif").exists())

    def test_report_history_lists_newest_runs(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / "reports"
            old = root / "old"
            new = root / "new"
            old.mkdir(parents=True)
            new.mkdir(parents=True)
            os.utime(old, (1, 1))
            os.utime(new, (2, 2))
            self.assertEqual([path.name for path in list_runs(root)], ["new", "old"])

    def test_view_list_flag_is_available(self):
        args = build_parser().parse_args(["view", "--list"])
        self.assertTrue(args.list_runs)

    def test_summary_contains_finding_status_and_category_counts(self):
        with TemporaryDirectory() as directory:
            outdir = Path(directory) / "run"
            outdir.mkdir()
            save_summary(
                outdir,
                "test scope",
                [{"name": "Semgrep", "returncode": 1, "output": "semgrep.txt"}],
                [],
                [{
                    "title": "Missing CSP",
                    "category": "headers",
                    "status": "opportunity",
                    "detail": "CSP was not observed",
                    "recommendation": "Add a CSP",
                }],
            )
            summary = json.loads((outdir / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["finding_status_counts"], {
                "opportunity": 1,
                "review-needed": 1,
            })
            self.assertEqual(summary["finding_category_counts"], {
                "evidence-review": 1,
                "headers": 1,
            })
            markdown = (outdir / "summary.md").read_text(encoding="utf-8")
            self.assertIn("## Overview", markdown)
            self.assertIn("**review-needed**: 1", markdown)

    def test_sarif_preserves_review_needed_status(self):
        document = build_sarif([
            {
                "id": "check-semgrep",
                "title": "Review Semgrep output",
                "status": "review-needed",
                "confidence": "unconfirmed",
                "severity": "unclassified",
                "evidence": "semgrep.txt",
                "reason": "reported a non-zero result",
            }
        ], version="test")
        self.assertEqual(document["version"], "2.1.0")
        result = document["runs"][0]["results"][0]
        self.assertEqual(result["level"], "warning")
        self.assertEqual(result["kind"], "review")
        self.assertIn("not a confirmed vulnerability", result["message"]["text"])
        self.assertEqual(result["properties"]["agentsec.status"], "review-needed")

    def test_sarif_uses_note_for_non_actionable_observation(self):
        document = build_sarif([{
            "id": "observation-robots-1",
            "title": "robots.txt not observed",
            "status": "opportunity",
            "reason": "No crawler policy was found",
            "recommendation": "Add one if useful",
        }])
        result = document["runs"][0]["results"][0]
        self.assertEqual(result["level"], "note")
        self.assertEqual(result["kind"], "informational")

    def test_viewer_escapes_report_content_and_selects_latest_run(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / "reports"
            run = root / "run-1"
            run.mkdir(parents=True)
            (run / "summary.json").write_text(
                '{"scope":"<unsafe-scope>","version":"test"}', encoding="utf-8"
            )
            (run / "findings.json").write_text(
                '[{"title":"<script>alert(1)</script>","reason":"review",'
                '"evidence":"raw.txt"}]', encoding="utf-8"
            )
            self.assertEqual(select_run(root, None), run)
            page = render_dashboard(run)
            self.assertNotIn("<script>alert(1)</script>", page)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)

    def test_web_baseline_reports_missing_controls_and_database_review(self):
        root = {
            "headers": {"access-control-allow-origin": "*"},
            "body_sample": "<html><body>app</body></html>",
        }
        paths = {
            "/robots.txt": {"status": 404, "final_url": "", "body_sample": ""},
            "/sitemap.xml": {"status": 404, "final_url": "", "body_sample": ""},
            "/.well-known/security.txt": {"status": 200, "final_url": "", "body_sample": "Redirecting..."},
            "/.git/HEAD": {"status": 404, "final_url": "", "body_sample": ""},
            "/.env": {"status": 404, "final_url": "", "body_sample": ""},
            "/server-status": {"status": 404, "final_url": "", "body_sample": ""},
            "/actuator/env": {"status": 404, "final_url": "", "body_sample": ""},
            "/phpinfo.php": {"status": 404, "final_url": "", "body_sample": ""},
            "/backup.zip": {"status": 404, "final_url": "", "body_sample": ""},
            "/config.json": {"status": 404, "final_url": "", "body_sample": ""},
            "/api": {"status": 404, "final_url": "", "body_sample": ""},
            "/graphql": {"status": 404, "final_url": "", "body_sample": ""},
            "/swagger.json": {"status": 404, "final_url": "", "body_sample": ""},
            "/openapi.json": {"status": 404, "final_url": "", "body_sample": ""},
        }
        observations = analyze_responses(root, paths)
        titles = {item["title"] for item in observations}
        self.assertIn("Missing browser security headers", titles)
        self.assertIn("Wildcard CORS policy observed", titles)
        self.assertIn("robots.txt not observed", titles)
        self.assertIn("Database security not observable from public HTML", titles)

    def test_web_baseline_detects_shared_spa_soft_404_without_root_body(self):
        shell = "<html><head><title>Sharp Shot</title></head><body>app</body></html>"
        root = {"headers": {"content-type": "text/html"}, "body_sample": ""}
        paths = {
            "/.env": {"status": 200, "headers": {"content-type": "text/html"}, "body_sample": shell},
            "/backup.zip": {"status": 200, "headers": {"content-type": "text/html"}, "body_sample": shell},
            "/api": {"status": 200, "headers": {"content-type": "text/html"}, "body_sample": shell},
        }
        observations = analyze_responses(root, paths)
        exposure_titles = {item["title"] for item in observations if item["category"] == "exposure"}
        self.assertNotIn("Potentially exposed Environment File", exposure_titles)
        self.assertNotIn("Potentially exposed Backup Archive", exposure_titles)

    def test_web_baseline_does_not_turn_unreachable_target_into_path_findings(self):
        observations = analyze_responses(
            {"status": None, "error": "DNS lookup failed", "headers": {}, "body_sample": ""},
            {"/.env": {"status": None, "body_sample": ""}},
        )
        self.assertEqual([item["title"] for item in observations], ["Target baseline unavailable"])
        self.assertEqual(observations[0]["status"], "review-needed")

    def test_web_baseline_only_flag_is_available(self):
        args = build_parser().parse_args(["web", "https://example.com", "--authorized", "--baseline-only"])
        self.assertTrue(args.authorized)
        self.assertTrue(args.baseline_only)

    def test_architecture_opportunities_are_report_observations(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "architecture.json"
            path.write_text(
                '{"opportunities":[{"title":"Review database roles",'
                '"category":"database","security_control":true,'
                '"why":"Database evidence exists",'
                '"recommended_action":"Inspect runtime roles"}]}',
                encoding="utf-8",
            )
            observations = architecture_observations(path)
            self.assertEqual(observations[0]["status"], "review-needed")
            self.assertEqual(observations[0]["title"], "Review database roles")

    def test_repository_scan_profiles_are_available(self):
        for mode in ("quick", "standard", "deep"):
            args = build_parser().parse_args(["repo", ".", "--scan-mode", mode])
            self.assertEqual(args.scan_mode, mode)

    def test_scan_accepts_repeated_targets_and_ci_options(self):
        args = build_parser().parse_args([
            "scan", "-t", ".", "-t", "https://example.com", "--target-list", "targets.txt",
            "-n", "--scope-mode", "diff", "--diff-base", "origin/main", "--fail-on", "medium",
        ])
        self.assertEqual(args.target, [".", "https://example.com"])
        self.assertEqual(args.target_list, ["targets.txt"])
        self.assertTrue(args.non_interactive)
        self.assertEqual(args.scope_mode, "diff")
        self.assertEqual(args.fail_on, "medium")

    def test_trivy_json_is_normalized_with_actionable_fields(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "trivy.txt"
            output.write_text(json.dumps({"Results": [{"Target": "Dockerfile", "Misconfigurations": [{
                "ID": "DS002", "Title": "Root user", "Severity": "HIGH", "Resolution": "Use a non-root user",
            }]}]}), encoding="utf-8")
            findings = findings_from_check({"name": "trivy-filesystem", "returncode": 1, "output": str(output)})
            self.assertEqual(findings[0]["status"], "evidence-backed")
            self.assertEqual(findings[0]["severity"], "high")
            self.assertEqual(findings[0]["location"], "Dockerfile")
            self.assertIn("non-root", findings[0]["recommendation"])

    def test_scan_session_persists_events_and_agent_state(self):
        with TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            run.mkdir()
            session = ScanSession.start(run, "test scope")
            session.agent("recon", "started", detail="mapping")
            session.agent("recon", "completed", result={"count": 2})
            session.finish()
            record = json.loads((run / "run.json").read_text(encoding="utf-8"))
            agents = json.loads((run / "agents.json").read_text(encoding="utf-8"))
            events = (run / "events.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(record["status"], "completed")
            self.assertEqual(agents[0]["status"], "completed")
            self.assertGreaterEqual(len(events), 4)

    def test_openapi_inventory_rejects_invalid_contract(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "api.json"
            path.write_text('{"openapi":"3.0.0","paths":{"/health":{"get":{"operationId":"health"}}}}', encoding="utf-8")
            self.assertEqual(inventory(load_spec(path))[0]["method"], "GET")
            path.write_text('{"openapi":"3.0.0"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_spec(path)

    def test_source_security_finds_high_risk_patterns_with_locations(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("import subprocess\nsubprocess.run(user_value, shell=True)\n", encoding="utf-8")
            findings = scan(root)
            self.assertEqual(findings[0]["severity"], "high")
            self.assertEqual(findings[0]["location"], "app.py:2")
            self.assertEqual(findings[0]["cwe"], "CWE-78")

    def test_source_security_ignores_safe_subprocess_and_test_fixtures_by_default(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("subprocess.run(['git', 'status'])\n", encoding="utf-8")
            fixture = root / "tests"
            fixture.mkdir()
            (fixture / "fixture.py").write_text("subprocess.run(user_value, shell=True)\n", encoding="utf-8")
            self.assertEqual(scan(root), [])
            self.assertEqual(scan(root, include_tests=True)[0]["location"], "tests/fixture.py:1")

    def test_source_security_patterns_remain_review_needed(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "source.json"
            (root / "app.py").write_text("subprocess.run(user_value, shell=True)\n", encoding="utf-8")
            write_source(root, output)
            findings = findings_from_check({"name": "source-security-patterns", "returncode": 1, "output": str(output)})
            self.assertEqual(findings[0]["status"], "review-needed")
            self.assertEqual(findings[0]["confidence"], "unconfirmed")

    def test_web_baseline_ignores_spa_soft_404s(self):
        from scripts.web_baseline import PATHS

        body = "<html><div id='app'>same shell</div></html>"
        root = {"headers": {"content-type": "text/html"}, "body_sample": body}
        paths = {
            path: {"status": 200, "final_url": path, "headers": {"content-type": "text/html"}, "body_sample": body}
            for path in PATHS
        }
        observations = analyze_responses(root, paths)
        titles = {item["title"] for item in observations}
        self.assertNotIn("Potentially exposed Git Metadata", titles)
        self.assertIn("No public git metadata response observed", titles)
        self.assertIn("robots.txt not observed", titles)


if __name__ == "__main__":
    unittest.main()
