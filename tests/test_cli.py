import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.agentsec import build_parser, url_parts
from scripts.finding_model import finding_from_check, write_findings
from scripts.sarif import build_sarif
from scripts.viewer import render_dashboard, select_run
from scripts.web_baseline import analyze_responses


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

    def test_findings_index_is_written(self):
        with TemporaryDirectory() as directory:
            findings = write_findings(
                Path(directory),
                [{"name": "Gitleaks", "returncode": 1, "output": "gitleaks.txt"}],
            )
            self.assertEqual(len(findings), 1)
            self.assertTrue((Path(directory) / "findings.json").exists())
            self.assertTrue((Path(directory) / "findings.sarif").exists())

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

    def test_web_baseline_only_flag_is_available(self):
        args = build_parser().parse_args(["web", "https://example.com", "--authorized", "--baseline-only"])
        self.assertTrue(args.authorized)
        self.assertTrue(args.baseline_only)

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
