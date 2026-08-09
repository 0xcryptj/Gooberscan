import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.agentsec import build_parser, url_parts
from scripts.finding_model import finding_from_check, write_findings
from scripts.sarif import build_sarif
from scripts.viewer import render_dashboard, select_run


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


if __name__ == "__main__":
    unittest.main()
