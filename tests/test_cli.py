import unittest

from scripts.agentsec import build_parser, url_parts


class CliTests(unittest.TestCase):
    def test_url_alias_uses_web_audit(self):
        args = build_parser().parse_args(["url", "https://example.com", "--authorized"])
        self.assertEqual(args.url, "https://example.com")
        self.assertTrue(args.authorized)
        self.assertEqual(args.func.__name__, "audit_web")

    def test_url_validation_rejects_non_http_urls(self):
        with self.assertRaises(ValueError):
            url_parts("example.com")


if __name__ == "__main__":
    unittest.main()
