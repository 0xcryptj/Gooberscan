import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "architecture_inventory.py"
spec = importlib.util.spec_from_file_location("architecture_inventory", MODULE_PATH)
architecture_inventory = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(architecture_inventory)


class ArchitectureInventoryTests(unittest.TestCase):
    def test_detects_auth_database_cloudflare_and_design_opportunities(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "public").mkdir()
            (root / "src").mkdir()
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "dependencies": {
                            "next": "15.0.0",
                            "next-auth": "5.0.0",
                            "@prisma/client": "6.0.0",
                        }
                    }
                ),
                encoding="utf-8",
            )
            (root / "wrangler.toml").write_text("name = 'demo'\n", encoding="utf-8")
            (root / "src" / "auth.ts").write_text(
                "export const roles = ['user', 'admin'];\n",
                encoding="utf-8",
            )

            result = architecture_inventory.analyze(root)
            signals = result["signals"]
            titles = {item["title"] for item in result["opportunities"]}

            self.assertTrue(signals["auth_present"])
            self.assertTrue(signals["database_present"])
            self.assertTrue(signals["cloudflare_present"])
            self.assertIn("next", signals["frameworks"])
            self.assertIn("Perform a least-privilege authorization pass", titles)
            self.assertIn("Verify least-privilege database identities", titles)
            self.assertIn("Use Cloudflare as a security control plane", titles)
            self.assertIn("Evaluate MFA/passkeys for privileged and high-impact accounts", titles)
            self.assertIn("Consider robots.txt for crawler policy", titles)
            self.assertIn("Consider llms.txt for AI-readable documentation", titles)

    def test_robots_and_llms_are_not_classified_as_security_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "public").mkdir()
            result = architecture_inventory.analyze(root)
            recommendations = {item["title"]: item for item in result["opportunities"]}

            self.assertFalse(recommendations["Consider robots.txt for crawler policy"]["security_control"])
            self.assertFalse(recommendations["Consider llms.txt for AI-readable documentation"]["security_control"])

    def test_external_mfa_cannot_be_declared_missing_when_marker_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"next-auth": "5.0.0"}}),
                encoding="utf-8",
            )
            (root / "src" / "security.ts").write_text(
                "// Enterprise IdP requires WebAuthn MFA for admin accounts\n",
                encoding="utf-8",
            )

            result = architecture_inventory.analyze(root)
            titles = {item["title"] for item in result["opportunities"]}
            self.assertNotIn("Evaluate MFA/passkeys for privileged and high-impact accounts", titles)


if __name__ == "__main__":
    unittest.main()
