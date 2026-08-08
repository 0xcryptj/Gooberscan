import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "architecture_inventory.py"
spec = importlib.util.spec_from_file_location("architecture_inventory", MODULE_PATH)
architecture_inventory = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(architecture_inventory)

FIXTURES = Path(__file__).parent / "fixtures" / "capability"


class SecurityCapabilityTests(unittest.TestCase):
    def analyze(self, name):
        return architecture_inventory.analyze(FIXTURES / name)

    def titles(self, result):
        return {item["title"] for item in result["opportunities"]}

    def test_baas_inventory_distinguishes_policy_evidence_from_public_client_key(self):
        vulnerable = self.analyze("supabase-vulnerable")
        secure = self.analyze("supabase-secure")

        self.assertEqual(vulnerable["signals"]["baas_platforms"], ["supabase"])
        self.assertTrue(vulnerable["signals"]["public_client_credential_evidence"])
        self.assertFalse(vulnerable["signals"]["supabase_rls_enablement"])
        self.assertTrue(vulnerable["signals"]["public_database_grants"])
        self.assertTrue(vulnerable["signals"]["security_definer_functions"])
        self.assertIn("Verify Supabase tables fail closed with Row Level Security", self.titles(vulnerable))

        self.assertTrue(secure["signals"]["public_client_credential_evidence"])
        self.assertTrue(secure["signals"]["supabase_rls_enablement"])
        self.assertFalse(secure["signals"]["public_database_grants"])
        self.assertNotIn("Verify Supabase tables fail closed with Row Level Security", self.titles(secure))

    def test_authorization_inventory_surfaces_effective_rpc_boundary(self):
        vulnerable = self.analyze("authz-inversion-vulnerable")
        secure = self.analyze("authz-inversion-secure")

        self.assertTrue(vulnerable["signals"]["database_identity_checks"])
        self.assertTrue(vulnerable["signals"]["security_definer_functions"])
        self.assertTrue(vulnerable["signals"]["public_database_grants"])
        self.assertIn("Trace RPC and database-function authorization to the data operation", self.titles(vulnerable))

        self.assertTrue(secure["signals"]["database_identity_checks"])
        self.assertFalse(secure["signals"]["security_definer_functions"])
        self.assertFalse(secure["signals"]["public_database_grants"])

    def test_authentication_inventory_surfaces_alternate_identity_paths(self):
        vulnerable = self.analyze("auth-bypass-vulnerable")
        secure = self.analyze("auth-bypass-secure")

        self.assertTrue(vulnerable["signals"]["authentication_route_evidence"])
        self.assertTrue(vulnerable["signals"]["authentication_policy_evidence"])
        self.assertIn("Enumerate every authentication and identity-changing path", self.titles(vulnerable))

        self.assertTrue(secure["signals"]["authentication_route_evidence"])
        self.assertTrue(secure["signals"]["authentication_policy_evidence"])
        # Secure controls still warrant review; the inventory must not claim that
        # route presence alone proves a bypass.
        self.assertIn("Enumerate every authentication and identity-changing path", self.titles(secure))


if __name__ == "__main__":
    unittest.main()
