import json
import unittest
from pathlib import Path

from tools.build_skill_index import SKILLS_ROOT, frontmatter
from tools.validate_skills import validate


class CapabilityTests(unittest.TestCase):
    def test_all_capabilities_have_valid_metadata_and_structure(self):
        paths = sorted(path for path in SKILLS_ROOT.iterdir() if path.is_dir())
        self.assertGreaterEqual(len(paths), 5)
        for path in paths:
            self.assertEqual(validate(path), [], path.name)

    def test_catalog_is_machine_readable(self):
        catalog = json.loads((SKILLS_ROOT / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(catalog["total_capabilities"], len(catalog["capabilities"]))
        self.assertIn("framework_mappings", catalog["coverage"])
        self.assertTrue(all(frontmatter((SKILLS_ROOT / entry["name"] / "SKILL.md").read_text(encoding="utf-8")) for entry in catalog["capabilities"]))


if __name__ == "__main__":
    unittest.main()
