import unittest

from auditor.dependency_policy import check_dependency_policy
from auditor.license_policy import check_license_compliance
from auditor.typosquat import check_typosquat


class PolicyTests(unittest.TestCase):
    def test_unpinned_requirement_is_flagged(self):
        pkg = {
            "name": "requests",
            "ecosystem": "pip",
            "version": "unpinned",
            "source_file": "requirements.txt",
            "source_type": "direct",
            "raw_spec": "requests>=2",
            "hashes": [],
        }
        result = check_dependency_policy(pkg, {})
        self.assertFalse(result["pinned"])
        self.assertTrue(result["flags"])

    def test_permissive_license_passes(self):
        result = check_license_compliance("requests", "pip", {"license": "Apache-2.0"})
        self.assertEqual(result["status"], "PASS")

    def test_typosquat_reques7s(self):
        result = check_typosquat("reques7s", "pip")
        self.assertTrue(result["is_suspicious"])
        self.assertEqual(result["closest_match"], "requests")


if __name__ == "__main__":
    unittest.main()
