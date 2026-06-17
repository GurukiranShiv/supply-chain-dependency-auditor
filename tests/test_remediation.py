import unittest

from auditor.remediation import build_remediation
from auditor.scorer import RiskReport


class RemediationTests(unittest.TestCase):
    def test_typosquat_replacement_suggestion(self):
        report = RiskReport("reques7s", "pip", "1.0", 100, "CRITICAL", "bad", typosquat={"is_suspicious": True, "closest_match": "requests"}, metadata={}, vulns={})
        result = build_remediation(report)
        self.assertEqual(result["suggestions"][0]["type"], "replace_typosquat")
        self.assertFalse(result["suggestions"][0]["safe_to_auto_apply"])

    def test_osv_fixed_version_suggestion(self):
        report = RiskReport("demo", "npm", "1.0.0", 70, "HIGH", "upgrade", typosquat={}, metadata={}, vulns={"vulns": [{"affected_ranges": [{"fixed": "2.0.0"}]}]})
        result = build_remediation(report)
        self.assertEqual(result["suggestions"][0]["fixed_versions"], ["2.0.0"])
        self.assertIn("npm install demo@2.0.0", result["suggestions"][0]["command"])

    def test_pin_and_hash_suggestions(self):
        report = RiskReport("requests", "pip", "unpinned", 10, "LOW", "pin", metadata={"latest_version": "2.32.3"}, dependency_policy={"pinned": False, "has_integrity": False}, vulns={})
        result = build_remediation(report)
        types = {s["type"] for s in result["suggestions"]}
        self.assertIn("pin_dependency", types)
        self.assertIn("add_integrity_hashes", types)


if __name__ == "__main__":
    unittest.main()
