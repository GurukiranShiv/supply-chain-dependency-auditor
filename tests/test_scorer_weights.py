import unittest

from auditor.scorer import score_package


class ScorerWeightTests(unittest.TestCase):
    def base(self):
        return {
            "typo": {"is_suspicious": False},
            "meta": {"name": "demo", "ecosystem": "pip", "exists": True, "latest_version": "1.0.0", "maintainers": ["a", "b"], "classifiers": ["x"], "version_count": 5, "weekly_downloads": 0, "monthly_downloads": 0},
            "scan": {"findings": []},
            "osv": {"vulns": []},
        }

    def test_typosquat_scores_critical(self):
        b = self.base()
        b["typo"] = {"is_suspicious": True, "distance": 1, "closest_match": "requests", "reason": "1 char away"}
        r = score_package(b["typo"], b["meta"], b["scan"], b["osv"], {}, {}, provenance_result={"flags": []})
        self.assertGreaterEqual(r.risk_score, 60)
        self.assertTrue(any(s["category"] == "Typosquatting" for s in r.signals))

    def test_integrity_mismatch_scores_critical(self):
        b = self.base()
        r = score_package(b["typo"], b["meta"], b["scan"], b["osv"], {}, {}, dependency_policy_result={"flags": ["Downloaded artifact SHA-256 does not match requirement hash"]})
        self.assertGreaterEqual(r.risk_score, 70)
        self.assertTrue(any(s["category"] == "Package integrity" for s in r.signals))

    def test_provenance_mismatch_scores_critical(self):
        b = self.base()
        r = score_package(b["typo"], b["meta"], b["scan"], b["osv"], {}, {}, provenance_result={"flags": ["npm tarball SHA-512 does not match registry integrity digest"]})
        self.assertGreaterEqual(r.risk_score, 70)
        self.assertTrue(any(s["category"] == "Artifact integrity" for s in r.signals))


if __name__ == "__main__":
    unittest.main()
