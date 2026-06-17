import unittest
from auditor.policy_engine import evaluate_policy, load_policy
from auditor.scorer import RiskReport


class PolicyEngineTests(unittest.TestCase):
    def _report(self, package="demo", score=0, level="SAFE", license_status="PASS", source_type="direct"):
        return RiskReport(
            package=package,
            ecosystem="pip",
            version="1.0.0",
            risk_score=score,
            risk_level=level,
            recommendation="test",
            signals=[{"severity": "LOW", "category": "Dependency pinning", "detail": "not pinned"}] if source_type == "direct" else [],
            license={"status": license_status},
            dependency_policy={"source_type": source_type},
        )

    def test_default_policy_blocks_critical_risk(self):
        result = evaluate_policy([self._report(score=90, level="CRITICAL")], load_policy(None))
        self.assertEqual(result["summary"]["block"], 1)
        self.assertEqual(result["decisions"][0]["action"], "block")

    def test_allowlist_prevents_risk_rule_block(self):
        policy = load_policy(None)
        policy["allowlist"] = [{"package": "demo", "ecosystem": "pip"}]
        result = evaluate_policy([self._report(score=90, level="CRITICAL")], policy)
        self.assertEqual(result["decisions"][0]["action"], "allow")

    def test_blocklist_overrides_safe_score(self):
        policy = {"default_action": "allow", "allowlist": [], "blocklist": ["demo"], "rules": []}
        result = evaluate_policy([self._report(score=0)], policy)
        self.assertEqual(result["decisions"][0]["action"], "block")

    def test_warn_on_denied_license_can_be_block(self):
        policy = {
            "default_action": "allow",
            "allowlist": [],
            "blocklist": [],
            "rules": [{"id": "license", "when": {"license_status_in": ["DENY"]}, "action": "block"}],
        }
        result = evaluate_policy([self._report(license_status="DENY")], policy)
        self.assertEqual(result["summary"]["block"], 1)

    def test_policy_decision_attached_to_report(self):
        report = self._report(score=90, level="CRITICAL")
        evaluate_policy([report], load_policy(None))
        self.assertEqual(report.policy_decision["action"], "block")


if __name__ == "__main__":
    unittest.main()
