import json
import tempfile
import unittest
from pathlib import Path

from auditor.sbom import export_cyclonedx
from auditor.report_html import export_html
from auditor.scorer import RiskReport


class ExporterTests(unittest.TestCase):
    def test_cyclonedx_includes_risk_properties(self):
        report = RiskReport("demo", "pip", "1.0", 0, "SAFE", "ok", license={"normalized_license": "MIT", "status": "PASS"}, dependency_policy={"pinned": True, "has_integrity": True, "integrity_verified": True}, provenance={"artifact_integrity_verified": True, "provenance_attestation_present": False})
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sbom.json"
            export_cyclonedx([report], str(path))
            data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["bomFormat"], "CycloneDX")
        props = {p["name"]: p["value"] for p in data["components"][0]["properties"]}
        self.assertEqual(props["auditor:risk_level"], "SAFE")
        self.assertEqual(props["auditor:artifact_integrity_verified"], "True")

    def test_html_contains_fix_suggestions_section(self):
        report = RiskReport("demo", "pip", "1.0", 10, "LOW", "ok", signals=[], remediation={"suggestions": [{"priority": "info", "summary": "Monitor only"}]})
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "report.html"
            export_html([report], str(path))
            html = path.read_text(encoding="utf-8")
        self.assertIn("Fix suggestions", html)
        self.assertIn("Monitor only", html)


if __name__ == "__main__":
    unittest.main()
