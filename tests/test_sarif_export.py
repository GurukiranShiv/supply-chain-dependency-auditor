import json
import tempfile
import unittest
from pathlib import Path

from auditor.sarif import export_sarif
from auditor.scorer import RiskReport


class SarifExportTests(unittest.TestCase):
    def test_exports_sarif_210_with_results(self):
        report = RiskReport("demo", "pip", "1.0", 85, "CRITICAL", "bad", signals=[{"severity": "CRITICAL", "category": "Typosquatting", "detail": "looks like requests"}], dependency_policy={"source_file": "requirements.txt"})
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "results.sarif"
            export_sarif([report], str(path))
            data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(len(data["runs"][0]["results"]), 1)
        self.assertEqual(data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "requirements.txt")


if __name__ == "__main__":
    unittest.main()
