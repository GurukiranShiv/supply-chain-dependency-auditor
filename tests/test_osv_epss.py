import unittest
from unittest.mock import patch

from auditor.osv_check import _extract_cvss, _severity_from_cvss, check_osv
from auditor.epss import extract_cves, enrich_vulnerabilities_with_epss


class OsvEpssTests(unittest.TestCase):
    def test_cvss_severity_mapping(self):
        self.assertEqual(_severity_from_cvss(9.8), "CRITICAL")
        self.assertEqual(_severity_from_cvss(7.2), "HIGH")
        self.assertEqual(_severity_from_cvss(5.0), "MEDIUM")
        self.assertEqual(_severity_from_cvss(2.0), "LOW")
        self.assertEqual(_severity_from_cvss(None), "UNKNOWN")

    def test_extract_cvss_from_osv_record(self):
        severity, score = _extract_cvss({"severity": [{"type": "CVSS_V3", "score": "8.1"}]})
        self.assertEqual(severity, "HIGH")
        self.assertEqual(score, 8.1)

    def test_extract_cves_from_references(self):
        cves = extract_cves({"id": "GHSA-123", "references": ["https://x/CVE-2024-12345"]})
        self.assertEqual(cves, ["CVE-2024-12345"])

    def test_enrich_vulnerabilities_with_mocked_epss(self):
        vulns = [{"id": "CVE-2024-12345", "summary": "demo", "references": []}]
        with patch("auditor.epss.fetch_epss", return_value={"CVE-2024-12345": {"epss": 0.42, "percentile": 0.9, "date": "2026-01-01"}}):
            enriched = enrich_vulnerabilities_with_epss(vulns)
        self.assertEqual(enriched[0]["epss_probability"], 0.42)
        self.assertEqual(enriched[0]["epss_percentile"], 0.9)

    def test_check_osv_parses_fixed_versions(self):
        fake = {"vulns": [{"id": "CVE-2024-12345", "summary": "bad", "severity": [{"type": "CVSS_V3", "score": "9.8"}], "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}], "references": []}]}
        with patch("auditor.osv_check.fetch_json", return_value=fake), patch("auditor.osv_check.enrich_vulnerabilities_with_epss", side_effect=lambda x: x):
            result = check_osv("demo", "pip", "1.0.0")
        self.assertEqual(result["vuln_count"], 1)
        self.assertEqual(result["vulns"][0]["severity"], "CRITICAL")
        self.assertIn({"fixed": "2.0.0"}, result["vulns"][0]["affected_ranges"])


if __name__ == "__main__":
    unittest.main()
