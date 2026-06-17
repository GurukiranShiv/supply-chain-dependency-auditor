import unittest
from unittest import mock

from auditor import environment_scan
from auditor.environment_scan import scan_python_environment
from auditor.registry import get_metadata
from auditor.osv_check import check_osv


class MockedNetworkSubprocessTests(unittest.TestCase):
    @mock.patch("auditor.environment_scan.subprocess.run")
    def test_scan_python_environment_mocks_subprocess(self, run):
        run.return_value.stdout = '{"installed": [{"metadata": {"name": "requests", "version": "2.32.0"}, "requested": true}]}'
        run.return_value.stderr = ""
        run.return_value.returncode = 0
        packages, warnings = scan_python_environment("python")
        self.assertEqual(warnings, [])
        self.assertEqual(packages[0]["name"], "requests")
        self.assertEqual(packages[0]["source_type"], "environment-direct")

    @mock.patch("auditor.registry.fetch_json")
    def test_get_pypi_metadata_mocks_http(self, fetch_json):
        fetch_json.return_value = {
            "info": {"name": "demo", "version": "1.0.0", "license": "MIT", "classifiers": ["License :: OSI Approved :: MIT License"], "project_urls": {"Source": "https://github.com/a/b"}},
            "releases": {"1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}]},
        }
        meta = get_metadata("demo", "pip")
        self.assertTrue(meta["exists"])
        self.assertEqual(meta["latest_version"], "1.0.0")

    @mock.patch("auditor.osv_check.fetch_json")
    @mock.patch("auditor.osv_check.enrich_vulnerabilities_with_epss")
    def test_osv_check_mocks_http_and_epss(self, enrich, fetch_json):
        enrich.side_effect = lambda vulns: vulns
        fetch_json.return_value = {"vulns": [{"id": "GHSA-test", "summary": "demo", "affected": []}]}
        result = check_osv("demo", "pip", "1.0.0")
        self.assertEqual(result["vulns"][0]["id"], "GHSA-test")
        fetch_json.assert_called_once()

    @mock.patch("auditor.environment_scan._run_json")
    def test_npm_environment_scan_mocks_json_runner(self, run_json):
        run_json.return_value = ({"name": "root", "dependencies": {"left-pad": {"version": "1.3.0"}}}, None)
        with mock.patch("auditor.environment_scan.Path.exists", return_value=True):
            packages, warnings = environment_scan.scan_npm_environment(".")
        self.assertEqual(warnings, [])
        self.assertEqual(packages[0]["name"], "left-pad")


if __name__ == "__main__":
    unittest.main()
