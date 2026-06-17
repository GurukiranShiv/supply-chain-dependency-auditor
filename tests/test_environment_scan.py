import unittest
from unittest.mock import patch

from auditor.environment_scan import scan_python_environment, scan_npm_environment


class EnvironmentScanTests(unittest.TestCase):
    def test_pip_inspect_parses_requested_and_transitive(self):
        data = {"installed": [
            {"metadata": {"name": "requests", "version": "2.32.3"}, "requested": True},
            {"metadata": {"name": "urllib3", "version": "2.2.1"}, "requested": False},
        ]}
        with patch("auditor.environment_scan._run_json", return_value=(data, None)):
            pkgs, warnings = scan_python_environment("python")
        self.assertEqual(len(pkgs), 2)
        self.assertEqual(warnings, [])
        self.assertEqual(pkgs[0]["source_type"], "environment-direct")
        self.assertEqual(pkgs[1]["source_type"], "environment-transitive")

    def test_pip_list_fallback(self):
        responses = [(None, "pip inspect failed"), ([{"name": "flask", "version": "3.0.0"}], None)]
        with patch("auditor.environment_scan._run_json", side_effect=responses):
            pkgs, warnings = scan_python_environment("python")
        self.assertEqual(pkgs[0]["name"], "flask")
        self.assertEqual(warnings, [])

    def test_pip_environment_reports_warnings_only_if_all_sources_fail(self):
        responses = [(None, "pip inspect failed"), (None, "pip list failed")]
        with patch("auditor.environment_scan._run_json", side_effect=responses):
            pkgs, warnings = scan_python_environment("python")
        self.assertEqual(pkgs, [])
        self.assertEqual(warnings, ["pip inspect failed", "pip list failed"])

    def test_npm_ls_tree_parses_transitive(self):
        data = {"dependencies": {"express": {"version": "4.18.3", "dependencies": {"qs": {"version": "6.0.0"}}}}}
        with patch("auditor.environment_scan.Path.exists", return_value=True), patch("auditor.environment_scan._run_json", return_value=(data, None)):
            pkgs, warnings = scan_npm_environment(".")
        self.assertEqual(len(pkgs), 2)
        names = {p["name"] for p in pkgs}
        self.assertEqual(names, {"express", "qs"})
        self.assertEqual(warnings, [])


if __name__ == "__main__":
    unittest.main()
