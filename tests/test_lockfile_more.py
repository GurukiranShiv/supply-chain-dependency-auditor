import json
import tempfile
import unittest
from pathlib import Path

from auditor.lockfile import parse_package_json, parse_pyproject_toml, parse_pipfile_lock


class MoreLockfileTests(unittest.TestCase):
    def test_package_json_marks_dev_dependencies(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "package.json"
            path.write_text(json.dumps({"dependencies": {"express": "4.18.3"}, "devDependencies": {"jest": "^29.0.0"}}), encoding="utf-8")
            pkgs = parse_package_json(str(path))
        by_name = {p["name"]: p for p in pkgs}
        self.assertFalse(by_name["express"]["dev"])
        self.assertTrue(by_name["jest"]["dev"])
        self.assertFalse(by_name["jest"]["is_lockfile"])

    def test_pyproject_pep621_dependencies(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "pyproject.toml"
            path.write_text('[project]\ndependencies = ["requests==2.32.3", "flask>=3"]\n[project.optional-dependencies]\ndev = ["pytest"]\n', encoding="utf-8")
            pkgs = parse_pyproject_toml(str(path))
        names = {p["name"] for p in pkgs}
        self.assertIn("requests", names)
        self.assertIn("flask", names)
        self.assertIn("pytest", names)

    def test_pipfile_lock_hashes(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "Pipfile.lock"
            path.write_text(json.dumps({"default": {"requests": {"version": "==2.32.3", "hashes": ["sha256:" + "a" * 64]}}}), encoding="utf-8")
            pkgs = parse_pipfile_lock(str(path))
        self.assertEqual(pkgs[0]["version"], "2.32.3")
        self.assertEqual(len(pkgs[0]["hashes"]), 1)
        self.assertTrue(pkgs[0]["is_lockfile"])


if __name__ == "__main__":
    unittest.main()
