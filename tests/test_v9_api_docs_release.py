import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from auditor.api_server import _safe_target, _build_audit_command, openapi_schema, run_audit_for_api
from auditor.version import __version__


class V9ApiDocsReleaseTests(unittest.TestCase):
    def test_openapi_schema_exposes_audit_and_webhook_paths(self):
        schema = openapi_schema()
        self.assertEqual(schema["info"]["version"], __version__)
        self.assertIn("/audit", schema["paths"])
        self.assertIn("/webhook/github", schema["paths"])

    def test_safe_target_blocks_path_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(_safe_target(root, "."), root.resolve())
            with self.assertRaises(ValueError):
                _safe_target(root, "../outside")

    def test_build_audit_command_includes_enterprise_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            cmd = _build_audit_command(Path(tmp), Path(tmp), {"no_scan": True, "no_malware": True, "resolver": "exact", "policy": "data/security_policy.example.json"})
            joined = " ".join(cmd)
            self.assertIn("auditor.cli", joined)
            self.assertIn("--json", cmd)
            self.assertIn("--sbom", cmd)
            self.assertIn("--sarif", cmd)
            self.assertIn("--policy", cmd)
            self.assertIn("--ci-hardening-report", cmd)

    @patch("auditor.api_server.subprocess.run")
    def test_run_audit_for_api_returns_summary_from_results(self, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "proj").mkdir()
            def fake_run(cmd, text, capture_output, timeout, env=None, encoding=None, errors=None):
                self.assertEqual(env.get("PYTHONIOENCODING"), "utf-8")
                self.assertEqual(env.get("PYTHONUTF8"), "1")
                self.assertEqual(encoding, "utf-8")
                self.assertEqual(errors, "replace")
                outdir = Path(cmd[cmd.index("--json") + 1]).parent
                (outdir / "results.json").write_text(json.dumps([
                    {"package": "reques7s", "risk_level": "CRITICAL"},
                    {"package": "requests", "risk_level": "SAFE"},
                ]), encoding="utf-8")
                return Mock(returncode=1, stdout="audit output", stderr="")
            mock_run.side_effect = fake_run
            result = run_audit_for_api(root, {"path": "proj", "no_scan": True}, timeout=5)
            self.assertTrue(result["ok"])
            self.assertEqual(result["summary"]["total"], 2)
            self.assertEqual(result["summary"]["critical"], 1)

    @patch("auditor.api_server.subprocess.run")
    def test_run_audit_for_api_marks_traceback_without_results_as_not_ok(self, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "proj").mkdir()
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="UnicodeEncodeError traceback")
            result = run_audit_for_api(root, {"path": "proj", "no_scan": True}, timeout=5)
            self.assertFalse(result["ok"])
            self.assertEqual(result["summary"]["total"], 0)
            self.assertIn("UnicodeEncodeError", result["stderr_tail"])

    def test_release_and_docs_files_exist(self):
        self.assertTrue(Path("mkdocs.yml").exists())
        self.assertTrue(Path("docs/api.md").exists())
        self.assertTrue(Path("RELEASE.md").exists())
        self.assertTrue(Path(".github/workflows/publish-pypi.yml").exists())


if __name__ == "__main__":
    unittest.main()
