import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from auditor.lockfile import detect_and_parse
from auditor.registry import get_metadata
from auditor.resolver import resolve_pip_exact
from auditor.sandbox import sandbox_package
from auditor.ci_hardening import audit_github_actions
from auditor.enterprise_governance import build_sla_report, create_evidence_bundle
from auditor.scorer import score_package


class V8EnterpriseGapTests(unittest.TestCase):
    def test_multiecosystem_go_mod_and_pom_parsing(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            go = root / "go.mod"
            go.write_text('module example\nrequire (\n github.com/gin-gonic/gin v1.9.1\n)\n', encoding="utf-8")
            pom = root / "pom.xml"
            pom.write_text('<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.14.0</version></dependency></dependencies></project>', encoding="utf-8")
            self.assertEqual(detect_and_parse(str(go))[0]["ecosystem"], "go")
            self.assertEqual(detect_and_parse(str(pom))[0]["name"], "org.apache.commons:commons-lang3")

    def test_dockerfile_and_github_actions_parsing(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            dockerfile = root / "Dockerfile"
            dockerfile.write_text("FROM python:3.12-slim\n", encoding="utf-8")
            wfdir = root / ".github" / "workflows"
            wfdir.mkdir(parents=True)
            wf = wfdir / "ci.yml"
            wf.write_text("steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8")
            self.assertEqual(detect_and_parse(str(dockerfile))[0]["ecosystem"], "docker")
            self.assertEqual(detect_and_parse(str(wf))[0]["ecosystem"], "github-actions")

    def test_generic_metadata_for_container_flags_unpinned_digest(self):
        meta = get_metadata("python:3.12-slim", "docker")
        self.assertEqual(meta["ecosystem"], "docker")
        self.assertTrue(any("digest" in f.lower() for f in meta["flags"]))

    def test_exact_pip_resolver_parses_report(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")
            def fake_run(cmd, **kwargs):
                report_path = cmd[cmd.index("--report") + 1]
                Path(report_path).write_text(json.dumps({"install": [{"metadata": {"name": "requests", "version": "2.32.5"}}]}), encoding="utf-8")
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            packages, warnings = resolve_pip_exact(str(root), runner=fake_run)
            self.assertFalse(warnings)
            self.assertEqual(packages[0]["name"], "requests")
            self.assertEqual(packages[0]["source_type"], "exact-resolver")

    def test_sandbox_skips_cleanly_when_docker_missing(self):
        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="no docker")
        result = sandbox_package("requests", "pip", runner=fake_run)
        self.assertFalse(result["executed"])
        self.assertTrue(result["warnings"])

    def test_ci_hardening_flags_unpinned_action_and_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            wfdir = root / ".github" / "workflows"
            wfdir.mkdir(parents=True)
            (wfdir / "ci.yml").write_text("name: ci\nsteps:\n  - uses: actions/checkout@v4\n", encoding="utf-8")
            result = audit_github_actions(str(root))
            self.assertGreaterEqual(result["workflow_count"], 1)
            self.assertTrue(any("pinned" in f["description"] for f in result["findings"]))

    def test_governance_sla_and_evidence_bundle(self):
        report = score_package(
            {"is_suspicious": True, "distance": 1, "reason": "typo", "closest_match": "requests"},
            {"name": "reques7s", "ecosystem": "pip", "exists": True, "flags": [], "latest_version": "1.0", "monthly_downloads": 0},
            {"findings": []},
            {"vulns": []},
        )
        sla = build_sla_report([report], {"reques7s": {"owner": "appsec", "team": "security"}})
        self.assertEqual(sla["items"][0]["owner"], "appsec")
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "bundle.json"
            bundle = create_evidence_bundle(reports=[report], path=str(out))
            self.assertTrue(out.exists())
            self.assertIn("NIST_SSDF", bundle["control_mapping"])

    def test_false_positive_guardrail_caps_reputable_low_confidence_malware(self):
        report = score_package(
            {"is_suspicious": False},
            {"name": "chardet", "ecosystem": "pip", "exists": True, "flags": [], "latest_version": "5.0", "monthly_downloads": 500000, "repository": "https://github.com/chardet/chardet"},
            {"findings": []},
            {"vulns": []},
            malware_result={"findings": [{"category": "Malware behavior", "description": "subprocess usage", "severity": "HIGH", "confidence": "LOW", "scoreable": True}]},
        )
        self.assertLess(report.risk_score, 15)
        self.assertEqual(report.risk_level, "SAFE")


if __name__ == "__main__":
    unittest.main()

class V81PolishTests(unittest.TestCase):
    def test_github_actions_artifact_scan_skips_without_error(self):
        from auditor.scanner import scan_package
        result = scan_package("actions/checkout", "github-actions")
        self.assertIsNone(result.get("error"))
        self.assertTrue(result.get("skipped"))
        self.assertEqual(result["findings"], [])

    def test_malware_scan_skips_non_artifact_ecosystem(self):
        from auditor.malware_analysis import scan_malware
        result = scan_malware("actions/checkout", "github-actions")
        self.assertIsNone(result.get("error"))
        self.assertTrue(result.get("skipped"))
        self.assertEqual(result["findings"], [])

    def test_pyproject_console_script_metadata_is_not_install_behavior(self):
        from auditor.scanner import _scan_python_metadata_file
        content = '''
[project.scripts]
chardetect = "chardet.cli.chardetect:main"
[tool.hatch.envs.default.scripts]
compare = "python scripts/compare_detectors.py"
'''
        findings = _scan_python_metadata_file(content, "pyproject.toml")
        self.assertEqual(findings, [])

    def test_html_report_can_embed_ci_hardening_section(self):
        from pathlib import Path
        import tempfile
        from auditor.report_html import export_html
        from auditor.scorer import RiskReport
        report = RiskReport("demo", "pip", "1.0.0", 0, "SAFE", "ok")
        ci_result = {"summary": {"workflows_scanned": 1, "high": 1}, "findings": [{"severity": "HIGH", "workflow": "ci.yml", "rule": "Unpinned action", "detail": "Use a commit SHA"}]}
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.html"
            export_html([report], str(out), ci_result=ci_result)
            text = out.read_text(encoding="utf-8")
        self.assertIn("CI/CD Hardening", text)
        self.assertIn("Unpinned action", text)
