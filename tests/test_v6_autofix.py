import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from argparse import Namespace

from auditor.autofix import apply_fixes, create_branch_commit_push, open_github_pr, plan_fixes
from auditor.cli import cmd_fix


class AutoFixTests(unittest.TestCase):
    def test_dry_run_plans_pip_pin_without_modifying_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            req = root / "requirements.txt"
            req.write_text("requests>=2\n", encoding="utf-8")
            plan = {"items": [{"package": "requests", "ecosystem": "pip", "suggestions": [{"type": "pin_dependency", "suggested_line": "requests==2.32.0", "summary": "pin"}]}]}
            ops = plan_fixes(root, plan)
            self.assertEqual(len(ops), 1)
            self.assertIn("requests>=2", req.read_text(encoding="utf-8"))

    def test_apply_fixes_rewrites_requirements(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            req = root / "requirements.txt"
            req.write_text("requests>=2\nflask==3.0.0\n", encoding="utf-8")
            plan = {"items": [{"package": "requests", "ecosystem": "pip", "suggestions": [{"type": "pin_dependency", "suggested_line": "requests==2.32.0", "summary": "pin"}]}]}
            ops = apply_fixes(root, plan)
            self.assertEqual(len(ops), 1)
            self.assertIn("requests==2.32.0", req.read_text(encoding="utf-8"))

    def test_apply_fixes_rewrites_package_json(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pkg = root / "package.json"
            pkg.write_text(json.dumps({"dependencies": {"lodash": "^4.17.0"}}), encoding="utf-8")
            plan = {"items": [{"package": "lodash", "ecosystem": "npm", "suggestions": [{"type": "upgrade_vulnerable_dependency", "fixed_versions": ["4.17.21"], "summary": "upgrade"}]}]}
            ops = apply_fixes(root, plan)
            self.assertEqual(len(ops), 1)
            data = json.loads(pkg.read_text(encoding="utf-8"))
            self.assertEqual(data["dependencies"]["lodash"], "4.17.21")

    def test_typosquat_replacement_requires_allow_unsafe(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            req = root / "requirements.txt"
            req.write_text("reques7s==1.0.0\n", encoding="utf-8")
            plan = {"items": [{"package": "reques7s", "ecosystem": "pip", "suggestions": [{"type": "replace_typosquat", "summary": "Replace suspicious package 'reques7s' with 'requests' if intended."}]}]}
            self.assertEqual(plan_fixes(root, plan), [])
            ops = apply_fixes(root, plan, allow_unsafe=True)
            self.assertEqual(len(ops), 1)
            self.assertIn("requests", req.read_text(encoding="utf-8"))

    def test_fix_missing_remediation_returns_clean_error(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            args = Namespace(
                path=str(root),
                remediation=str(root / "missing-remediation.json"),
                apply=False,
                allow_unsafe=False,
                create_branch=False,
                branch_name="scda/auto-remediation",
                commit_message="Apply supply chain dependency remediations",
                push=False,
                open_pr=False,
                remote="origin",
                pr_body=None,
                pr_title="Automated supply chain dependency remediation",
                base_branch="main",
                fix_report=None,
            )
            with mock.patch("builtins.print"):
                self.assertEqual(cmd_fix(args), 2)

    @mock.patch("auditor.autofix.subprocess.run")
    def test_git_branch_commit_push_uses_subprocess(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "ok"
        run.return_value.stderr = ""
        result = create_branch_commit_push(".", branch="fix/test", commit_message="fix", push=True)
        self.assertTrue(result["ok"])
        self.assertEqual(run.call_count, 4)

    @mock.patch("auditor.autofix.subprocess.run")
    def test_open_github_pr_uses_gh_cli(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "https://github.com/org/repo/pull/1"
        run.return_value.stderr = ""
        result = open_github_pr(".", title="fix", body="body", base="main", head="fix/test")
        self.assertTrue(result["ok"])
        self.assertEqual(run.call_args[0][0][0], "gh")


if __name__ == "__main__":
    unittest.main()
