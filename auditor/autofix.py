"""Auto-fix and auto-PR helpers.

The module applies only conservative, dependency-manifest edits by default.
Potentially dangerous changes such as replacing a typosquatted package name are
kept behind --allow-unsafe because the scanner cannot know intent.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass
class FixOperation:
    file: str
    package: str
    ecosystem: str
    action: str
    before: str | None
    after: str | None
    safe: bool
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


def load_remediation_plan(path: str | os.PathLike[str]) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _items(plan: dict) -> list[dict]:
    return list(plan.get("items", []) or [])


def _best_suggestion(item: dict, *, allow_unsafe: bool) -> dict | None:
    preferred = ["upgrade_vulnerable_dependency", "pin_dependency", "replace_typosquat"]
    suggestions = list(item.get("suggestions", []) or [])
    suggestions.sort(key=lambda s: preferred.index(s.get("type")) if s.get("type") in preferred else 99)
    for suggestion in suggestions:
        typ = suggestion.get("type")
        if typ in {"upgrade_vulnerable_dependency", "pin_dependency"}:
            return suggestion
        if typ == "replace_typosquat" and allow_unsafe:
            return suggestion
    return None


def _target_version(suggestion: dict) -> str | None:
    if suggestion.get("type") == "upgrade_vulnerable_dependency":
        fixed = suggestion.get("fixed_versions") or []
        return str(fixed[-1]) if fixed else None
    if suggestion.get("type") == "pin_dependency":
        line = suggestion.get("suggested_line") or ""
        if "==" in line:
            return line.split("==", 1)[1].strip()
        match = re.search(r'"[^\"]+"\s*:\s*"([^\"]+)"', line)
        if match:
            return match.group(1).strip()
    return None


def _replacement_package(item: dict, suggestion: dict) -> str | None:
    summary = suggestion.get("summary", "")
    match = re.search(r"with '([^']+)'", summary)
    if match:
        return match.group(1)
    return None


def _iter_requirement_files(project: Path) -> list[Path]:
    if project.is_file() and project.name.startswith("requirements") and project.suffix == ".txt":
        return [project]
    return sorted(project.glob("requirements*.txt"))


def _requirement_line_matches(line: str, package: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("-"):
        return False
    name_match = re.match(r"([A-Za-z0-9_.\-]+)", stripped)
    return bool(name_match and name_match.group(1).lower().replace("_", "-") == package.lower().replace("_", "-"))


def _rewrite_requirements(path: Path, item: dict, suggestion: dict, *, apply: bool) -> list[FixOperation]:
    package = str(item.get("package", ""))
    version = _target_version(suggestion)
    replacement = _replacement_package(item, suggestion) if suggestion.get("type") == "replace_typosquat" else None
    if not package or (not version and not replacement):
        return []

    original = path.read_text(encoding="utf-8").splitlines()
    changed = False
    new_lines: list[str] = []
    ops: list[FixOperation] = []
    for line in original:
        if _requirement_line_matches(line, package):
            if replacement:
                new_line = f"{replacement}=={version}" if version else replacement
                action = "replace_typosquat"
                safe = False
            else:
                new_line = f"{package}=={version}"
                action = suggestion.get("type", "pin_dependency")
                safe = True
            if line != new_line:
                changed = True
                ops.append(FixOperation(str(path), package, "pip", action, line, new_line, safe, suggestion.get("summary", "")))
            new_lines.append(new_line)
        else:
            new_lines.append(line)
    if changed and apply:
        path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    return ops


def _rewrite_package_json(path: Path, item: dict, suggestion: dict, *, apply: bool) -> list[FixOperation]:
    package = str(item.get("package", ""))
    version = _target_version(suggestion)
    replacement = _replacement_package(item, suggestion) if suggestion.get("type") == "replace_typosquat" else None
    if not package or (not version and not replacement):
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    changed = False
    ops: list[FixOperation] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict) or package not in deps:
            continue
        before = f'{section}.{package}={deps[package]}'
        if replacement:
            after_value = version or deps.get(package, "latest")
            deps.pop(package)
            deps[replacement] = after_value
            after = f'{section}.{replacement}={after_value}'
            action = "replace_typosquat"
            safe = False
        else:
            after_value = str(version)
            deps[package] = after_value
            after = f'{section}.{package}={after_value}'
            action = suggestion.get("type", "pin_dependency")
            safe = True
        changed = True
        ops.append(FixOperation(str(path), package, "npm", action, before, after, safe, suggestion.get("summary", "")))
    if changed and apply:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return ops


def plan_fixes(project_path: str | os.PathLike[str], remediation_plan: dict, *, allow_unsafe: bool = False) -> list[FixOperation]:
    project = Path(project_path)
    operations: list[FixOperation] = []
    for item in _items(remediation_plan):
        suggestion = _best_suggestion(item, allow_unsafe=allow_unsafe)
        if not suggestion:
            continue
        ecosystem = item.get("ecosystem")
        if ecosystem == "pip":
            for req_file in _iter_requirement_files(project):
                operations.extend(_rewrite_requirements(req_file, item, suggestion, apply=False))
        elif ecosystem == "npm":
            package_json = project if project.is_file() and project.name == "package.json" else project / "package.json"
            if package_json.exists():
                operations.extend(_rewrite_package_json(package_json, item, suggestion, apply=False))
    return operations


def apply_fixes(project_path: str | os.PathLike[str], remediation_plan: dict, *, allow_unsafe: bool = False) -> list[FixOperation]:
    project = Path(project_path)
    operations: list[FixOperation] = []
    for item in _items(remediation_plan):
        suggestion = _best_suggestion(item, allow_unsafe=allow_unsafe)
        if not suggestion:
            continue
        ecosystem = item.get("ecosystem")
        if ecosystem == "pip":
            for req_file in _iter_requirement_files(project):
                operations.extend(_rewrite_requirements(req_file, item, suggestion, apply=True))
        elif ecosystem == "npm":
            package_json = project if project.is_file() and project.name == "package.json" else project / "package.json"
            if package_json.exists():
                operations.extend(_rewrite_package_json(package_json, item, suggestion, apply=True))
    return operations


def run_command(command: list[str], *, cwd: str | os.PathLike[str]) -> tuple[bool, str]:
    try:
        proc = subprocess.run(command, cwd=str(cwd), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except FileNotFoundError:
        return False, f"Command not found: {command[0]}"
    except Exception as exc:
        return False, str(exc)
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, output.strip()


def create_branch_commit_push(
    project_path: str | os.PathLike[str],
    *,
    branch: str,
    commit_message: str,
    push: bool = False,
    remote: str = "origin",
) -> dict:
    project = Path(project_path)
    steps: list[dict] = []
    commands = [
        ["git", "checkout", "-B", branch],
        ["git", "add", "."],
        ["git", "commit", "-m", commit_message],
    ]
    if push:
        commands.append(["git", "push", "-u", remote, branch])
    ok_all = True
    for command in commands:
        ok, output = run_command(command, cwd=project)
        steps.append({"command": command, "ok": ok, "output": output})
        # `git commit` exits non-zero if there is nothing to commit; that should be visible.
        if not ok:
            ok_all = False
            break
    return {"ok": ok_all, "steps": steps}


def open_github_pr(
    project_path: str | os.PathLike[str],
    *,
    title: str,
    body: str,
    base: str = "main",
    head: str | None = None,
) -> dict:
    command = ["gh", "pr", "create", "--title", title, "--body", body, "--base", base]
    if head:
        command.extend(["--head", head])
    ok, output = run_command(command, cwd=project_path)
    return {"ok": ok, "command": command, "output": output}


def export_fix_result(operations: list[FixOperation], path: str | os.PathLike[str], extra: dict | None = None) -> None:
    data = {
        "schema": "supply-chain-auditor-fix-result-v1",
        "operations": [op.to_dict() for op in operations],
    }
    if extra:
        data.update(extra)
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def validate_project_after_fix(project_path: str | os.PathLike[str]) -> dict:
    """Run lightweight installability checks after auto-fix changes.

    This avoids opening a remediation PR that cannot even resolve/install.
    Checks are best-effort and dependency-free.
    """
    project = Path(project_path)
    checks: list[dict] = []

    req_files = _iter_requirement_files(project)
    for req_file in req_files[:3]:
        ok, output = run_command(["python", "-m", "pip", "install", "--dry-run", "-r", str(req_file)], cwd=project)
        checks.append({"name": f"pip install --dry-run -r {req_file.name}", "ok": ok, "output": output[:3000]})

    if req_files:
        ok, output = run_command(["python", "-m", "pip", "check"], cwd=project)
        checks.append({"name": "pip check", "ok": ok, "output": output[:3000]})

    package_json = project / "package.json"
    if package_json.exists():
        ok, output = run_command(["npm", "install", "--package-lock-only", "--ignore-scripts"], cwd=project)
        checks.append({"name": "npm install --package-lock-only --ignore-scripts", "ok": ok, "output": output[:3000]})

    return {"ok": all(c.get("ok") for c in checks) if checks else True, "checks": checks}
