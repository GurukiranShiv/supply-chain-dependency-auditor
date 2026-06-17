"""CI/CD hardening checks for GitHub Actions workflows."""

from __future__ import annotations

import json
import re
from pathlib import Path

SHA_RE = re.compile(r"^[a-fA-F0-9]{40}$")
USES_RE = re.compile(r"uses:\s*([^\s#]+)")
PERMISSIONS_RE = re.compile(r"^permissions:\s*$", re.MULTILINE)
DANGEROUS_PERMS_RE = re.compile(r"permissions:\s*(write-all|read-all)", re.IGNORECASE)


def _workflow_files(project_path: str) -> list[Path]:
    root = Path(project_path)
    wf = root / ".github" / "workflows"
    if not wf.exists():
        return []
    return sorted([p for p in wf.rglob("*") if p.suffix.lower() in {".yml", ".yaml"}])


def audit_github_actions(project_path: str) -> dict:
    result = {"project": project_path, "workflow_count": 0, "findings": [], "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
    for path in _workflow_files(project_path):
        result["workflow_count"] += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = str(path.relative_to(project_path)) if Path(project_path).exists() and path.is_relative_to(Path(project_path)) else str(path)
        if not PERMISSIONS_RE.search(text) and "permissions:" not in text:
            result["findings"].append({"severity": "MEDIUM", "file": rel, "category": "GitHub Actions permissions", "description": "Workflow does not declare least-privilege permissions"})
        if DANGEROUS_PERMS_RE.search(text):
            result["findings"].append({"severity": "HIGH", "file": rel, "category": "GitHub Actions permissions", "description": "Workflow uses broad token permissions"})
        for match in USES_RE.finditer(text):
            spec = match.group(1).strip().strip('"\'')
            if spec.startswith("./"):
                continue
            if "@" not in spec:
                result["findings"].append({"severity": "HIGH", "file": rel, "category": "Action pinning", "description": f"Action is not pinned: {spec}"})
                continue
            ref = spec.rsplit("@", 1)[1]
            if not SHA_RE.match(ref):
                result["findings"].append({"severity": "MEDIUM", "file": rel, "category": "Action pinning", "description": f"Action should be pinned to a full commit SHA: {spec}"})
        if "pull_request_target" in text:
            result["findings"].append({"severity": "HIGH", "file": rel, "category": "Pull request security", "description": "pull_request_target requires careful checkout/token isolation"})
    for finding in result["findings"]:
        key = finding["severity"].lower()
        result["summary"][key] = result["summary"].get(key, 0) + 1
    return result


def export_ci_hardening(result: dict, path: str) -> None:
    Path(path).write_text(json.dumps(result, indent=2), encoding="utf-8")
