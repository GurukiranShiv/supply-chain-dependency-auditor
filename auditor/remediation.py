"""Generate actionable remediation suggestions from audit findings."""

from __future__ import annotations

import json
from typing import Any, Optional


def _fixed_versions_from_osv(osv_result: dict | None) -> list[str]:
    fixed: set[str] = set()
    for vuln in (osv_result or {}).get("vulns", []) or []:
        for event in vuln.get("affected_ranges", []) or []:
            value = event.get("fixed")
            if value and value != "0":
                fixed.add(str(value))
    return sorted(fixed)


def build_remediation(report: Any) -> dict:
    suggestions: list[dict] = []
    typo = getattr(report, "typosquat", None) or {}
    meta = getattr(report, "metadata", None) or {}
    policy = getattr(report, "dependency_policy", None) or {}
    osv = getattr(report, "vulns", None) or {}
    license_result = getattr(report, "license", None) or {}

    if typo.get("is_suspicious") and typo.get("closest_match"):
        suggestions.append({
            "type": "replace_typosquat",
            "priority": "critical",
            "summary": f"Replace suspicious package '{report.package}' with '{typo['closest_match']}' if that was the intended dependency.",
            "command": None,
            "safe_to_auto_apply": False,
        })

    fixed_versions = _fixed_versions_from_osv(osv)
    if fixed_versions:
        target = fixed_versions[-1]
        if report.ecosystem == "pip":
            command = f"python -m pip install --upgrade '{report.package}>={target}'"
        else:
            command = f"npm install {report.package}@{target}"
        suggestions.append({
            "type": "upgrade_vulnerable_dependency",
            "priority": "high",
            "summary": f"Upgrade {report.package} to a fixed version. OSV reports fixed version(s): {', '.join(fixed_versions)}.",
            "fixed_versions": fixed_versions,
            "command": command,
            "safe_to_auto_apply": False,
        })

    if policy and policy.get("pinned") is False:
        latest = meta.get("latest_version") or report.version
        if latest and latest not in {"unknown", "unpinned", "transitive"}:
            if report.ecosystem == "pip":
                line = f"{report.package}=={latest}"
            else:
                line = f'"{report.package}": "{latest}"'
            suggestions.append({
                "type": "pin_dependency",
                "priority": "medium",
                "summary": f"Pin {report.package} to an exact reviewed version.",
                "suggested_line": line,
                "safe_to_auto_apply": False,
            })

    if policy and policy.get("has_integrity") is False:
        if report.ecosystem == "pip":
            command = "pip-compile --generate-hashes requirements.in"
            summary = "Generate and commit pip hashes so artifact tampering can be detected."
        else:
            command = "npm install --package-lock-only"
            summary = "Regenerate and commit package-lock.json with integrity hashes."
        suggestions.append({
            "type": "add_integrity_hashes",
            "priority": "medium",
            "summary": summary,
            "command": command,
            "safe_to_auto_apply": False,
        })

    if license_result.get("status") == "DENY":
        suggestions.append({
            "type": "license_remediation",
            "priority": "high",
            "summary": f"Replace or obtain legal approval for {report.package}; license status is DENY.",
            "safe_to_auto_apply": False,
        })

    if not suggestions and report.risk_level in {"SAFE", "LOW"}:
        suggestions.append({
            "type": "monitor",
            "priority": "info",
            "summary": "No urgent fix required. Keep dependency pinned and continue monitoring OSV/registry metadata.",
            "safe_to_auto_apply": False,
        })

    return {"package": report.package, "ecosystem": report.ecosystem, "suggestions": suggestions}


def export_remediation_plan(reports: list[Any], path: str) -> None:
    data = {
        "schema": "supply-chain-auditor-remediation-v1",
        "items": [build_remediation(r) for r in reports],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
