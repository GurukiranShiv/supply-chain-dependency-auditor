"""SARIF 2.1.0 exporter for GitHub Code Scanning and enterprise SIEM ingestion."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .version import __version__

SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
    "SAFE": "none",
}


def _rule_id(signal: dict) -> str:
    category = str(signal.get("category", "signal")).lower().replace(" ", "-")
    severity = str(signal.get("severity", "INFO")).lower()
    return f"SCDA-{severity}-{category}"[:80]


def export_sarif(reports: list[Any], path: str) -> None:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for report in reports:
        for signal in report.signals or []:
            rid = _rule_id(signal)
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "name": signal.get("category", "Supply-chain signal"),
                    "shortDescription": {"text": signal.get("category", "Supply-chain signal")},
                    "fullDescription": {"text": f"{signal.get('category', 'Signal')} reported by Supply Chain Dependency Auditor."},
                    "defaultConfiguration": {"level": SEVERITY_TO_LEVEL.get(signal.get("severity"), "warning")},
                    "properties": {"security-severity": str({"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0}.get(signal.get("severity"), 1.0))},
                }

            source_file = "dependency-manifest"
            policy = getattr(report, "dependency_policy", None) or {}
            if policy.get("source_file"):
                source_file = policy["source_file"]
            message = f"{report.package} ({report.ecosystem}) risk {report.risk_level} {report.risk_score}/100: {signal.get('detail', '')}"
            results.append({
                "ruleId": rid,
                "level": SEVERITY_TO_LEVEL.get(signal.get("severity"), "warning"),
                "message": {"text": message[:1800]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": source_file},
                        "region": {"startLine": int(signal.get("line") or 1)},
                    }
                }],
                "properties": {
                    "package": report.package,
                    "ecosystem": report.ecosystem,
                    "riskScore": report.risk_score,
                    "riskLevel": report.risk_level,
                },
            })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Supply Chain Dependency Auditor",
                    "informationUri": "https://github.com/",
                    "version": __version__,
                    "rules": list(rules.values()),
                }
            },
            "invocations": [{"executionSuccessful": True, "endTimeUtc": datetime.now(timezone.utc).isoformat()}],
            "results": results,
        }],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
