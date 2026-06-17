"""OSV vulnerability checker with CVSS parsing and optional EPSS enrichment."""

from __future__ import annotations

from typing import Optional

from .epss import enrich_vulnerabilities_with_epss
from .http_client import fetch_json

OSV_API = "https://api.osv.dev/v1/query"


def _severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_cvss(vuln: dict) -> tuple[str, Optional[float]]:
    best_score: Optional[float] = None
    for sev in vuln.get("severity", []) or []:
        if not str(sev.get("type", "")).startswith("CVSS"):
            continue
        try:
            score = float(sev.get("score", 0))
        except (ValueError, TypeError):
            continue
        if best_score is None or score > best_score:
            best_score = score
    return _severity_from_cvss(best_score), best_score


def check_osv(package_name: str, ecosystem: str, version: Optional[str] = None) -> dict:
    ecosystem_map = {
        "npm": "npm",
        "pip": "PyPI",
        "maven": "Maven",
        "go": "Go",
        "nuget": "NuGet",
        "rubygems": "RubyGems",
        "docker": "Docker",
    }
    osv_ecosystem = ecosystem_map.get(ecosystem)
    result = {
        "package": package_name,
        "ecosystem": ecosystem,
        "version_checked": None,
        "vuln_count": 0,
        "vulns": [],
        "error": None,
    }
    if not osv_ecosystem:
        result["error"] = f"OSV ecosystem mapping is not implemented for {ecosystem}"
        return result
    payload = {"package": {"name": package_name, "ecosystem": osv_ecosystem}}
    if version and version not in {"unknown", "unpinned", "transitive"}:
        payload["version"] = version

    result["version_checked"] = payload.get("version")

    data = fetch_json(OSV_API, method="POST", payload=payload, timeout=12)
    if not data or data.get("__error__"):
        result["error"] = f"OSV API request failed: {data.get('__error__', 'unknown')}"
        return result

    vulns = data.get("vulns", []) or []
    parsed_vulns = []

    for vuln in vulns:
        severity, cvss_score = _extract_cvss(vuln)

        affected_ranges = []
        for affected in vuln.get("affected", []) or []:
            for rng in affected.get("ranges", []) or []:
                for evt in rng.get("events", []) or []:
                    if "introduced" in evt or "fixed" in evt:
                        affected_ranges.append(evt)

        parsed_vulns.append({
            "id": vuln.get("id"),
            "summary": str(vuln.get("summary", "No summary available"))[:240],
            "severity": severity,
            "cvss_score": cvss_score,
            "published": vuln.get("published"),
            "modified": vuln.get("modified"),
            "references": [r.get("url") for r in vuln.get("references", [])[:5] if r.get("url")],
            "affected_ranges": affected_ranges[:8],
        })

    parsed_vulns = enrich_vulnerabilities_with_epss(parsed_vulns)
    result["vuln_count"] = len(parsed_vulns)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    parsed_vulns.sort(
        key=lambda x: (
            severity_order.get(x.get("severity"), 4),
            -(x.get("epss_probability") or 0),
        )
    )
    result["vulns"] = parsed_vulns
    return result
