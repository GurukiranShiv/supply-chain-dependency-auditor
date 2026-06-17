"""EPSS enrichment for CVE records.

EPSS is optional enrichment. If the public API is unavailable, the scanner keeps
running and leaves EPSS fields empty.
"""

from __future__ import annotations

import re
from typing import Iterable

from .http_client import fetch_json

EPSS_API = "https://api.first.org/data/v1/epss"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cves(vuln: dict) -> list[str]:
    values = [str(vuln.get("id", "")), str(vuln.get("summary", ""))]
    values.extend(str(ref) for ref in vuln.get("references", []) or [])
    found = []
    for value in values:
        found.extend(CVE_RE.findall(value))
    return sorted({cve.upper() for cve in found})


def fetch_epss(cves: Iterable[str]) -> dict[str, dict]:
    unique = sorted({str(cve).upper() for cve in cves if str(cve).strip()})
    if not unique:
        return {}

    # FIRST currently supports comma-separated CVE lists. Keep batches small.
    out: dict[str, dict] = {}
    for idx in range(0, len(unique), 50):
        batch = unique[idx: idx + 50]
        url = f"{EPSS_API}?cve={','.join(batch)}"
        data = fetch_json(url, timeout=10)
        if not data or data.get("__error__"):
            continue
        for item in data.get("data", []) or []:
            cve = str(item.get("cve", "")).upper()
            if not cve:
                continue
            try:
                epss = float(item.get("epss", 0))
            except (TypeError, ValueError):
                epss = None
            try:
                percentile = float(item.get("percentile", 0))
            except (TypeError, ValueError):
                percentile = None
            out[cve] = {"epss": epss, "percentile": percentile, "date": item.get("date")}
    return out


def enrich_vulnerabilities_with_epss(vulns: list[dict]) -> list[dict]:
    all_cves = []
    for vuln in vulns:
        cves = extract_cves(vuln)
        vuln["cves"] = cves
        all_cves.extend(cves)

    epss_map = fetch_epss(all_cves)
    for vuln in vulns:
        matches = [epss_map[cve] for cve in vuln.get("cves", []) if cve in epss_map]
        if not matches:
            vuln["epss_probability"] = None
            vuln["epss_percentile"] = None
            continue
        best = max(matches, key=lambda x: x.get("epss") or 0)
        vuln["epss_probability"] = best.get("epss")
        vuln["epss_percentile"] = best.get("percentile")
        vuln["epss_date"] = best.get("date")
    return vulns
