"""CycloneDX SBOM export with supply-chain risk properties."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .version import __version__


def export_cyclonedx(reports: list[Any], path: str) -> None:
    components = []
    for r in reports:
        purl_type = "npm" if r.ecosystem == "npm" else "pypi"
        purl = f"pkg:{purl_type}/{r.package}" + (f"@{r.version}" if r.version else "")
        license_info = getattr(r, "license", None) or {}
        policy = getattr(r, "dependency_policy", None) or {}
        properties = [
            {"name": "auditor:risk_score", "value": str(r.risk_score)},
            {"name": "auditor:risk_level", "value": r.risk_level},
            {"name": "auditor:recommendation", "value": r.recommendation},
        ]
        if license_info:
            properties.append({"name": "auditor:license_status", "value": str(license_info.get("status"))})
            properties.append({"name": "auditor:license", "value": str(license_info.get("license"))})
        if policy:
            properties.append({"name": "auditor:pinned", "value": str(policy.get("pinned"))})
            properties.append({"name": "auditor:has_integrity", "value": str(policy.get("has_integrity"))})
            properties.append({"name": "auditor:integrity_verified", "value": str(policy.get("integrity_verified"))})
        provenance = getattr(r, "provenance", None) or {}
        if provenance:
            properties.append({"name": "auditor:artifact_integrity_verified", "value": str(provenance.get("artifact_integrity_verified"))})
            properties.append({"name": "auditor:provenance_attestation_present", "value": str(provenance.get("provenance_attestation_present"))})

        component = {
            "type": "library",
            "name": r.package,
            "version": r.version or "unknown",
            "purl": purl,
            "properties": properties,
        }
        if license_info.get("normalized_license") and license_info.get("normalized_license") != "UNKNOWN":
            component["licenses"] = [{"license": {"id": license_info["normalized_license"]}}]
        components.append(component)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "portfolio", "name": "supply-chain-dependency-auditor", "version": __version__}],
        },
        "components": components,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bom, f, indent=2)
