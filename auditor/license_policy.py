"""License compliance checks for dependency metadata."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Optional

DEFAULT_DENY = {
    "AGPL",
    "AGPL-3.0",
    "AGPL-3.0-ONLY",
    "AGPL-3.0-OR-LATER",
    "SSPL",
    "SSPL-1.0",
}

DEFAULT_REVIEW = {
    "GPL",
    "GPL-2.0",
    "GPL-2.0-ONLY",
    "GPL-2.0-OR-LATER",
    "GPL-3.0",
    "GPL-3.0-ONLY",
    "GPL-3.0-OR-LATER",
    "LGPL",
    "LGPL-2.1",
    "LGPL-3.0",
    "UNKNOWN",
}

PERMISSIVE_HINTS = {
    "MIT",
    "APACHE",
    "APACHE-2.0",
    "BSD",
    "BSD-2-CLAUSE",
    "BSD-3-CLAUSE",
    "ISC",
    "MPL-2.0",
    "PYTHON-2.0",
}


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _policy_path(path: Optional[str] = None) -> Path:
    return Path(path or os.getenv("AUDITOR_LICENSE_POLICY", "") or _project_root() / "data" / "license_policy.json")


def _load_policy(path: Optional[str] = None) -> dict:
    default = {
        "deny": sorted(DEFAULT_DENY),
        "review": sorted(DEFAULT_REVIEW),
        "allow_unknown": True,
    }
    chosen = _policy_path(path)
    if not chosen.exists():
        return default
    try:
        data = json.loads(chosen.read_text(encoding="utf-8"))
    except Exception:
        return default
    return {
        "deny": data.get("deny", default["deny"]),
        "review": data.get("review", default["review"]),
        "allow_unknown": bool(data.get("allow_unknown", default["allow_unknown"])),
    }


def _normalize_license(value: Optional[str]) -> str:
    if not value:
        return "UNKNOWN"
    text = str(value).strip()
    if not text:
        return "UNKNOWN"
    # Normalize common separators while keeping SPDX identifiers readable.
    text = text.replace("License :: OSI Approved :: ", "")
    text = re.sub(r"\s+", " ", text)
    upper = text.upper()
    if "APACHE" in upper:
        return "APACHE-2.0" if "2" in upper else "APACHE"
    if "MIT" in upper:
        return "MIT"
    if "BSD" in upper:
        if "3" in upper:
            return "BSD-3-CLAUSE"
        if "2" in upper:
            return "BSD-2-CLAUSE"
        return "BSD"
    if "AGPL" in upper:
        return "AGPL-3.0" if "3" in upper else "AGPL"
    if "LGPL" in upper:
        return "LGPL-3.0" if "3" in upper else "LGPL"
    if "GPL" in upper:
        return "GPL-3.0" if "3" in upper else "GPL"
    if "SSPL" in upper:
        return "SSPL-1.0"
    if "ISC" in upper:
        return "ISC"
    if "MPL" in upper:
        return "MPL-2.0"
    return upper


def _license_from_classifiers(classifiers: list[str]) -> Optional[str]:
    for classifier in classifiers or []:
        if "License ::" in classifier:
            return classifier.split("::")[-1].strip()
    return None


def check_license_compliance(package_name: str, ecosystem: str, metadata: dict, policy_path: Optional[str] = None) -> dict:
    policy = _load_policy(policy_path)
    raw_license = metadata.get("license") or metadata.get("license_expression") or _license_from_classifiers(metadata.get("classifiers", []))
    normalized = _normalize_license(raw_license)

    deny = {_normalize_license(x) for x in policy.get("deny", [])}
    review = {_normalize_license(x) for x in policy.get("review", [])}

    result = {
        "ecosystem": ecosystem,
        "name": package_name,
        "license": raw_license or "UNKNOWN",
        "normalized_license": normalized,
        "policy": {
            "deny": sorted(deny),
            "review": sorted(review),
            "allow_unknown": bool(policy.get("allow_unknown", True)),
        },
        "status": "PASS",
        "flags": [],
    }

    if normalized in deny:
        result["status"] = "DENY"
        result["flags"].append(f"License '{raw_license or 'UNKNOWN'}' is denied by policy")
    elif normalized in review:
        if normalized == "UNKNOWN" and policy.get("allow_unknown", True):
            result["status"] = "UNKNOWN"
            result["flags"].append("Package license is unknown; review before production approval")
        else:
            result["status"] = "REVIEW"
            result["flags"].append(f"License '{raw_license or 'UNKNOWN'}' requires legal/security review")
    elif normalized in PERMISSIVE_HINTS or normalized not in {"UNKNOWN"}:
        result["status"] = "PASS"
    else:
        result["status"] = "UNKNOWN"
        result["flags"].append("Package license could not be confidently classified")

    return result
