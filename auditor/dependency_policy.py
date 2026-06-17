"""Project dependency policy checks: pinning, lockfile use, and integrity hashes."""

from __future__ import annotations

import re
from typing import Optional


PINNED_EXACT_RE = re.compile(r"^[0-9]+(?:\.[0-9A-Za-z*+!_\-]+)*$")


def _is_exact_version(version: Optional[str], raw_spec: Optional[str], ecosystem: str) -> bool:
    value = str(version or "").strip()
    raw = str(raw_spec or "").strip()
    if value in {"", "unknown", "unpinned", "transitive"}:
        return False
    if ecosystem == "pip":
        return "==" in raw or PINNED_EXACT_RE.match(value) is not None
    if ecosystem == "npm":
        if raw.startswith(("^", "~", ">", "<", "*")) or raw in {"latest", "next"}:
            return False
        return PINNED_EXACT_RE.match(value) is not None
    return False


def _npm_sri_sha512_b64(integrity: Optional[str]) -> Optional[str]:
    if not integrity or not str(integrity).startswith("sha512-"):
        return None
    return str(integrity).split("sha512-", 1)[1].split("?", 1)[0].strip()


def check_dependency_policy(pkg: dict, scan_result: Optional[dict] = None) -> dict:
    """Return lock/pin/integrity findings for one dependency entry.

    Integrity verification is only marked True when the scanned artifact digest
    matches the digest recorded by the dependency file/registry. Presence of a
    hash alone is not treated as verification.
    """
    name = pkg.get("name", "unknown")
    ecosystem = pkg.get("ecosystem", "unknown")
    version = pkg.get("version")
    raw_spec = pkg.get("raw_spec") or version
    source_file = pkg.get("source_file") or "unknown"
    source_type = pkg.get("source_type") or "direct"
    is_lockfile = bool(pkg.get("is_lockfile"))
    integrity = pkg.get("integrity")
    hashes = pkg.get("hashes") or []
    scan_result = scan_result or {}

    result = {
        "ecosystem": ecosystem,
        "name": name,
        "source_file": source_file,
        "source_type": source_type,
        "is_lockfile": is_lockfile,
        "pinned": _is_exact_version(version, raw_spec, ecosystem),
        "has_integrity": bool(integrity or hashes),
        "integrity_verified": None,
        "flags": [],
    }

    # Registry/environment transitive deps are observations, not policy in the user's manifest.
    if source_type in {"transitive-registry", "environment", "environment-direct", "environment-transitive"}:
        return result

    if not result["pinned"]:
        result["flags"].append(
            f"Dependency is not pinned to an exact version in {source_file} (spec: {raw_spec or 'unknown'})"
        )

    if ecosystem == "npm":
        if not is_lockfile:
            result["flags"].append("No npm lockfile entry was used for this package; integrity cannot be verified")
        elif not integrity:
            result["flags"].append("npm lockfile entry does not include an integrity hash")
        else:
            expected_b64 = _npm_sri_sha512_b64(integrity)
            actual_b64 = scan_result.get("artifact_sha512_base64")
            if expected_b64 and actual_b64:
                result["integrity_verified"] = expected_b64 == actual_b64
                if result["integrity_verified"] is False:
                    result["flags"].append("Downloaded npm tarball SHA-512 does not match package-lock integrity hash")
            elif expected_b64:
                result["integrity_verified"] = None
            else:
                result["flags"].append("npm lockfile integrity algorithm is not SHA-512; verification skipped")
    elif ecosystem == "pip":
        if not hashes:
            result["flags"].append(
                "Python dependency has no --hash pin; use pip-compile --generate-hashes for tamper detection"
            )
        else:
            artifact_sha = (scan_result.get("artifact_sha256") or "").lower()
            expected = {h.split(":", 1)[1].lower() for h in hashes if str(h).startswith("sha256:")}
            if artifact_sha:
                result["integrity_verified"] = artifact_sha in expected
                if result["integrity_verified"] is False:
                    result["flags"].append("Downloaded artifact SHA-256 does not match requirement hash")
            else:
                result["integrity_verified"] = None

    return result
