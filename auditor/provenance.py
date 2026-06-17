"""Artifact integrity, Sigstore, and SLSA provenance checks.

V7 keeps registry digest verification from earlier versions and adds optional
identity-bound verification paths:
- Sigstore CLI verification when a provenance policy provides issuer/identity.
- Local SLSA/in-toto attestation validation against expected builder/source.

The module never invents trusted identities. Teams must define identity/issuer
policy in JSON for real organizational verification.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from pathlib import Path
from typing import Optional

from .http_client import fetch_bytes, fetch_json


DEFAULT_PROVENANCE_POLICY = {
    "schema": "supply-chain-auditor-provenance-policy-v1",
    "require_registry_digest": True,
    "sigstore": {
        "enabled": False,
        "required": False,
        "cert_identity_regex": None,
        "cert_oidc_issuer": None,
    },
    "slsa": {
        "required": False,
        "attestation_file": None,
        "expected_builder_id": None,
        "expected_source_repository": None,
        "min_predicate_version": "1.0",
    },
}


def _npm_package_url(name: str) -> str:
    if name.startswith("@"):
        return "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="")
    return "https://registry.npmjs.org/" + urllib.parse.quote(name)


def _sri_sha512_b64(integrity: str | None) -> Optional[str]:
    if not integrity or not str(integrity).startswith("sha512-"):
        return None
    return str(integrity).split("sha512-", 1)[1].split("?", 1)[0].strip()


def _registry_npm_dist(package_name: str, version: str | None) -> dict:
    data = fetch_json(_npm_package_url(package_name), timeout=12)
    if not data or data.get("__error__"):
        return {"error": data.get("__error__", "registry unavailable") if isinstance(data, dict) else "registry unavailable"}
    latest = version or (data.get("dist-tags", {}) or {}).get("latest")
    versions = data.get("versions", {}) or {}
    if latest in {None, "unknown", "unpinned", "transitive"}:
        latest = (data.get("dist-tags", {}) or {}).get("latest")
    info = versions.get(str(latest), {}) if latest else {}
    return info.get("dist", {}) or {}


def _registry_pypi_files(package_name: str, version: str | None) -> list[dict]:
    data = fetch_json(f"https://pypi.org/pypi/{urllib.parse.quote(package_name)}/json", timeout=12)
    if not data or data.get("__error__"):
        return []
    selected = version if version not in {None, "unknown", "unpinned", "transitive"} else (data.get("info", {}) or {}).get("version")
    return (data.get("releases", {}) or {}).get(str(selected), []) or data.get("urls", []) or []


def load_provenance_policy(path: str | os.PathLike[str] | None = None) -> dict:
    if not path:
        return DEFAULT_PROVENANCE_POLICY.copy()
    chosen = Path(path)
    if not chosen.exists():
        raise FileNotFoundError(f"Provenance policy file not found: {path}")
    data = json.loads(chosen.read_text(encoding="utf-8"))
    policy = json.loads(json.dumps(DEFAULT_PROVENANCE_POLICY))
    for key, value in data.items():
        if isinstance(value, dict) and isinstance(policy.get(key), dict):
            policy[key].update(value)
        else:
            policy[key] = value
    if policy.get("schema") != DEFAULT_PROVENANCE_POLICY["schema"]:
        raise ValueError("Unsupported provenance policy schema")
    return policy


def _download_temp_artifact(url: str | None) -> tuple[str | None, str | None]:
    if not url:
        return None, "no artifact URL available for Sigstore verification"
    content, err = fetch_bytes(url, timeout=30, use_cache=True)
    if err or content is None:
        return None, str((err or {}).get("detail") or err or "empty response")
    suffix = Path(urllib.parse.urlparse(url).path).suffix or ".artifact"
    fd, path = tempfile.mkstemp(prefix="scda-artifact-", suffix=suffix)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
    return path, None


def _run_sigstore_verify(artifact_path: str, policy: dict) -> dict:
    sigstore_cfg = policy.get("sigstore", {}) or {}
    identity_regex = sigstore_cfg.get("cert_identity_regex")
    issuer = sigstore_cfg.get("cert_oidc_issuer")
    if not shutil.which("sigstore"):
        return {"ok": False, "executed": False, "error": "sigstore CLI is not installed"}
    if not identity_regex or not issuer:
        return {"ok": False, "executed": False, "error": "sigstore identity regex and OIDC issuer are required"}
    cmd = [
        "sigstore",
        "verify",
        "identity",
        "--cert-identity-regex",
        str(identity_regex),
        "--cert-oidc-issuer",
        str(issuer),
        artifact_path,
    ]
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return {"ok": proc.returncode == 0, "executed": True, "command": cmd, "output": ((proc.stdout or "") + (proc.stderr or "")).strip()[:3000]}


def _load_attestation_records(path: str | os.PathLike[str]) -> list[dict]:
    raw = Path(path).read_text(encoding="utf-8").strip()
    if not raw:
        return []
    if raw.startswith("["):
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    if raw.startswith("{"):
        return [json.loads(raw)]
    records = []
    for line in raw.splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def _attestation_payload(record: dict) -> dict:
    # Accept raw in-toto Statement, DSSE envelope with decoded payload, or compact test fixture.
    if "predicate" in record:
        return record
    payload = record.get("payload")
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        try:
            decoded = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8")
            return json.loads(decoded)
        except Exception:
            return {}
    return {}


def validate_slsa_attestation(policy: dict) -> dict:
    cfg = policy.get("slsa", {}) or {}
    path = cfg.get("attestation_file")
    result = {"ok": None, "checked": False, "flags": [], "evidence": {}}
    if not path:
        if cfg.get("required"):
            result["ok"] = False
            result["flags"].append("SLSA attestation is required but no attestation_file was configured")
        return result
    if not Path(path).exists():
        result["ok"] = False
        result["checked"] = True
        result["flags"].append(f"SLSA attestation file was not found: {path}")
        return result
    try:
        records = _load_attestation_records(path)
    except Exception as exc:
        result["ok"] = False
        result["checked"] = True
        result["flags"].append(f"Could not parse SLSA attestation: {exc}")
        return result
    expected_builder = cfg.get("expected_builder_id")
    expected_repo = cfg.get("expected_source_repository")
    matched = False
    for record in records:
        statement = _attestation_payload(record)
        predicate_type = str(statement.get("predicateType") or "")
        predicate = statement.get("predicate") or {}
        builder_id = str(((predicate.get("builder") or {}).get("id")) or "")
        source_uri = str((((predicate.get("invocation") or {}).get("configSource") or {}).get("uri")) or "")
        if "slsa" not in predicate_type.lower():
            continue
        if expected_builder and expected_builder not in builder_id:
            continue
        if expected_repo and expected_repo not in source_uri:
            continue
        matched = True
        result["evidence"] = {"predicateType": predicate_type, "builder_id": builder_id, "source_uri": source_uri}
        break
    result["checked"] = True
    result["ok"] = matched
    if matched:
        result["flags"].append("SLSA provenance attestation matched configured builder/source policy")
    else:
        result["flags"].append("No SLSA provenance attestation matched configured builder/source policy")
    return result


def check_provenance(package_name: str, ecosystem: str, version: str | None, scan_result: dict | None, metadata: dict | None = None, *, provenance_policy_path: str | None = None) -> dict:
    policy = load_provenance_policy(provenance_policy_path)
    result = {
        "package": package_name,
        "ecosystem": ecosystem,
        "version": version,
        "artifact_integrity_verified": None,
        "registry_digest_present": False,
        "provenance_attestation_present": False,
        "sigstore_cli_available": bool(shutil.which("sigstore")),
        "sigstore_verified": None,
        "slsa_verified": None,
        "flags": [],
        "evidence": {},
    }

    scan_result = scan_result or {}
    artifact_url = scan_result.get("artifact_url")

    if ecosystem == "npm":
        dist = _registry_npm_dist(package_name, version)
        integrity = dist.get("integrity")
        expected_b64 = _sri_sha512_b64(integrity)
        result["registry_digest_present"] = bool(expected_b64 or dist.get("shasum"))
        result["provenance_attestation_present"] = bool(dist.get("provenance") or dist.get("attestations") or dist.get("signatures"))
        result["evidence"] = {"registry_integrity": integrity, "tarball": dist.get("tarball")}

        actual_b64 = scan_result.get("artifact_sha512_base64")
        if expected_b64 and actual_b64:
            result["artifact_integrity_verified"] = expected_b64 == actual_b64
            result["flags"].append("npm tarball integrity verified against registry SHA-512 SRI digest" if result["artifact_integrity_verified"] else "npm tarball SHA-512 does not match registry integrity digest")
        elif expected_b64:
            result["flags"].append("npm registry integrity digest exists but local artifact was not available for verification")
        else:
            result["flags"].append("npm registry did not expose a SHA-512 integrity digest for this package/version")

        result["flags"].append("npm registry exposes provenance/signature attestation metadata" if result["provenance_attestation_present"] else "No npm provenance/signature attestation metadata found in registry response")
        artifact_url = artifact_url or dist.get("tarball")

    elif ecosystem == "pip":
        files = _registry_pypi_files(package_name, version)
        result["registry_digest_present"] = any(((f.get("digests") or {}).get("sha256")) for f in files)
        result["provenance_attestation_present"] = any(bool(f.get("provenance") or f.get("attestations") or f.get("gpg_sig")) for f in files)
        result["evidence"] = {"files_seen": len(files), "artifact_url": artifact_url}

        actual_sha = (scan_result.get("artifact_sha256") or "").lower()
        matching_file = None
        for f in files:
            if artifact_url and f.get("url") != artifact_url:
                continue
            expected = ((f.get("digests") or {}).get("sha256") or "").lower()
            if expected:
                matching_file = f
                if actual_sha:
                    result["artifact_integrity_verified"] = actual_sha == expected
                artifact_url = artifact_url or f.get("url")
                break
        if result["artifact_integrity_verified"] is True:
            result["flags"].append("PyPI artifact SHA-256 verified against registry digest")
        elif result["artifact_integrity_verified"] is False:
            result["flags"].append("Downloaded PyPI artifact SHA-256 does not match registry digest")
        elif matching_file:
            result["flags"].append("PyPI registry digest exists but local artifact was not available for verification")
        else:
            result["flags"].append("No PyPI registry digest could be matched to the scanned artifact")
        result["flags"].append("PyPI file metadata exposes signature/provenance-related fields" if result["provenance_attestation_present"] else "No PyPI trusted-publishing/Sigstore attestation metadata found in registry response")
    else:
        # Ecosystems such as GitHub Actions, Terraform, Maven coordinates, Go modules,
        # and Dockerfile image references are handled by their own static policy scanners.
        # Do not apply PyPI/npm artifact-digest requirements to them.
        result["flags"].append(f"Artifact provenance is handled by ecosystem-specific checks for {ecosystem}")
        return result

    # Optional real Sigstore CLI verification.
    sigstore_cfg = policy.get("sigstore", {}) or {}
    if sigstore_cfg.get("enabled") or sigstore_cfg.get("required"):
        artifact_path, error = _download_temp_artifact(artifact_url)
        if error:
            result["sigstore_verified"] = False
            result["flags"].append(f"Sigstore verification could not run: {error}")
        else:
            try:
                verification = _run_sigstore_verify(artifact_path, policy)
                result["sigstore_verified"] = bool(verification.get("ok"))
                result.setdefault("evidence", {})["sigstore"] = verification
                result["flags"].append("Sigstore identity verification succeeded" if verification.get("ok") else f"Sigstore identity verification failed: {verification.get('error') or verification.get('output', '')[:300]}")
            finally:
                try:
                    if artifact_path:
                        os.remove(artifact_path)
                except OSError:
                    pass

    slsa = validate_slsa_attestation(policy)
    if slsa.get("checked") or (policy.get("slsa") or {}).get("required"):
        result["slsa_verified"] = slsa.get("ok")
        result.setdefault("evidence", {})["slsa"] = slsa.get("evidence")
        result["flags"].extend(slsa.get("flags", []))

    if policy.get("require_registry_digest") and not result["registry_digest_present"]:
        result["flags"].append("Registry digest is required by provenance policy but was not present")
    return result
