"""
Risk scorer.

Combines typosquatting, registry metadata, install script scanning,
OSV vulnerability checks, maintainer/repository signals, and optional
breach/watchlist matches into one score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


TOP_REPUTABLE_PACKAGES = {
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "scipy",
    "fastapi",
    "pytest",
    "setuptools",
    "pip",
    "wheel",
    "urllib3",
    "certifi",
    "cryptography",
    "pyyaml",
    "jinja2",
    "click",
    "werkzeug",
    "sqlalchemy",
    "beautifulsoup4",
    "lxml",
    "boto3",
    "botocore",
    "matplotlib",
    "scikit-learn",
    "tensorflow",
    "torch",
    "lodash",
    "react",
    "express",
    "axios",
    "vite",
    "next",
    "typescript",
    "eslint",
    "webpack",
    "pydantic",
    "pydantic-core",
    "pydantic_core",
    "chardet",
    "asgiref",
    "idna",
    "httpx",
    "markupsafe",
    "blinker",
    "charset-normalizer",
    "charset_normalizer",
    "python-dotenv",
    "ollama",
}



RISK_WEIGHTS = {
    "package_not_found": 20,

    "typosquat_distance_1": 65,
    "typosquat_distance_2": 35,
    "typosquat_high_similarity": 20,

    "package_age_under_7_days": 35,
    "package_age_under_30_days": 20,
    "package_age_under_90_days": 8,
    "latest_version_under_7_days": 30,
    "latest_version_under_30_days": 12,

    "no_repository": 8,
    "single_version": 8,
    "single_maintainer": 2,
    "very_low_downloads": 12,
    "no_classifiers": 2,

    "install_script_exec": 30,
    "install_script_network": 35,
    "install_script_env_harvest": 30,
    "install_script_obfuscation": 40,
    "install_script_permission": 25,
    "install_script_persistence": 30,

    "vuln_critical": 45,
    "vuln_high": 30,
    "vuln_medium": 12,
    "vuln_low": 4,

    "maintainer_takeover": 6,
    "repo_archived": 12,
    "repo_unverified": 3,
    "repo_stale": 3,
    "repo_very_new": 10,

    "breach_watchlist_match": 50,

    "license_denied": 35,
    "license_review": 12,
    "license_unknown": 4,

    "dependency_unpinned": 8,
    "missing_lockfile": 8,
    "missing_integrity": 5,
    "integrity_mismatch": 70,

    "epss_high": 20,
    "epss_medium": 10,

    # Missing provenance is useful context but is not automatically risk.
    # Many legitimate registry packages still do not publish Sigstore/attestation metadata.
    "provenance_missing": 0,
    "provenance_integrity_mismatch": 70,

    # Static malware analysis is intentionally conservative in scoring.
    # Package archives often contain tests/docs/examples that mention tokens,
    # URLs, subprocesses, or credential words. Those findings are still reported
    # for analysts, but a single pattern match should not make a mature package
    # look malicious. Correlated indicators, typosquatting, integrity mismatch,
    # or breach signals still drive high risk.
    "malware_secret": 40,
    "malware_critical": 45,
    "malware_high": 18,
    "malware_medium": 5,
    "malware_low": 2,
    "malware_binary": 6,
}


@dataclass
class RiskReport:
    package: str
    ecosystem: str
    version: Optional[str]
    risk_score: int
    risk_level: str
    recommendation: str
    signals: list[dict] = field(default_factory=list)
    typosquat: Optional[dict] = None
    metadata: Optional[dict] = None
    scan: Optional[dict] = None
    vulns: Optional[dict] = None
    maintainer: Optional[dict] = None
    breach: Optional[dict] = None
    license: Optional[dict] = None
    dependency_policy: Optional[dict] = None
    provenance: Optional[dict] = None
    malware: Optional[dict] = None
    sandbox: Optional[dict] = None
    remediation: Optional[dict] = None
    policy_decision: Optional[dict] = None
    ai_explanation: Optional[str] = None


def _add_signal(signals: list, severity: str, category: str, detail: str, **extra) -> None:
    signal = {
        "severity": severity,
        "category": category,
        "detail": detail,
    }
    signal.update(extra)
    signals.append(signal)


def _download_count(metadata: dict) -> int:
    weekly = metadata.get("weekly_downloads") or 0
    monthly = metadata.get("monthly_downloads") or 0
    return max(weekly, monthly)


def _reputation_bonus(package_name: str, metadata: dict, maintainer_result: Optional[dict]) -> int:
    """Reduce false positives for established packages."""
    bonus = 0
    downloads = _download_count(metadata)

    if downloads >= 1_000_000:
        bonus += 30
    elif downloads >= 100_000:
        bonus += 20
    elif downloads >= 10_000:
        bonus += 10

    if package_name.lower() in TOP_REPUTABLE_PACKAGES:
        bonus += 20

    if maintainer_result:
        repo = maintainer_result.get("repository_health", {}) or {}
        stars = repo.get("stars") or 0
        if stars >= 10_000:
            bonus += 15
        elif stars >= 1_000:
            bonus += 8
        elif stars >= 100:
            bonus += 4

    return min(bonus, 45)


def _install_script_severity_and_weight(description: str) -> tuple[str, int]:
    lowered = description.lower()

    if any(word in lowered for word in ["obfuscat", "base64", "decompress", "marshal", "pickle", "deserialize"]):
        return "CRITICAL", RISK_WEIGHTS["install_script_obfuscation"]

    if any(word in lowered for word in ["network", "socket", "url", "http", "download"]):
        return "HIGH", RISK_WEIGHTS["install_script_network"]

    if any(word in lowered for word in ["credential", "token", "key", "password", "secret", "environ"]):
        return "HIGH", RISK_WEIGHTS["install_script_env_harvest"]

    if any(word in lowered for word in ["exec", "eval", "shell", "subprocess", "system", "popen", "spawn"]):
        return "HIGH", RISK_WEIGHTS["install_script_exec"]

    if any(word in lowered for word in ["permission", "ownership", "privilege", "chmod", "chown", "sudo", "executionpolicy", "icacls"]):
        return "HIGH", RISK_WEIGHTS["install_script_permission"]

    if any(word in lowered for word in ["persistence", "startup", "autorun", "crontab", "schtasks", "systemctl", "launchctl"]):
        return "HIGH", RISK_WEIGHTS["install_script_persistence"]

    return "MEDIUM", 10


def score_package(
    typosquat_result: dict,
    metadata_result: dict,
    scan_result: dict,
    osv_result: dict,
    maintainer_result: Optional[dict] = None,
    breach_result: Optional[dict] = None,
    requested_version: Optional[str] = None,
    license_result: Optional[dict] = None,
    dependency_policy_result: Optional[dict] = None,
    provenance_result: Optional[dict] = None,
    malware_result: Optional[dict] = None,
    sandbox_result: Optional[dict] = None,
) -> RiskReport:
    name = metadata_result.get("name", "unknown")
    ecosystem = metadata_result.get("ecosystem", "unknown")
    version = (
        requested_version
        if requested_version not in (None, "", "unknown", "unpinned")
        else metadata_result.get("latest_version")
    )

    score = 0
    signals = []

    # -------------------------
    # Registry existence
    # -------------------------
    metadata_exists = metadata_result.get("exists")
    metadata_available = metadata_exists is True

    if metadata_exists is False:
        score += RISK_WEIGHTS["package_not_found"]
        _add_signal(
            signals,
            "HIGH",
            "Registry metadata",
            f"Package '{name}' was not found in the {ecosystem} registry",
        )
    elif metadata_exists is None:
        _add_signal(
            signals,
            "INFO",
            "Registry metadata",
            f"Registry metadata for '{name}' could not be verified because the registry request failed",
        )

    # -------------------------
    # Typosquatting
    # -------------------------
    is_typosquat = typosquat_result.get("is_suspicious", False)

    if is_typosquat:
        distance = typosquat_result.get("distance", 99)
        closest = typosquat_result.get("closest_match", "")
        reason = typosquat_result.get("reason", "")

        if distance == 1:
            score += RISK_WEIGHTS["typosquat_distance_1"]
            _add_signal(
                signals,
                "HIGH",
                "Typosquatting",
                reason or f"1 character away from popular package '{closest}'",
            )
        elif distance == 2:
            score += RISK_WEIGHTS["typosquat_distance_2"]
            _add_signal(
                signals,
                "MEDIUM",
                "Typosquatting",
                reason or f"2 characters away from popular package '{closest}'",
            )
        else:
            score += RISK_WEIGHTS["typosquat_high_similarity"]
            _add_signal(
                signals,
                "MEDIUM",
                "Typosquatting",
                reason or f"Similar name to popular package '{closest}'",
            )

    # -------------------------
    # Registry metadata
    # -------------------------
    package_age = metadata_result.get("age_days") if metadata_available else None
    if package_age is not None:
        if package_age < 7:
            score += RISK_WEIGHTS["package_age_under_7_days"]
            _add_signal(signals, "HIGH", "New package", f"Package was first published only {package_age} day(s) ago")
        elif package_age < 30:
            score += RISK_WEIGHTS["package_age_under_30_days"]
            _add_signal(signals, "MEDIUM", "New package", f"Package was first published {package_age} days ago")
        elif package_age < 90:
            score += RISK_WEIGHTS["package_age_under_90_days"]
            _add_signal(signals, "LOW", "Relatively new", f"Package was first published {package_age} days ago")

    latest_age = metadata_result.get("latest_version_age_days") if metadata_available else None
    if latest_age is not None:
        if latest_age < 7:
            score += RISK_WEIGHTS["latest_version_under_7_days"]
            _add_signal(signals, "HIGH", "Recently uploaded version", f"Latest version was uploaded only {latest_age} day(s) ago")
        elif latest_age < 30:
            score += RISK_WEIGHTS["latest_version_under_30_days"]
            _add_signal(signals, "MEDIUM", "Recently uploaded version", f"Latest version was uploaded {latest_age} days ago")

    if metadata_available and not metadata_result.get("repository"):
        score += RISK_WEIGHTS["no_repository"]
        _add_signal(signals, "MEDIUM", "No source repo", "Package has no linked source repository")

    if metadata_available and metadata_result.get("version_count", 99) == 1:
        score += RISK_WEIGHTS["single_version"]
        _add_signal(signals, "LOW", "Single version", "Only one version has ever been published")

    maintainers = metadata_result.get("maintainers", []) or []
    if metadata_available and len(maintainers) == 1 and maintainers[0] != "unknown":
        score += RISK_WEIGHTS["single_maintainer"]
        _add_signal(signals, "LOW", "Single maintainer", f"Only one maintainer: {maintainers[0]}")

    downloads = _download_count(metadata_result) if metadata_available else 0
    if downloads and downloads < 100:
        score += RISK_WEIGHTS["very_low_downloads"]
        _add_signal(signals, "MEDIUM", "Low downloads", f"Only {downloads} downloads recently")

    if metadata_available and not metadata_result.get("classifiers") and ecosystem == "pip":
        score += RISK_WEIGHTS["no_classifiers"]
        _add_signal(signals, "LOW", "PyPI metadata", "No PyPI classifiers are set")

    for flag in metadata_result.get("flags", []):
        _add_signal(signals, "INFO", "Registry flag", flag)

    # -------------------------
    # Maintainer / repository takeover signals
    # -------------------------
    if maintainer_result and metadata_available:
        for flag in maintainer_result.get("flags", []):
            low = flag.lower()

            if "single maintainer" in low or "recent publisher" in low or "several different" in low:
                score += RISK_WEIGHTS["maintainer_takeover"]
                _add_signal(signals, "MEDIUM", "Maintainer takeover", flag)
            elif "archived" in low:
                score += RISK_WEIGHTS["repo_archived"]
                _add_signal(signals, "MEDIUM", "Repository health", flag)
            elif "could not be verified" in low or "could not be resolved" in low:
                score += RISK_WEIGHTS["repo_unverified"]
                _add_signal(signals, "LOW", "Repository health", flag)
            elif "not been updated" in low:
                score += RISK_WEIGHTS["repo_stale"]
                _add_signal(signals, "LOW", "Repository health", flag)
            elif "very new" in low:
                score += RISK_WEIGHTS["repo_very_new"]
                _add_signal(signals, "MEDIUM", "Repository health", flag)
            elif "no github stars" in low:
                score += 2
                _add_signal(signals, "LOW", "Repository health", flag)
            else:
                _add_signal(signals, "INFO", "Maintainer signal", flag)

    # -------------------------
    # Breach/watchlist cross-reference
    # -------------------------
    if breach_result:
        for flag in breach_result.get("flags", []):
            score += RISK_WEIGHTS["breach_watchlist_match"]
            _add_signal(signals, "CRITICAL", "Breach watchlist", flag)

    # -------------------------
    # Install script scan
    # -------------------------
    findings = scan_result.get("findings", []) if scan_result else []
    seen_install_categories = set()

    for finding in findings:
        desc = finding.get("description", "")
        key = desc.lower()

        # Deduplicate by finding type so one script cannot inflate score endlessly.
        if key in seen_install_categories:
            severity, weight = _install_script_severity_and_weight(desc)
            weight = 0
        else:
            seen_install_categories.add(key)
            severity, weight = _install_script_severity_and_weight(desc)

        score += weight

        file_name = finding.get("file", "?")
        line = finding.get("line")
        file_ref = f"in {file_name}"
        if line:
            file_ref += f" line {line}"

        _add_signal(
            signals,
            severity,
            "Install script",
            f"{desc} ({file_ref})",
            snippet=finding.get("snippet"),
        )

    # -------------------------
    # License compliance
    # -------------------------
    if license_result:
        status = license_result.get("status")
        for flag in license_result.get("flags", []):
            if status == "DENY":
                score += RISK_WEIGHTS["license_denied"]
                _add_signal(signals, "HIGH", "License compliance", flag)
            elif status == "REVIEW":
                score += RISK_WEIGHTS["license_review"]
                _add_signal(signals, "MEDIUM", "License compliance", flag)
            elif status == "UNKNOWN":
                score += RISK_WEIGHTS["license_unknown"]
                _add_signal(signals, "LOW", "License compliance", flag)

    # -------------------------
    # Pinning / lockfile / integrity policy
    # -------------------------
    if dependency_policy_result:
        policy_flags = dependency_policy_result.get("flags", [])
        for flag in policy_flags:
            low = flag.lower()
            if "does not match" in low:
                score += RISK_WEIGHTS["integrity_mismatch"]
                _add_signal(signals, "CRITICAL", "Package integrity", flag)
            elif "not pinned" in low:
                score += RISK_WEIGHTS["dependency_unpinned"]
                _add_signal(signals, "LOW", "Dependency pinning", flag)
            elif "no npm lockfile" in low:
                score += RISK_WEIGHTS["missing_lockfile"]
                _add_signal(signals, "LOW", "Lockfile validation", flag)
            elif "does not include an integrity hash" in low or "no --hash" in low:
                score += RISK_WEIGHTS["missing_integrity"]
                _add_signal(signals, "LOW", "Package integrity", flag)
            else:
                _add_signal(signals, "INFO", "Dependency policy", flag)

    # -------------------------
    # Artifact integrity / provenance attestation
    # -------------------------
    if provenance_result:
        for flag in provenance_result.get("flags", []):
            low = flag.lower()
            if "does not match" in low or "verification failed" in low or "required" in low or "not found" in low or "no slsa provenance attestation matched" in low:
                score += RISK_WEIGHTS["provenance_integrity_mismatch"]
                _add_signal(signals, "CRITICAL", "Artifact integrity", flag)
            elif "verified against" in low or "attestation metadata" in low and "exposes" in low:
                _add_signal(signals, "INFO", "Artifact provenance", flag)
            elif "no " in low and ("provenance" in low or "attestation" in low or "digest" in low):
                # Missing provenance is useful supply-chain context, but it should not
                # make legitimate packages look malicious by itself. Only mismatches
                # are scored by default; missing attestation is informational unless
                # a future strict policy mode is enabled.
                _add_signal(signals, "INFO", "Artifact provenance", flag)
            else:
                _add_signal(signals, "INFO", "Artifact provenance", flag)


    # -------------------------
    # Static malware / secret / IOC analysis
    # -------------------------
    if malware_result:
        # Keep all unique analyst-visible findings, but score each behavior type only once.
        # This prevents large, legitimate packages from becoming CRITICAL because the
        # same low-context keyword appears repeatedly across source files.
        seen_signal_keys = set()
        scored_behavior_keys = set()
        malware_subscore = 0
        malware_scoreable_categories = 0

        for finding in malware_result.get("findings", []) or []:
            desc = str(finding.get("description") or "Malware indicator")
            category = str(finding.get("category") or "Malware analysis")
            severity = str(finding.get("severity") or "MEDIUM").upper()
            confidence = str(finding.get("confidence") or "HIGH").upper()
            scoreable = finding.get("scoreable", True)

            signal_key = (category, desc, finding.get("file"), finding.get("line"))
            behavior_key = (category.lower(), desc.lower())

            if scoreable and severity != "INFO" and behavior_key not in scored_behavior_keys:
                scored_behavior_keys.add(behavior_key)
                malware_scoreable_categories += 1
                if category.lower().startswith("secret") and confidence == "HIGH":
                    weight = RISK_WEIGHTS["malware_secret"]
                    severity = "HIGH"
                elif severity == "CRITICAL" and confidence == "HIGH":
                    weight = RISK_WEIGHTS["malware_critical"]
                elif severity == "HIGH" and confidence == "HIGH":
                    weight = RISK_WEIGHTS["malware_high"]
                elif category.lower().startswith("binary"):
                    weight = RISK_WEIGHTS["malware_binary"]
                elif severity == "LOW":
                    weight = RISK_WEIGHTS["malware_low"]
                else:
                    weight = RISK_WEIGHTS["malware_medium"]
                malware_subscore += weight

            if signal_key in seen_signal_keys:
                continue
            seen_signal_keys.add(signal_key)
            detail = desc
            file_name = finding.get("file")
            line = finding.get("line")
            if file_name:
                detail += f" in {file_name}"
                if line:
                    detail += f" line {line}"
            _add_signal(
                signals,
                severity,
                category,
                detail,
                snippet=finding.get("snippet"),
                line=line,
            )

        # Cap malware-only contribution for established packages unless there are
        # multiple independent, high-confidence behavior classes. This is a false-positive
        # guardrail for packages that contain security tests, documentation samples,
        # native extensions, or generic credential-handling code.
        mature_or_popular = (name.lower() in TOP_REPUTABLE_PACKAGES) or (_download_count(metadata_result) >= 100_000)
        if mature_or_popular and malware_scoreable_categories < 2:
            malware_subscore = min(malware_subscore, 12)
        elif mature_or_popular:
            malware_subscore = min(malware_subscore, 35)

        score += malware_subscore

        if malware_result.get("error"):
            _add_signal(signals, "INFO", "Malware analysis", f"Static malware analysis warning: {malware_result.get('error')}")

    # -------------------------
    # Optional dynamic sandbox behavior
    # -------------------------
    if sandbox_result:
        sandbox_subscore = 0
        seen_sandbox = set()
        for finding in sandbox_result.get("findings", []) or []:
            desc = str(finding.get("description") or "Sandbox finding")
            category = str(finding.get("category") or "Dynamic sandbox")
            severity = str(finding.get("severity") or "MEDIUM").upper()
            key = (category.lower(), desc.lower())
            if key not in seen_sandbox:
                seen_sandbox.add(key)
                if severity == "CRITICAL":
                    sandbox_subscore += 45
                elif severity == "HIGH":
                    sandbox_subscore += 30
                elif severity == "MEDIUM":
                    sandbox_subscore += 12
                else:
                    sandbox_subscore += 3
            _add_signal(signals, severity, category, desc, evidence=finding.get("evidence"))
        if sandbox_result.get("warnings"):
            for warning in sandbox_result.get("warnings", [])[:3]:
                _add_signal(signals, "INFO", "Dynamic sandbox", warning)
        score += min(sandbox_subscore, 70)

    # -------------------------
    # OSV vulnerabilities
    # -------------------------
    for vuln in osv_result.get("vulns", []) if osv_result else []:
        severity = vuln.get("severity", "UNKNOWN")
        key = f"vuln_{severity.lower()}"
        score += RISK_WEIGHTS.get(key, 0)

        epss = vuln.get("epss_probability")
        if epss is not None:
            if epss >= 0.50:
                score += RISK_WEIGHTS["epss_high"]
            elif epss >= 0.10:
                score += RISK_WEIGHTS["epss_medium"]

        cvss = f" (CVSS {vuln['cvss_score']})" if vuln.get("cvss_score") else ""
        epss_text = f"; EPSS {epss:.1%}" if epss is not None else ""
        _add_signal(
            signals,
            severity,
            "Known vulnerability",
            f"{vuln.get('id')}{cvss}{epss_text}: {vuln.get('summary', 'No summary')}",
            references=vuln.get("references", []),
        )

    # -------------------------
    # Reputation bonus
    # -------------------------
    has_critical_breach = bool(breach_result and breach_result.get("flags"))
    has_install_script_findings = bool(findings)
    has_high_vuln = any(v.get("severity") in {"CRITICAL", "HIGH"} for v in (osv_result or {}).get("vulns", []))

    # Do not let reputation hide typosquats, breach matches, malicious install scripts, or high CVEs.
    if not is_typosquat and not has_critical_breach and not has_install_script_findings and not has_high_vuln:
        bonus = _reputation_bonus(name, metadata_result, maintainer_result)
        score -= bonus
        if bonus > 0:
            _add_signal(
                signals,
                "INFO",
                "Reputation bonus",
                f"Reduced risk by {bonus} points due to package reputation/downloads/repository trust",
            )

    # V8 confidence calibration: established packages should not become MEDIUM/HIGH
    # from low-confidence static artifact signals alone. Do not apply this guardrail
    # to typosquats, breach hits, integrity/provenance mismatches, malicious install
    # scripts, high CVEs, or dynamic sandbox findings.
    strong_signal_present = (
        is_typosquat
        or has_critical_breach
        or has_install_script_findings
        or has_high_vuln
        or any("does not match" in str(flag).lower() or "verification failed" in str(flag).lower() for flag in (provenance_result or {}).get("flags", []))
        or bool(sandbox_result and sandbox_result.get("findings"))
    )
    mature_or_popular_final = (name.lower() in TOP_REPUTABLE_PACKAGES) or (_download_count(metadata_result) >= 100_000)
    if mature_or_popular_final and not strong_signal_present and score > 14:
        original_score = score
        score = 14
        _add_signal(
            signals,
            "INFO",
            "False-positive guardrail",
            f"Reduced score from {int(original_score)} to {score} because only low-confidence static signals were present for an established package",
        )

    # Clamp
    score = max(0, min(int(score), 100))

    # -------------------------
    # Risk level
    # -------------------------
    if score >= 85:
        risk_level = "CRITICAL"
        recommendation = "DO NOT INSTALL. This package shows multiple high-severity supply-chain risk indicators."
    elif score >= 60:
        risk_level = "HIGH"
        recommendation = "Avoid installing. Manually review the package source, maintainers, and registry history before using."
    elif score >= 35:
        risk_level = "MEDIUM"
        recommendation = "Proceed with caution. Review flagged signals before installing."
    elif score >= 15:
        risk_level = "LOW"
        recommendation = "Low risk. Consider reviewing flagged signals."
    else:
        risk_level = "SAFE"
        recommendation = "No significant risk signals detected."

    return RiskReport(
        package=name,
        ecosystem=ecosystem,
        version=version,
        risk_score=score,
        risk_level=risk_level,
        recommendation=recommendation,
        signals=signals,
        typosquat=typosquat_result,
        metadata=metadata_result,
        scan=scan_result,
        vulns=osv_result,
        maintainer=maintainer_result,
        breach=breach_result,
        license=license_result,
        dependency_policy=dependency_policy_result,
        provenance=provenance_result,
        malware=malware_result,
        sandbox=sandbox_result,
    )
