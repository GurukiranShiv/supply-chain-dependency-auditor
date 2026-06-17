"""
Registry metadata fetcher.

Pulls npm and PyPI metadata to detect:
- missing packages
- newly created packages and latest-version upload age
- low adoption and maintainer count
- repository/homepage links
- license metadata
- direct dependency metadata for controlled transitive scanning

Uses auditor.http_client for caching, retry/backoff, and rate limiting.
"""

from __future__ import annotations

import re
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

from .http_client import fetch_json


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _age_days(dt: Optional[datetime]) -> Optional[int]:
    if not dt:
        return None
    return max((datetime.now(timezone.utc) - dt).days, 0)


def _normalize_repo(repo_value) -> Optional[str]:
    if isinstance(repo_value, dict):
        return repo_value.get("url") or repo_value.get("repository")
    if isinstance(repo_value, str):
        return repo_value
    return None


def _npm_package_url(package_name: str) -> str:
    return "https://registry.npmjs.org/" + urllib.parse.quote(package_name, safe="@")


def _clean_dependency_name(requirement: str) -> Optional[str]:
    text = str(requirement).strip()
    if not text:
        return None
    # Drop environment markers and extras.
    text = text.split(";", 1)[0].strip()
    match = re.match(r"^([A-Za-z0-9_.\-]+)", text)
    return match.group(1) if match else None


def _npm_latest_version_info(data: dict) -> dict:
    latest = (data.get("dist-tags", {}) or {}).get("latest")
    versions = data.get("versions", {}) or {}
    if latest and isinstance(versions.get(latest), dict):
        return versions[latest]
    return {}


def get_npm_metadata(package_name: str) -> dict:
    result = {
        "ecosystem": "npm",
        "name": package_name,
        "exists": False,
        "published_at": None,
        "age_days": None,
        "latest_version": None,
        "latest_version_published_at": None,
        "latest_version_age_days": None,
        "version_count": 0,
        "maintainers": [],
        "weekly_downloads": None,
        "homepage": None,
        "repository": None,
        "license": None,
        "classifiers": [],
        "dependencies": [],
        "optional_dependencies": [],
        "peer_dependencies": [],
        "flags": [],
    }

    data = fetch_json(_npm_package_url(package_name))
    if not data or data.get("__error__"):
        if data.get("__error__") == "not_found" or data.get("status") == 404:
            result["flags"].append("Package not found in npm registry")
            return result
        result["exists"] = None
        result["flags"].append(f"Could not fetch npm registry metadata: {data.get('__error__', 'unknown')}")
        return result
    if data.get("error"):
        result["flags"].append("Package not found in npm registry")
        return result

    latest_info = _npm_latest_version_info(data)

    result["exists"] = True
    result["latest_version"] = (data.get("dist-tags", {}) or {}).get("latest")
    result["homepage"] = latest_info.get("homepage") or data.get("homepage")
    result["repository"] = _normalize_repo(latest_info.get("repository") or data.get("repository"))
    result["license"] = latest_info.get("license") or data.get("license")

    maintainers = data.get("maintainers", [])
    result["maintainers"] = [
        m.get("name", "")
        for m in maintainers
        if isinstance(m, dict) and m.get("name")
    ]

    versions = data.get("versions", {}) or {}
    time_info = data.get("time", {}) or {}
    result["version_count"] = len(versions)

    for section, key in (
        ("dependencies", "dependencies"),
        ("optionalDependencies", "optional_dependencies"),
        ("peerDependencies", "peer_dependencies"),
    ):
        deps = latest_info.get(section, {}) or {}
        if isinstance(deps, dict):
            result[key] = [
                {"name": str(name), "version_spec": str(spec)}
                for name, spec in deps.items()
            ]

    created = _parse_datetime(time_info.get("created"))
    if created:
        result["published_at"] = created.isoformat()
        result["age_days"] = _age_days(created)

    latest = result["latest_version"]
    latest_uploaded = _parse_datetime(time_info.get(latest)) if latest else None
    if latest_uploaded:
        result["latest_version_published_at"] = latest_uploaded.isoformat()
        result["latest_version_age_days"] = _age_days(latest_uploaded)

    dl_data = fetch_json(
        "https://api.npmjs.org/downloads/point/last-week/" + urllib.parse.quote(package_name, safe="@/")
    )
    if dl_data and isinstance(dl_data.get("downloads"), int):
        result["weekly_downloads"] = dl_data["downloads"]

    if result["age_days"] is not None and result["age_days"] < 30:
        result["flags"].append(f"Very new package — only {result['age_days']} days old")
    elif result["age_days"] is not None and result["age_days"] < 90:
        result["flags"].append(f"Relatively new package — {result['age_days']} days old")

    if result["latest_version_age_days"] is not None and result["latest_version_age_days"] < 7:
        result["flags"].append(
            f"Latest version was uploaded in the last 7 days ({result['latest_version_age_days']} day(s) ago)"
        )
    elif result["latest_version_age_days"] is not None and result["latest_version_age_days"] < 30:
        result["flags"].append(
            f"Latest version was uploaded recently ({result['latest_version_age_days']} days ago)"
        )

    if result["weekly_downloads"] is not None and result["weekly_downloads"] < 100:
        result["flags"].append(f"Very low weekly downloads ({result['weekly_downloads']})")

    if len(result["maintainers"]) == 1:
        result["flags"].append("Single maintainer — higher account takeover risk")

    if not result["repository"]:
        result["flags"].append("No source repository linked")

    if result["version_count"] == 1:
        result["flags"].append("Only one version ever published")

    if not result["license"]:
        result["flags"].append("No license metadata found")

    return result


def _project_urls_repository(project_urls: dict) -> Optional[str]:
    if not isinstance(project_urls, dict):
        return None
    preferred_keys = ("Source", "Repository", "GitHub", "Code", "Source Code", "Homepage", "Home")
    for key in preferred_keys:
        value = project_urls.get(key)
        if value:
            return value
    for key, value in project_urls.items():
        if value and any(word in key.lower() for word in ("source", "repo", "code", "github")):
            return value
    return None


def _latest_pypi_upload_time(releases: dict, latest_version: Optional[str]) -> Optional[datetime]:
    if not latest_version:
        return None
    latest_files = releases.get(latest_version, []) or []
    upload_times = []
    for file_info in latest_files:
        upload_time = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
        parsed = _parse_datetime(upload_time)
        if parsed:
            upload_times.append(parsed)
    return min(upload_times) if upload_times else None


def _pypi_dependencies(info: dict) -> list[dict]:
    deps = []
    for req in info.get("requires_dist") or []:
        name = _clean_dependency_name(req)
        if name:
            deps.append({"name": name, "version_spec": str(req)})
    # Deduplicate but keep first seen spec.
    seen = set()
    out = []
    for dep in deps:
        key = dep["name"].lower()
        if key not in seen:
            seen.add(key)
            out.append(dep)
    return out


def get_pip_metadata(package_name: str) -> dict:
    result = {
        "ecosystem": "pip",
        "name": package_name,
        "exists": False,
        "published_at": None,
        "age_days": None,
        "latest_version": None,
        "latest_version_published_at": None,
        "latest_version_age_days": None,
        "version_count": 0,
        "maintainers": [],
        "monthly_downloads": None,
        "homepage": None,
        "repository": None,
        "license": None,
        "license_expression": None,
        "classifiers": [],
        "dependencies": [],
        "flags": [],
    }

    data = fetch_json(f"https://pypi.org/pypi/{urllib.parse.quote(package_name)}/json")
    if not data or data.get("__error__"):
        if data.get("__error__") == "not_found" or data.get("status") == 404:
            result["flags"].append("Package not found in PyPI")
            return result
        result["exists"] = None
        result["flags"].append(f"Could not fetch PyPI metadata: {data.get('__error__', 'unknown')}")
        return result

    result["exists"] = True
    info = data.get("info", {}) or {}
    releases = data.get("releases", {}) or {}

    result["latest_version"] = info.get("version")
    result["homepage"] = info.get("home_page")
    result["repository"] = _project_urls_repository(info.get("project_urls") or {})
    result["classifiers"] = info.get("classifiers") or []
    result["license"] = info.get("license") or info.get("license_expression")
    result["license_expression"] = info.get("license_expression")
    result["dependencies"] = _pypi_dependencies(info)
    result["version_count"] = len(releases)

    maintainers = []
    for key in ("maintainer", "author"):
        value = info.get(key)
        if value and value not in maintainers:
            maintainers.append(value)
    result["maintainers"] = maintainers

    earliest = None
    for version_files in releases.values():
        for file_info in version_files:
            upload_time = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
            parsed = _parse_datetime(upload_time)
            if parsed and (earliest is None or parsed < earliest):
                earliest = parsed

    if earliest:
        result["published_at"] = earliest.isoformat()
        result["age_days"] = _age_days(earliest)

    latest_uploaded = _latest_pypi_upload_time(releases, result["latest_version"])
    if latest_uploaded:
        result["latest_version_published_at"] = latest_uploaded.isoformat()
        result["latest_version_age_days"] = _age_days(latest_uploaded)

    if result["age_days"] is not None and result["age_days"] < 30:
        result["flags"].append(f"Very new package — only {result['age_days']} days old")
    elif result["age_days"] is not None and result["age_days"] < 90:
        result["flags"].append(f"Relatively new package — {result['age_days']} days old")

    if result["latest_version_age_days"] is not None and result["latest_version_age_days"] < 7:
        result["flags"].append(
            f"Latest version was uploaded in the last 7 days ({result['latest_version_age_days']} day(s) ago)"
        )
    elif result["latest_version_age_days"] is not None and result["latest_version_age_days"] < 30:
        result["flags"].append(
            f"Latest version was uploaded recently ({result['latest_version_age_days']} days ago)"
        )

    if not result["repository"]:
        result["flags"].append("No source repository linked")

    if result["version_count"] == 1:
        result["flags"].append("Only one version ever published")

    if not result["classifiers"]:
        result["flags"].append("No PyPI classifiers set (often skipped by malicious packages)")

    if not result["license"]:
        result["flags"].append("No license metadata found")

    return result


def get_metadata(package_name: str, ecosystem: str) -> dict:
    if ecosystem == "npm":
        return get_npm_metadata(package_name)
    if ecosystem == "pip":
        return get_pip_metadata(package_name)
    raise ValueError(f"Unknown ecosystem: {ecosystem}")

# ---------------------------------------------------------------------------
# V8 additional ecosystem metadata adapters
# ---------------------------------------------------------------------------

def _empty_metadata(package_name: str, ecosystem: str, *, exists=None, flags=None, latest_version=None, license=None, repository=None) -> dict:
    return {
        "ecosystem": ecosystem,
        "name": package_name,
        "exists": exists,
        "published_at": None,
        "age_days": None,
        "latest_version": latest_version,
        "latest_version_published_at": None,
        "latest_version_age_days": None,
        "version_count": 0,
        "maintainers": [],
        "weekly_downloads": None,
        "monthly_downloads": None,
        "homepage": None,
        "repository": repository,
        "license": license,
        "classifiers": [],
        "dependencies": [],
        "optional_dependencies": [],
        "peer_dependencies": [],
        "flags": flags or [],
    }


def get_maven_metadata(coordinate: str) -> dict:
    if ":" not in coordinate:
        return _empty_metadata(coordinate, "maven", exists=None, flags=["Invalid Maven coordinate; expected groupId:artifactId"])
    group, artifact = coordinate.split(":", 1)
    url = "https://search.maven.org/solrsearch/select?q=" + urllib.parse.quote(f'g:"{group}" AND a:"{artifact}"') + "&rows=1&wt=json"
    data = fetch_json(url, timeout=12)
    if not data or data.get("__error__"):
        return _empty_metadata(coordinate, "maven", exists=None, flags=[f"Could not fetch Maven Central metadata: {data.get('__error__', 'unknown') if isinstance(data, dict) else 'unknown'}"])
    docs = (((data.get("response") or {}).get("docs")) or [])
    if not docs:
        return _empty_metadata(coordinate, "maven", exists=False, flags=["Package not found in Maven Central"])
    doc = docs[0]
    return _empty_metadata(coordinate, "maven", exists=True, latest_version=doc.get("latestVersion"), flags=[], repository="https://search.maven.org/", license=None) | {"version_count": int(doc.get("versionCount") or 0)}


def get_nuget_metadata(package_name: str) -> dict:
    url = f"https://api.nuget.org/v3/registration5-semver1/{urllib.parse.quote(package_name.lower())}/index.json"
    data = fetch_json(url, timeout=12)
    if not data or data.get("__error__"):
        err = data.get("__error__", "unknown") if isinstance(data, dict) else "unknown"
        return _empty_metadata(package_name, "nuget", exists=False if err == "not_found" else None, flags=[f"Could not fetch NuGet metadata: {err}"])
    versions = []
    for page in data.get("items", []) or []:
        for item in page.get("items", []) or []:
            catalog = item.get("catalogEntry") or {}
            if catalog.get("version"):
                versions.append(catalog.get("version"))
    latest = versions[-1] if versions else None
    return _empty_metadata(package_name, "nuget", exists=True, latest_version=latest, repository=(data.get("@id") or None)) | {"version_count": len(versions)}


def get_rubygems_metadata(package_name: str) -> dict:
    data = fetch_json(f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(package_name)}.json", timeout=12)
    if not data or data.get("__error__"):
        err = data.get("__error__", "unknown") if isinstance(data, dict) else "unknown"
        return _empty_metadata(package_name, "rubygems", exists=False if err == "not_found" else None, flags=[f"Could not fetch RubyGems metadata: {err}"])
    return _empty_metadata(
        package_name,
        "rubygems",
        exists=True,
        latest_version=data.get("version"),
        license=(data.get("licenses") or [None])[0] if isinstance(data.get("licenses"), list) else data.get("licenses"),
        repository=data.get("source_code_uri") or data.get("homepage_uri"),
    ) | {"monthly_downloads": data.get("downloads")}


def get_go_metadata(module_path: str) -> dict:
    escaped = module_path.replace("/", "%2F")
    data = fetch_json(f"https://proxy.golang.org/{escaped}/@latest", timeout=12)
    if not data or data.get("__error__"):
        err = data.get("__error__", "unknown") if isinstance(data, dict) else "unknown"
        return _empty_metadata(module_path, "go", exists=None, flags=[f"Could not fetch Go proxy metadata: {err}"])
    return _empty_metadata(module_path, "go", exists=True, latest_version=data.get("Version"), repository="https://proxy.golang.org")


def get_container_metadata(image: str) -> dict:
    flags = []
    latest = None
    if ":" not in image.rsplit("/", 1)[-1] and "@sha256:" not in image:
        flags.append("Container image is not pinned by tag or digest")
    if "@sha256:" not in image:
        flags.append("Container image is not pinned by immutable digest")
    if ":" in image.rsplit("/", 1)[-1]:
        latest = image.rsplit(":", 1)[1]
    return _empty_metadata(image, "docker", exists=None, latest_version=latest, flags=flags, repository="container-registry")


def get_metadata(package_name: str, ecosystem: str) -> dict:  # type: ignore[override]
    if ecosystem == "npm":
        return get_npm_metadata(package_name)
    if ecosystem == "pip":
        return get_pip_metadata(package_name)
    if ecosystem == "maven":
        return get_maven_metadata(package_name)
    if ecosystem == "nuget":
        return get_nuget_metadata(package_name)
    if ecosystem == "rubygems":
        return get_rubygems_metadata(package_name)
    if ecosystem == "go":
        return get_go_metadata(package_name)
    if ecosystem == "docker":
        return get_container_metadata(package_name)
    if ecosystem in {"github-actions", "terraform"}:
        return _empty_metadata(package_name, ecosystem, exists=None, flags=[f"Registry metadata adapter is limited for {ecosystem}; static policy checks still apply"])
    return _empty_metadata(package_name, ecosystem, exists=None, flags=[f"Unknown ecosystem '{ecosystem}' handled with static checks only"])
