"""
Maintainer takeover and repository health checks.
"""

import re
from datetime import datetime, timezone
from typing import Optional

from .http_client import fetch_json


def _fetch_json(url: str, timeout: int = 10) -> Optional[dict]:
    data = fetch_json(url, timeout=timeout)
    if not data or data.get("__error__"):
        return None
    return data


def _age_days(iso_date: Optional[str]) -> Optional[int]:
    if not iso_date:
        return None

    try:
        dt = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def normalize_github_repo(repo_url: Optional[str]) -> Optional[str]:
    if not repo_url:
        return None

    repo_url = repo_url.strip().replace("git+", "")

    patterns = [
        r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/#?]+)",
        r"github\.com/(?P<owner>[^/]+)/(?P<repo>[^/#?]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, repo_url)

        if match:
            repo = match.group("repo").replace(".git", "")
            return f"{match.group('owner')}/{repo}"

    return None


def _github_repo_health(repo_url: Optional[str]) -> dict:
    result = {
        "repository": repo_url,
        "github_repo": None,
        "repo_age_days": None,
        "last_push_days": None,
        "open_issues": None,
        "stars": None,
        "archived": None,
        "fork": None,
        "flags": [],
    }

    slug = normalize_github_repo(repo_url)
    result["github_repo"] = slug

    if not slug:
        result["flags"].append("No GitHub repository could be verified")
        return result

    data = _fetch_json(f"https://api.github.com/repos/{slug}")

    if not data or data.get("message") == "Not Found":
        result["flags"].append("Linked GitHub repository could not be resolved")
        return result

    result["repo_age_days"] = _age_days(data.get("created_at"))
    result["last_push_days"] = _age_days(data.get("pushed_at"))
    result["open_issues"] = data.get("open_issues_count")
    result["stars"] = data.get("stargazers_count") or 0
    result["archived"] = data.get("archived")
    result["fork"] = data.get("fork")

    if result["archived"]:
        result["flags"].append("Linked repository is archived")

    if result["repo_age_days"] is not None and result["repo_age_days"] < 30:
        result["flags"].append(f"Linked repository is very new ({result['repo_age_days']} days old)")

    if result["last_push_days"] is not None and result["last_push_days"] > 1095:
        result["flags"].append(f"Repository has not been updated in {result['last_push_days']} days")

    if result["stars"] == 0:
        result["flags"].append("Repository has no GitHub stars")

    return result


def _npm_recent_maintainer_churn(package_name: str) -> dict:
    out = {
        "recent_publishers": [],
        "flags": [],
    }

    data = _fetch_json(f"https://registry.npmjs.org/{package_name}")

    if not data:
        return out

    versions = data.get("versions", {})
    time_info = data.get("time", {})

    dated_versions = []

    for version, meta in versions.items():
        timestamp = time_info.get(version)

        if not timestamp:
            continue

        publisher = meta.get("_npmUser", {}).get("name")
        dated_versions.append((timestamp, version, publisher))

    dated_versions.sort(reverse=True)

    recent_users = [user for _, _, user in dated_versions[:5] if user]
    out["recent_publishers"] = list(dict.fromkeys(recent_users))

    maintainers = [
        maintainer.get("name")
        for maintainer in data.get("maintainers", [])
        if isinstance(maintainer, dict)
    ]

    new_publishers = [
        user for user in out["recent_publishers"]
        if user not in maintainers
    ]

    if new_publishers:
        out["flags"].append("Recent publisher is not listed in current maintainers")

    if len(set(out["recent_publishers"])) >= 3:
        out["flags"].append("Several different accounts published recent versions")

    return out


def check_maintainer_takeover(package_name: str, ecosystem: str, metadata: dict) -> dict:
    repo_health = _github_repo_health(metadata.get("repository"))

    maintainers = metadata.get("maintainers", [])
    maintainer_count = len(maintainers)

    weekly_downloads = metadata.get("weekly_downloads") or 0
    monthly_downloads = metadata.get("monthly_downloads") or 0
    downloads = max(weekly_downloads, monthly_downloads)

    stars = repo_health.get("stars") or 0

    result = {
        "ecosystem": ecosystem,
        "name": package_name,
        "repository_health": repo_health,
        "maintainer_count": maintainer_count,
        "flags": [],
    }

    if maintainer_count == 0:
        if downloads < 10000 and stars < 100:
            result["flags"].append("No maintainers were listed in registry metadata")

    elif maintainer_count == 1:
        if downloads < 10000 and stars < 100:
            result["flags"].append("Single maintainer package creates takeover risk")

    result["flags"].extend(repo_health.get("flags", []))

    if ecosystem == "npm":
        churn = _npm_recent_maintainer_churn(package_name)
        result["recent_publisher_check"] = churn
        result["flags"].extend(churn.get("flags", []))

    return result