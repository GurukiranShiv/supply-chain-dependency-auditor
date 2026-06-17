"""
Optional breach/watchlist cross-reference.

Real maintainer-compromise intelligence usually comes from private feeds, GitHub
security advisories, npm incident posts, or organization-owned watchlists. To keep
this portfolio project safe and dependency-free, the auditor supports a local JSON
watchlist instead of querying sensitive breach APIs.

Default file:
  data/compromised_accounts.json

Override with:
  AUDITOR_BREACH_WATCHLIST=C:\\path\\to\\watchlist.json

Supported JSON shape:
{
  "npm": ["publisher-name"],
  "pip": ["maintainer name"],
  "github": ["owner-or-owner/repo"],
  "domains": ["suspicious-domain.example"]
}
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _default_watchlist_path() -> Path:
    return _project_root() / "data" / "compromised_accounts.json"


def _load_watchlist(path: Optional[str] = None) -> dict[str, set[str]]:
    chosen = Path(path or os.getenv("AUDITOR_BREACH_WATCHLIST", "") or _default_watchlist_path())
    empty = {"npm": set(), "pip": set(), "github": set(), "domains": set()}

    if not chosen.exists():
        return empty

    try:
        data = json.loads(chosen.read_text(encoding="utf-8"))
    except Exception:
        return empty

    out = {}
    for key in empty:
        values = data.get(key, [])
        if isinstance(values, list):
            out[key] = {str(v).strip().lower() for v in values if str(v).strip()}
        else:
            out[key] = set()
    return out


def _normalize_identity(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text or text == "unknown":
        return None
    return text


def _github_slug_from_repo_health(maintainer_result: Optional[dict]) -> Optional[str]:
    if not maintainer_result:
        return None
    repo = maintainer_result.get("repository_health", {}) or {}
    slug = repo.get("github_repo")
    return _normalize_identity(slug)


def _github_owner(slug: Optional[str]) -> Optional[str]:
    if not slug or "/" not in slug:
        return slug
    return slug.split("/", 1)[0]


def _domains_from_metadata(metadata: dict) -> set[str]:
    domains = set()
    for key in ("repository", "homepage"):
        value = metadata.get(key)
        if not value:
            continue
        match = re.search(r"(?:https?://|git\+https?://|git@)?([^/:]+)", str(value), re.IGNORECASE)
        if match:
            domain = match.group(1).replace("www.", "").lower()
            if domain and "." in domain:
                domains.add(domain)
    return domains


def check_breach_watchlist(
    package_name: str,
    ecosystem: str,
    metadata: dict,
    maintainer_result: Optional[dict] = None,
    watchlist_path: Optional[str] = None,
) -> dict:
    """
    Cross-reference maintainers, recent npm publishers, GitHub repo owner, and
    linked domains with a local compromised-account/watchlist file.
    """
    watchlist = _load_watchlist(watchlist_path)

    result = {
        "ecosystem": ecosystem,
        "name": package_name,
        "watchlist_loaded": any(watchlist.values()),
        "matches": [],
        "flags": [],
    }

    maintainers = {
        item for item in (_normalize_identity(m) for m in metadata.get("maintainers", [])) if item
    }

    for maintainer in sorted(maintainers):
        if maintainer in watchlist.get(ecosystem, set()):
            result["matches"].append({"type": "maintainer", "value": maintainer})
            result["flags"].append(f"Maintainer '{maintainer}' appears in the local compromised-account watchlist")

    if maintainer_result and ecosystem == "npm":
        recent = maintainer_result.get("recent_publisher_check", {}) or {}
        recent_publishers = {
            item for item in (_normalize_identity(p) for p in recent.get("recent_publishers", [])) if item
        }
        for publisher in sorted(recent_publishers):
            if publisher in watchlist.get("npm", set()):
                result["matches"].append({"type": "recent_npm_publisher", "value": publisher})
                result["flags"].append(f"Recent npm publisher '{publisher}' appears in the local compromised-account watchlist")

    github_slug = _github_slug_from_repo_health(maintainer_result)
    github_owner = _github_owner(github_slug)
    github_watch = watchlist.get("github", set())

    for candidate_type, candidate in (("github_repo", github_slug), ("github_owner", github_owner)):
        if candidate and candidate in github_watch:
            result["matches"].append({"type": candidate_type, "value": candidate})
            result["flags"].append(f"GitHub identity '{candidate}' appears in the local compromised-account watchlist")

    domains = _domains_from_metadata(metadata)
    domain_watch = watchlist.get("domains", set())
    for domain in sorted(domains):
        if domain in domain_watch:
            result["matches"].append({"type": "domain", "value": domain})
            result["flags"].append(f"Linked domain '{domain}' appears in the local suspicious-domain watchlist")

    return result
