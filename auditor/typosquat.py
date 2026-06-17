"""Typosquatting detection using configurable popular-package lists."""

from __future__ import annotations

import json
import os
import re
from difflib import SequenceMatcher
from pathlib import Path

FALLBACK_NPM_POPULAR = [
    "lodash", "chalk", "react", "express", "axios", "moment", "typescript",
    "webpack", "eslint", "prettier", "jest", "mocha", "nodemon", "dotenv",
    "commander", "inquirer", "yargs", "uuid", "async", "jquery", "vue",
    "next", "vite", "rollup", "esbuild", "semver", "debug", "glob",
]

FALLBACK_PIP_POPULAR = [
    "requests", "numpy", "pandas", "scipy", "matplotlib", "pillow", "flask",
    "django", "fastapi", "sqlalchemy", "celery", "redis", "boto3", "pytest",
    "setuptools", "pip", "wheel", "cryptography", "paramiko", "pydantic",
    "click", "rich", "httpx", "aiohttp", "uvicorn", "gunicorn", "twisted",
    "beautifulsoup4", "selenium", "tensorflow", "torch", "scikit-learn",
    "transformers", "openai", "langchain", "tiktoken", "networkx",
]


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _popular_path() -> Path:
    override = os.getenv("AUDITOR_POPULAR_PACKAGES", "")
    if override:
        return Path(override)
    root_path = _project_root() / "data" / "popular_packages.json"
    if root_path.exists():
        return root_path
    return Path(__file__).resolve().parent / "data" / "popular_packages.json"


def load_popular_packages(ecosystem: str) -> list[str]:
    fallback = FALLBACK_NPM_POPULAR if ecosystem == "npm" else FALLBACK_PIP_POPULAR
    path = _popular_path()
    if not path.exists():
        return fallback
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        values = data.get(ecosystem, [])
        if not isinstance(values, list) or not values:
            return fallback
        cleaned = [str(v).strip().lower() for v in values if str(v).strip()]
        return cleaned or fallback
    except Exception:
        return fallback


def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def similarity_ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def canonical_package_name(name: str, ecosystem: str = "pip") -> str:
    """Return the registry canonical form used for exact-name comparisons.

    PyPI treats hyphen, underscore, and dot runs as equivalent (PEP 503).
    Without this, legitimate packages such as ``charset_normalizer`` can be
    incorrectly flagged as typosquats of ``charset-normalizer``.
    npm does not apply the same normalization, so scoped npm names are only
    lowercased and trimmed.
    """
    lowered = str(name or "").strip().lower()
    if ecosystem == "pip":
        return re.sub(r"[-_.]+", "-", lowered)
    return lowered


def _normalize_substitutions(name: str, ecosystem: str = "pip") -> str:
    normalized = re.sub(r"[0-9]", lambda m: {"0": "o", "1": "l", "3": "e", "5": "s", "7": "t"}.get(m.group(), m.group()), name)
    if ecosystem == "pip":
        # Use canonical separators first, then remove them for homograph checks.
        normalized = canonical_package_name(normalized, ecosystem)
    return normalized.replace("-", "").replace("_", "").replace(".", "")


def check_typosquat(package_name: str, ecosystem: str) -> dict:
    popular = load_popular_packages(ecosystem)
    name = package_name.lower().strip()
    canonical_name = canonical_package_name(name, ecosystem)
    canonical_popular = {canonical_package_name(p, ecosystem): p for p in popular}

    if name in popular or canonical_name in canonical_popular:
        return {
            "is_suspicious": False,
            "closest_match": None,
            "distance": 0,
            "similarity": 1.0,
            "reason": None,
            "popular_list_source": str(_popular_path()) if _popular_path().exists() else "fallback",
        }

    best_match = None
    best_distance = float("inf")
    best_ratio = 0.0

    for pop in popular:
        dist = levenshtein_distance(name, pop)
        ratio = similarity_ratio(name, pop)
        if dist < best_distance or (dist == best_distance and ratio > best_ratio):
            best_distance = dist
            best_match = pop
            best_ratio = ratio

    suspicious = False
    reason = None

    if best_distance == 1:
        suspicious = True
        reason = f"1 character away from popular package '{best_match}' (edit distance: 1)"
    elif best_distance == 2 and len(name) <= 8:
        suspicious = True
        reason = f"2 characters away from short popular package '{best_match}'"
    elif best_ratio > 0.85 and best_distance <= 3:
        suspicious = True
        reason = f"Very similar to '{best_match}' (similarity: {best_ratio:.0%}, distance: {best_distance})"

    if not suspicious:
        normalized = _normalize_substitutions(name, ecosystem)
        for pop in popular:
            pop_norm = _normalize_substitutions(pop, ecosystem)
            # Hyphen/underscore/dot differences are canonical equivalents on PyPI, not typosquats.
            if ecosystem == "pip" and canonical_name == canonical_package_name(pop, ecosystem):
                continue
            if normalized == pop_norm and name != pop:
                suspicious = True
                reason = f"Matches '{pop}' after normalizing number/symbol substitutions"
                best_match = pop
                best_distance = levenshtein_distance(name, pop)
                best_ratio = similarity_ratio(name, pop)
                break

    return {
        "is_suspicious": suspicious,
        "closest_match": best_match,
        "distance": best_distance,
        "similarity": round(best_ratio, 3),
        "reason": reason,
        "popular_list_source": str(_popular_path()) if _popular_path().exists() else "fallback",
    }

_ORIGINAL_CHECK_TYPOSQUAT_V8 = check_typosquat


def check_typosquat(package_name: str, ecosystem: str) -> dict:  # type: ignore[override]
    if ecosystem not in {"npm", "pip"}:
        return {
            "is_suspicious": False,
            "closest_match": None,
            "distance": 0,
            "similarity": 0.0,
            "reason": f"Typosquatting heuristic is not enabled for ecosystem {ecosystem}",
            "popular_list_source": "not-applicable",
        }
    return _ORIGINAL_CHECK_TYPOSQUAT_V8(package_name, ecosystem)
