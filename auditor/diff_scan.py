"""Baseline and diff-aware dependency scanning helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def package_key(pkg: dict) -> str:
    return f"{pkg.get('ecosystem')}:{str(pkg.get('name', '')).lower()}"


def build_baseline(packages: list[dict]) -> dict:
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "packages": {
            package_key(pkg): {
                "name": pkg.get("name"),
                "ecosystem": pkg.get("ecosystem"),
                "version": pkg.get("version"),
                "source_file": pkg.get("source_file"),
                "source_type": pkg.get("source_type"),
            }
            for pkg in packages
        },
    }


def save_baseline(packages: list[dict], path: str) -> None:
    Path(path).write_text(json.dumps(build_baseline(packages), indent=2), encoding="utf-8")


def load_baseline(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def diff_packages(packages: list[dict], baseline_path: str) -> dict:
    baseline = load_baseline(baseline_path)
    previous = baseline.get("packages", {}) or {}
    added = []
    changed = []
    unchanged = []

    for pkg in packages:
        key = package_key(pkg)
        old = previous.get(key)
        if not old:
            added.append(pkg)
            continue
        if str(old.get("version")) != str(pkg.get("version")):
            changed.append(pkg)
        else:
            unchanged.append(pkg)

    previous_keys = set(previous)
    current_keys = {package_key(pkg) for pkg in packages}
    removed = sorted(previous_keys - current_keys)

    return {
        "added": added,
        "changed": changed,
        "unchanged": unchanged,
        "removed": removed,
        "baseline_created_at": baseline.get("created_at"),
    }
