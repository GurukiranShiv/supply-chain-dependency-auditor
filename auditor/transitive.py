"""Controlled transitive dependency expansion from registry metadata."""

from __future__ import annotations

from collections import deque

from .registry import get_metadata


def _deps_from_metadata(meta: dict, include_optional: bool = False, include_peer: bool = False) -> list[dict]:
    deps = list(meta.get("dependencies") or [])
    if include_optional:
        deps.extend(meta.get("optional_dependencies") or [])
    if include_peer:
        deps.extend(meta.get("peer_dependencies") or [])
    out = []
    seen = set()
    for dep in deps:
        name = dep.get("name") if isinstance(dep, dict) else None
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(dep)
    return out


def expand_transitive_dependencies(
    packages: list[dict],
    *,
    max_depth: int = 1,
    include_optional: bool = False,
    include_peer: bool = False,
) -> list[dict]:
    """Return original packages plus transitive dependencies discovered from registries.

    max_depth=0 disables expansion. The function is intentionally bounded to avoid
    unexpectedly auditing thousands of packages in a portfolio/demo environment.
    """
    if max_depth <= 0:
        return packages

    output = list(packages)
    seen = {(p.get("ecosystem"), p.get("name", "").lower()) for p in output}
    queue = deque((p, 0) for p in packages)

    while queue:
        pkg, depth = queue.popleft()
        if depth >= max_depth:
            continue
        name = pkg.get("name")
        ecosystem = pkg.get("ecosystem")
        if not name or ecosystem not in {"npm", "pip"}:
            continue

        meta = get_metadata(name, ecosystem)
        if meta.get("exists") is not True:
            continue

        for dep in _deps_from_metadata(meta, include_optional=include_optional, include_peer=include_peer):
            dep_name = dep.get("name")
            key = (ecosystem, dep_name.lower())
            if key in seen:
                continue
            seen.add(key)
            child = {
                "name": dep_name,
                "version": "transitive",
                "ecosystem": ecosystem,
                "dev": bool(pkg.get("dev", False)),
                "source_file": f"registry:{name}",
                "source_type": "transitive-registry",
                "is_lockfile": False,
                "integrity": None,
                "resolved": None,
                "raw_spec": dep.get("version_spec"),
                "hashes": [],
            }
            output.append(child)
            queue.append((child, depth + 1))

    return output
