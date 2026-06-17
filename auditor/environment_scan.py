"""Scan the actual installed dependency environment.

This module complements lockfile parsing. Lockfiles show what a project *claims*
it will install; environment scans show what is actually present in a running
Python/npm environment.

Supported sources:
- Python: `python -m pip inspect --local` for dependency relationships, with
  `python -m pip list --format=json` fallback.
- npm: `npm ls --all --json --long` from the supplied project directory.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def _run_json(command: list[str], *, cwd: str | None = None, timeout: int = 45) -> tuple[dict | list | None, str | None]:
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return None, f"Command not found: {command[0]}"
    except subprocess.TimeoutExpired:
        return None, f"Command timed out: {' '.join(command)}"
    except Exception as exc:  # pragma: no cover - defensive
        return None, str(exc)

    output = (proc.stdout or "").strip()
    if not output:
        return None, (proc.stderr or f"Command returned no JSON: {' '.join(command)}").strip()
    try:
        return json.loads(output), None
    except json.JSONDecodeError as exc:
        # Some tools/plugins print banners or warnings around JSON. Try to salvage
        # the first complete JSON object/array before falling back.
        starts = [i for i in (output.find("{"), output.find("[")) if i != -1]
        if starts:
            start = min(starts)
            end_obj = output.rfind("}")
            end_arr = output.rfind("]")
            end = max(end_obj, end_arr)
            if end > start:
                candidate = output[start:end + 1]
                try:
                    return json.loads(candidate), None
                except json.JSONDecodeError:
                    pass
        return None, f"Could not parse JSON from {' '.join(command)}: {exc}"


def _parse_pip_inspect(data: dict) -> list[dict]:
    packages: list[dict] = []
    installed = data.get("installed", []) if isinstance(data, dict) else []
    for entry in installed or []:
        metadata = entry.get("metadata", {}) or {}
        name = metadata.get("name") or entry.get("name")
        version = metadata.get("version") or entry.get("version") or "unknown"
        if not name:
            continue
        direct_url = entry.get("direct_url")
        requested = bool(entry.get("requested", False))
        packages.append({
            "name": str(name),
            "version": str(version),
            "ecosystem": "pip",
            "dev": False,
            "source_file": "pip inspect --local",
            "source_type": "environment-direct" if requested else "environment-transitive",
            "is_lockfile": False,
            "integrity": None,
            "resolved": str(direct_url) if direct_url else None,
            "raw_spec": str(version),
            "hashes": [],
        })
    return packages


def _parse_pip_list(data: list) -> list[dict]:
    packages: list[dict] = []
    for entry in data or []:
        name = entry.get("name")
        if not name:
            continue
        packages.append({
            "name": str(name),
            "version": str(entry.get("version", "unknown")),
            "ecosystem": "pip",
            "dev": False,
            "source_file": "pip list --format=json",
            "source_type": "environment",
            "is_lockfile": False,
            "integrity": None,
            "resolved": None,
            "raw_spec": str(entry.get("version", "unknown")),
            "hashes": [],
        })
    return packages


def scan_python_environment(python_executable: str | None = None) -> tuple[list[dict], list[str]]:
    """Return installed Python packages and warnings."""
    exe = python_executable or sys.executable
    warnings: list[str] = []

    data, inspect_err = _run_json([exe, "-m", "pip", "inspect", "--local"], timeout=60)
    if isinstance(data, dict):
        return _parse_pip_inspect(data), warnings

    data, list_err = _run_json([exe, "-m", "pip", "list", "--format=json"], timeout=60)
    if isinstance(data, list):
        # pip list is an acceptable fallback, so do not warn unless verbose/debug
        # support is added later. This keeps environment scans clean.
        return _parse_pip_list(data), warnings
    if inspect_err:
        warnings.append(inspect_err)
    if list_err:
        warnings.append(list_err)
    return [], warnings


def _walk_npm_tree(node: dict, *, root_name: str | None = None, direct_names: set[str] | None = None, seen: set[tuple[str, str]] | None = None) -> list[dict]:
    direct_names = direct_names or set()
    seen = seen or set()
    out: list[dict] = []
    deps = node.get("dependencies", {}) or {}
    if not isinstance(deps, dict):
        return out

    for name, info in deps.items():
        if not isinstance(info, dict):
            continue
        version = str(info.get("version", "unknown"))
        key = (name.lower(), version)
        if key not in seen:
            seen.add(key)
            out.append({
                "name": str(name),
                "version": version,
                "ecosystem": "npm",
                "dev": bool(info.get("dev", False)),
                "source_file": "npm ls --all --json --long",
                "source_type": "environment-direct" if name in direct_names else "environment-transitive",
                "is_lockfile": False,
                "integrity": info.get("integrity"),
                "resolved": info.get("resolved"),
                "raw_spec": version,
                "hashes": [],
            })
        out.extend(_walk_npm_tree(info, root_name=root_name, direct_names=set(), seen=seen))
    return out


def scan_npm_environment(project_path: str | os.PathLike[str]) -> tuple[list[dict], list[str]]:
    """Return packages from node_modules using npm ls."""
    project = Path(project_path)
    warnings: list[str] = []
    if not (project / "package.json").exists() and not (project / "node_modules").exists():
        return [], ["No package.json or node_modules directory found for npm environment scan"]

    data, err = _run_json(["npm", "ls", "--all", "--json", "--long"], cwd=str(project), timeout=90)
    if not isinstance(data, dict):
        return [], [err or "npm ls did not return JSON"]

    direct_names = set()
    root_deps = (data.get("dependencies", {}) or {})
    if isinstance(root_deps, dict):
        direct_names.update(root_deps.keys())
    return _walk_npm_tree(data, root_name=data.get("name"), direct_names=direct_names), warnings


def scan_environment(project_path: str | os.PathLike[str] = ".", *, python_executable: str | None = None, include_npm: bool = True) -> tuple[list[dict], list[str]]:
    """Scan installed Python and npm environments."""
    packages: list[dict] = []
    warnings: list[str] = []

    py_pkgs, py_warn = scan_python_environment(python_executable)
    packages.extend(py_pkgs)
    warnings.extend(py_warn)

    if include_npm:
        npm_pkgs, npm_warn = scan_npm_environment(project_path)
        packages.extend(npm_pkgs)
        warnings.extend(npm_warn)

    return packages, warnings
