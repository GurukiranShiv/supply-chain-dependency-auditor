"""Exact resolver integration for V8.

Registry metadata is useful, but enterprise dependency review must also know what
package managers would actually install. This module invokes native resolvers in
safe/dry-run modes when available and falls back cleanly when tools are absent.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

from .lockfile import detect_and_parse, parse_package_lock

Runner = Callable[..., subprocess.CompletedProcess]


def _run(cmd: list[str], *, cwd: str | None = None, timeout: int = 90, runner: Runner | None = None) -> subprocess.CompletedProcess:
    runner = runner or subprocess.run
    return runner(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout)


def _pkg(name: str, version: str, ecosystem: str, source_file: str, source_type: str = "exact-resolver") -> dict:
    return {
        "name": name,
        "version": version or "unknown",
        "ecosystem": ecosystem,
        "dev": False,
        "source_file": source_file,
        "source_type": source_type,
        "is_lockfile": True,
        "integrity": None,
        "resolved": None,
        "raw_spec": version or "unknown",
        "hashes": [],
    }


def resolve_pip_exact(project_path: str, *, runner: Runner | None = None) -> tuple[list[dict], list[str]]:
    root = Path(project_path)
    req = root / "requirements.txt"
    if not req.exists():
        return [], ["No requirements.txt found for exact pip resolution"]
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tmp:
        report_path = tmp.name
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--dry-run",
        "--ignore-installed",
        "--disable-pip-version-check",
        "--no-input",
        "--report",
        report_path,
        "-r",
        str(req),
    ]
    warnings: list[str] = []
    try:
        proc = _run(cmd, cwd=str(root), runner=runner, timeout=120)
        if proc.returncode != 0:
            return [], ["pip exact resolver failed: " + ((proc.stderr or proc.stdout or "").strip()[:800])]
        data = json.loads(Path(report_path).read_text(encoding="utf-8"))
        packages = []
        for item in data.get("install", []) or []:
            meta = item.get("metadata") or {}
            name = meta.get("name")
            version = meta.get("version")
            if name:
                packages.append(_pkg(name, version, "pip", "pip --dry-run --report"))
        return packages, warnings
    except Exception as exc:
        return [], [f"pip exact resolver could not run: {exc}"]
    finally:
        try:
            os.remove(report_path)
        except OSError:
            pass


def resolve_npm_exact(project_path: str, *, runner: Runner | None = None) -> tuple[list[dict], list[str]]:
    root = Path(project_path)
    package_json = root / "package.json"
    if not package_json.exists():
        return [], ["No package.json found for exact npm resolution"]
    with tempfile.TemporaryDirectory(prefix="scda-npm-resolve-") as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "package.json").write_text(package_json.read_text(encoding="utf-8"), encoding="utf-8")
        cmd = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
        try:
            proc = _run(cmd, cwd=str(tmp), runner=runner, timeout=120)
            if proc.returncode != 0:
                return [], ["npm exact resolver failed: " + ((proc.stderr or proc.stdout or "").strip()[:800])]
            lock = tmp / "package-lock.json"
            if not lock.exists():
                return [], ["npm did not produce package-lock.json"]
            return parse_package_lock(str(lock)), []
        except FileNotFoundError:
            return [], ["npm is not installed or not on PATH"]
        except Exception as exc:
            return [], [f"npm exact resolver could not run: {exc}"]


def resolve_go_exact(project_path: str, *, runner: Runner | None = None) -> tuple[list[dict], list[str]]:
    root = Path(project_path)
    if not (root / "go.mod").exists():
        return [], ["No go.mod found for exact Go module resolution"]
    try:
        proc = _run(["go", "list", "-m", "-json", "all"], cwd=str(root), runner=runner, timeout=90)
        if proc.returncode != 0:
            return [], ["go exact resolver failed: " + ((proc.stderr or proc.stdout or "").strip()[:800])]
        packages = []
        # go list -json all outputs concatenated JSON objects.
        decoder = json.JSONDecoder()
        text = proc.stdout.strip()
        idx = 0
        while idx < len(text):
            while idx < len(text) and text[idx].isspace():
                idx += 1
            obj, idx = decoder.raw_decode(text, idx)
            if obj.get("Path") and obj.get("Version"):
                packages.append(_pkg(obj["Path"], obj.get("Version"), "go", "go list -m -json all"))
        return packages, []
    except FileNotFoundError:
        return [], ["go is not installed or not on PATH"]
    except Exception as exc:
        return [], [f"go exact resolver could not run: {exc}"]


def exact_resolve_project(project_path: str, *, runner: Runner | None = None) -> tuple[list[dict], list[str]]:
    """Resolve dependencies with native package-manager tooling when possible."""
    packages: list[dict] = []
    warnings: list[str] = []
    for resolver in (resolve_pip_exact, resolve_npm_exact, resolve_go_exact):
        pkgs, warn = resolver(project_path, runner=runner)
        packages.extend(pkgs)
        warnings.extend(warn)
    # Use lockfile parsers as a fallback for ecosystems without installed toolchains.
    if not packages:
        root = Path(project_path)
        for child in root.iterdir() if root.is_dir() else []:
            parsed = detect_and_parse(str(child))
            if parsed:
                packages.extend(parsed)
        if packages:
            warnings.append("Exact resolver produced no output; used static manifest parsing fallback")
    # Deduplicate exact resolver output.
    seen = set()
    unique = []
    for pkg in packages:
        key = (pkg.get("ecosystem"), str(pkg.get("name", "")).lower(), pkg.get("version"))
        if key not in seen:
            seen.add(key)
            unique.append(pkg)
    return unique, warnings
