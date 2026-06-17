"""Optional dynamic sandbox analysis.

The auditor is safe-by-default and does not execute packages during normal scans.
When --sandbox is enabled, it uses Docker (if installed) to run an isolated,
resource-limited install attempt. This provides behavioral evidence without
exposing the analyst's host secrets.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

Runner = Callable[..., subprocess.CompletedProcess]

SUSPICIOUS_RUNTIME_PATTERNS = [
    ("network", ["http://", "https://", "curl", "wget", "Invoke-WebRequest", "socket"]),
    ("credential_access", ["AWS_SECRET", "GITHUB_TOKEN", ".npmrc", ".pypirc", "id_rsa", "credentials"]),
    ("persistence", ["crontab", "systemctl", "schtasks", "LaunchAgents", "Startup"]),
    ("shell_exec", ["/bin/sh", "powershell", "cmd.exe", "bash -c"]),
]


def _run(cmd: list[str], *, timeout: int = 120, runner: Runner | None = None) -> subprocess.CompletedProcess:
    runner = runner or subprocess.run
    return runner(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout)


def _docker_available(runner: Runner | None = None) -> bool:
    if runner is None and not shutil.which("docker"):
        return False
    try:
        proc = _run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=15, runner=runner)
        return proc.returncode == 0
    except Exception:
        return False


def _detect_runtime_findings(output: str) -> list[dict]:
    findings = []
    lowered = output.lower()
    for category, needles in SUSPICIOUS_RUNTIME_PATTERNS:
        for needle in needles:
            if needle.lower() in lowered:
                findings.append({
                    "severity": "HIGH" if category in {"credential_access", "persistence"} else "MEDIUM",
                    "category": "Dynamic sandbox",
                    "description": f"Runtime output referenced {category}: {needle}",
                    "evidence": needle,
                })
                break
    return findings


def sandbox_package(package_name: str, ecosystem: str, version: str | None = None, *, runner: Runner | None = None, network: str = "none") -> dict:
    """Run an isolated install attempt for one package.

    Docker is required. With network=none, package installation normally fails
    unless the package is cached/mounted, but the command path still proves the
    sandbox is configured safely. Teams can use network=bridge in a throwaway CI
    worker to observe live install behavior.
    """
    result = {
        "package": package_name,
        "ecosystem": ecosystem,
        "executed": False,
        "ok": None,
        "engine": "docker",
        "network": network,
        "findings": [],
        "warnings": [],
        "command": None,
        "output_excerpt": "",
    }
    if ecosystem not in {"pip", "npm"}:
        result["warnings"].append(f"Dynamic sandbox is currently implemented for pip/npm, not {ecosystem}")
        return result
    if not _docker_available(runner):
        result["warnings"].append("Docker is not installed/running; dynamic sandbox analysis was skipped")
        return result

    pkg_spec = package_name
    if version and version not in {"unknown", "unpinned", "transitive"}:
        pkg_spec = f"{package_name}=={version}" if ecosystem == "pip" else f"{package_name}@{version}"

    if ecosystem == "pip":
        image = "python:3.12-slim"
        inner = f"python -m pip install --no-input --disable-pip-version-check {pkg_spec}"
    else:
        image = "node:22-alpine"
        inner = f"npm install --ignore-scripts=false --no-audit --no-fund {pkg_spec}"

    with tempfile.TemporaryDirectory(prefix="scda-sandbox-") as tmp:
        Path(tmp, "empty").write_text("", encoding="utf-8")
        cmd = [
            "docker", "run", "--rm",
            "--network", network,
            "--cap-drop", "ALL",
            "--pids-limit", "128",
            "--memory", "512m",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
            "-v", f"{tmp}:/work:rw",
            "-w", "/work",
            image,
            "sh", "-lc", inner,
        ]
        result["command"] = cmd
        try:
            proc = _run(cmd, timeout=150, runner=runner)
            combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            result["executed"] = True
            result["ok"] = proc.returncode == 0
            result["output_excerpt"] = combined[:4000]
            result["findings"] = _detect_runtime_findings(combined)
        except Exception as exc:
            result["warnings"].append(f"Dynamic sandbox execution failed: {exc}")
    return result


def export_sandbox_results(results: list[dict], path: str) -> None:
    Path(path).write_text(json.dumps({"sandbox_results": results}, indent=2), encoding="utf-8")
