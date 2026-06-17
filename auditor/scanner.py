"""
Install script scanner.

Downloads npm/PyPI package artifacts and scans only package installation hooks:
- npm package.json install lifecycle scripts: preinstall, install, postinstall, prepare, prepack
- npm referenced local script files used by those hooks
- common npm install hook files such as install.js and postinstall.js
- Python setup.py / setup.cfg / pyproject.toml build files

The goal is to catch suspicious dependency behavior without executing package code.
"""

from __future__ import annotations

import io
import json
import os
import posixpath
import re
import tarfile
import urllib.parse
import zipfile
from typing import Optional

from .http_client import fetch_bytes, fetch_json, sha256_bytes, sha512_bytes, sha512_base64


DANGER_PATTERNS = [
    (r"(requests\.get|requests\.post|urllib\.request\.urlopen|urllib3\.PoolManager|fetch\s*\(|curl\s+|wget\s+|Invoke-WebRequest|iwr\s+)", "Outbound network request"),
    (r"(socket\.connect|socket\.create_connection|net\.connect|new\s+Socket)", "Raw socket connection"),
    (r"(download|fetch|urlopen|requests\.(?:get|post)|curl|wget|Invoke-WebRequest|iwr).{0,120}https?://(?!pypi\.org|files\.pythonhosted\.org|registry\.npmjs\.org|github\.com|raw\.githubusercontent\.com)", "External URL download/call"),
    (r"(subprocess\.run|subprocess\.Popen|os\.system|os\.popen|child_process|execFile|spawn\s*\(|exec\s*\()", "Shell command execution"),
    (r"(eval\s*\(|Function\s*\(|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"])", "Dynamic code execution"),
    (r"__import__\s*\(", "Dynamic import"),
    (r"(process\.env|os\.environ|getenv\s*\().*(AWS_|SECRET|TOKEN|PASSWORD|KEY|GITHUB_TOKEN|NPM_TOKEN)", "Sensitive credential access"),
    (r"(AWS_|SECRET|TOKEN|PASSWORD|GITHUB_TOKEN|NPM_TOKEN|SSH_AUTH_SOCK|\.npmrc)", "Sensitive credential reference"),
    (r"(base64\.(b64decode|decodebytes)|Buffer\.from\s*\([^)]*base64|atob\s*\()", "Base64 decoding"),
    (r"(zlib\.decompress|gzip\.decompress|lzma\.decompress|pako\.inflate|gunzip)", "Compressed payload decompression"),
    (r"(marshal\.loads|pickle\.loads|deserialize)", "Binary payload deserialization"),
    (r"(shutil\.rmtree|os\.remove|os\.unlink|rm\s+-rf|del\s+/f)", "File deletion"),
    (r"(~/?\.ssh|/etc/passwd|/etc/shadow|\.aws/credentials|AppData\\Roaming|\.config/gcloud)", "Sensitive file access"),
    (r"(chmod\s+(\+x|777|666|[0-7]{3,4})|os\.chmod|Path\([^)]*\)\.chmod)", "Permission modification"),
    (r"(chown\s+|os\.chown|sudo\s+|Set-ExecutionPolicy|icacls\s+|takeown\s+)", "Privilege or ownership modification"),
    (r"(crontab|schtasks|systemctl\s+enable|launchctl|Startup|RunOnce|autorun)", "Persistence mechanism"),
]

NPM_INSTALL_HOOKS = {"preinstall", "install", "postinstall", "prepare", "prepack"}
NPM_INSTALL_FILES = {"preinstall.js", "install.js", "postinstall.js"}
# setup.py is executable during legacy Python package builds.
# setup.cfg and pyproject.toml are mostly declarative metadata files; scanning
# them with generic code patterns creates false positives because they commonly
# contain homepage/documentation URLs. We still collect their names as metadata,
# but we do not score plain URLs in them as malicious behavior.
PIP_EXECUTABLE_INSTALL_FILES = {"setup.py"}
PIP_METADATA_FILES = {"setup.cfg", "pyproject.toml"}
IGNORE_DIRS = {"example", "examples", "test", "tests", "docs", "documentation", "benchmark", "benchmarks"}
MAX_FILE_BYTES = 250_000


def _request_bytes(url: str, timeout: int = 20) -> bytes:
    content, error = fetch_bytes(url, timeout=timeout, use_cache=True)
    if error or content is None:
        raise RuntimeError(error.get("detail") if error else "empty response")
    return content



def _looks_like_plain_packaging_metadata(line: str, filename: str) -> bool:
    """Return True for declarative metadata assignments in executable setup.py.

    setup.py is executable, but many mature packages keep static metadata inside
    it, including homepage, documentation, bug tracker, and project_urls. Those
    URL strings do not perform a network request. This helper prevents false
    positives while still allowing real executable calls such as requests.get(),
    urllib.request.urlopen(), curl/wget, subprocess, eval, chmod, etc.
    """
    if not filename.lower().endswith("setup.py"):
        return False
    stripped = line.strip().lower()
    metadata_keys = (
        "url=",
        "download_url=",
        "project_urls=",
        "home_page=",
        "homepage=",
        "documentation",
        "source",
        "tracker",
        "bug",
        "repository",
        "license=",
        "description=",
        "long_description=",
        "author_email=",
    )
    active_network_markers = (
        "requests.",
        "urllib.request",
        "urlopen",
        "urlretrieve",
        "curl ",
        "wget ",
        "invoke-webrequest",
        "iwr ",
        "irm ",
        "subprocess",
        "os.system",
        "os.popen",
        "eval(",
        "exec(",
    )
    if any(marker in stripped for marker in active_network_markers):
        return False
    return any(key in stripped for key in metadata_keys)

def _scan_content(content: str, filename: str) -> list[dict]:
    findings = []
    seen = set()

    for line_no, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        if _looks_like_plain_packaging_metadata(line, filename):
            continue

        for pattern, description in DANGER_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                key = (filename, line_no, description, stripped[:120])
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "file": filename,
                    "line": line_no,
                    "description": description,
                    "snippet": stripped[:160],
                })

    return findings


def _scan_script_command(command: str, location: str) -> list[dict]:
    """Scan a package.json lifecycle command string as if it were executable code."""
    return _scan_content(command, location)


def _scan_python_metadata_file(content: str, filename: str) -> list[dict]:
    """
    Scan declarative Python packaging metadata with a stricter rule set.

    pyproject.toml and setup.cfg often contain normal homepage, repository,
    issue-tracker, and documentation URLs. Those URLs are not install-time
    behavior by themselves, so this function only flags unusual build-system
    and command-hook patterns that can indicate risky install behavior.
    """
    findings = []
    patterns = [
        (r"cmdclass\s*=", "Custom setup command hook"),
        (r"setup_requires\s*=.*(http|https|git\+|svn\+)", "Dynamic setup-time dependency source"),
        (r"build-backend\s*=\s*[\"'][^\"']*(unknown|custom|hook|download|install)[^\"']*[\"']", "Unusual Python build backend"),
        # Intentionally do NOT flag ordinary pyproject/setup.cfg script entries.
        # Modern projects legitimately declare console scripts, tox/hatch scripts,
        # benchmark helpers, and documentation commands in metadata. Install-time
        # behavior is still checked through setup.py and actual artifact files.
        (r"(chmod\s+|chown\s+|sudo\s+|Set-ExecutionPolicy|icacls\s+|takeown\s+)", "Privilege or permission behavior in packaging metadata"),
    ]

    seen = set()
    for line_no, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        for pattern, description in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                key = (filename, line_no, description, stripped[:120])
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "file": filename,
                    "line": line_no,
                    "description": description,
                    "snippet": stripped[:160],
                })
    return findings


def _should_ignore(path: str) -> bool:
    parts = [p.lower() for p in re.split(r"[/\\]+", path)]
    return any(part in IGNORE_DIRS for part in parts)


def _safe_member_text_from_tar(tar: tarfile.TarFile, member: tarfile.TarInfo) -> Optional[str]:
    if not member.isfile() or member.size > MAX_FILE_BYTES:
        return None
    extracted = tar.extractfile(member)
    if not extracted:
        return None
    return extracted.read(MAX_FILE_BYTES + 1).decode("utf-8", errors="replace")


def _safe_member_text_from_zip(zf: zipfile.ZipFile, name: str) -> Optional[str]:
    info = zf.getinfo(name)
    if info.file_size > MAX_FILE_BYTES:
        return None
    return zf.read(name).decode("utf-8", errors="replace")


def _strip_tar_root(path: str) -> str:
    """Convert package/foo/bar.js to foo/bar.js for easier matching."""
    normalized = path.replace("\\", "/").lstrip("/")
    parts = normalized.split("/")
    if len(parts) > 1 and parts[0] in {"package", "dist", "src"}:
        return "/".join(parts[1:])
    return normalized


def _normalize_relative(base_dir: str, target: str) -> str:
    target = target.strip().strip("'\"")
    target = target.split("?")[0]
    if not target:
        return ""
    if target.startswith("./") or target.startswith("../"):
        return posixpath.normpath(posixpath.join(base_dir, target))
    return posixpath.normpath(target)


def _extract_referenced_script_paths(command: str, package_json_path: str) -> set[str]:
    """Find likely local script files referenced by npm install hooks."""
    base_dir = posixpath.dirname(_strip_tar_root(package_json_path))
    if base_dir == ".":
        base_dir = ""

    refs = set()

    # node scripts/postinstall.js, bash ./install.sh, python setup.py
    command_patterns = [
        r"(?:node|npm\s+run|bash|sh|python|python3|pwsh|powershell)\s+([^;&|\s]+)",
        r"([^;&|\s]+\.(?:js|mjs|cjs|sh|bash|ps1|py))",
    ]

    for pattern in command_patterns:
        for match in re.finditer(pattern, command, re.IGNORECASE):
            candidate = match.group(1).strip().strip("'\"")
            if candidate.startswith("-") or candidate.startswith("http"):
                continue
            if any(candidate.endswith(ext) for ext in (".js", ".mjs", ".cjs", ".sh", ".bash", ".ps1", ".py")):
                refs.add(_normalize_relative(base_dir, candidate))

    return {ref for ref in refs if ref and not ref.startswith("..")}


def _get_npm_tarball_url(package_name: str) -> Optional[str]:
    try:
        url = "https://registry.npmjs.org/" + urllib.parse.quote(package_name, safe="@")
        data = fetch_json(url, timeout=10)
        latest = data.get("dist-tags", {}).get("latest")
        return data.get("versions", {}).get(latest, {}).get("dist", {}).get("tarball")
    except Exception:
        return None


def _get_pip_artifact_url(package_name: str) -> Optional[str]:
    try:
        url = f"https://pypi.org/pypi/{urllib.parse.quote(package_name)}/json"
        data = fetch_json(url, timeout=10)
        urls = data.get("urls", []) or []

        # Prefer source distributions because setup.py is usually only present there.
        for item in urls:
            if item.get("packagetype") == "sdist" and item.get("url"):
                return item["url"]

        # Fall back to wheel if no sdist is available.
        for item in urls:
            if item.get("url"):
                return item["url"]
    except Exception:
        return None

    return None


def scan_npm_package(package_name: str) -> dict:
    result = {
        "ecosystem": "npm",
        "name": package_name,
        "scanned_files": [],
        "install_scripts": [],
        "findings": [],
        "error": None,
        "artifact_url": None,
        "artifact_sha256": None,
        "artifact_sha512": None,
        "artifact_sha512_base64": None,
    }

    tarball_url = _get_npm_tarball_url(package_name)
    if not tarball_url:
        result["error"] = "Could not resolve npm tarball URL"
        return result

    try:
        raw = _request_bytes(tarball_url, timeout=20)
        result["artifact_url"] = tarball_url
        result["artifact_sha256"] = sha256_bytes(raw)
        result["artifact_sha512"] = sha512_bytes(raw)
        result["artifact_sha512_base64"] = sha512_base64(raw)

        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
            members = [m for m in tar.getmembers() if m.isfile()]
            normalized_to_member = {_strip_tar_root(m.name): m for m in members}
            package_json_members = [m for m in members if os.path.basename(m.name) == "package.json" and not _should_ignore(m.name)]
            referenced_paths = set()

            for member in package_json_members:
                content = _safe_member_text_from_tar(tar, member)
                if content is None:
                    continue

                result["scanned_files"].append(member.name)
                try:
                    pkg = json.loads(content)
                except json.JSONDecodeError:
                    result["findings"].append({
                        "file": member.name,
                        "line": None,
                        "description": "Unreadable package.json",
                        "snippet": "package.json could not be parsed as JSON",
                    })
                    continue

                scripts = pkg.get("scripts", {}) or {}
                if isinstance(scripts, dict):
                    for hook in sorted(NPM_INSTALL_HOOKS):
                        command = scripts.get(hook)
                        if not isinstance(command, str) or not command.strip():
                            continue

                        location = f"{member.name}:scripts.{hook}"
                        result["install_scripts"].append({"hook": hook, "command": command})
                        result["findings"].extend(_scan_script_command(command, location))
                        referenced_paths.update(_extract_referenced_script_paths(command, member.name))

            # Always scan common install hook files.
            for member in members:
                basename = os.path.basename(member.name)
                normalized = _strip_tar_root(member.name)

                should_scan = basename in NPM_INSTALL_FILES or normalized in referenced_paths
                if not should_scan or _should_ignore(member.name):
                    continue

                content = _safe_member_text_from_tar(tar, member)
                if content is None:
                    continue

                if member.name not in result["scanned_files"]:
                    result["scanned_files"].append(member.name)
                result["findings"].extend(_scan_content(content, member.name))

    except Exception as exc:
        result["error"] = str(exc)

    return result


def scan_pip_package(package_name: str) -> dict:
    result = {
        "ecosystem": "pip",
        "name": package_name,
        "scanned_files": [],
        "install_scripts": [],
        "findings": [],
        "error": None,
        "artifact_url": None,
        "artifact_sha256": None,
        "artifact_sha512": None,
        "artifact_sha512_base64": None,
    }

    artifact_url = _get_pip_artifact_url(package_name)
    if not artifact_url:
        result["error"] = "Could not resolve PyPI artifact URL"
        return result

    try:
        raw = _request_bytes(artifact_url, timeout=20)
        result["artifact_url"] = artifact_url
        result["artifact_sha256"] = sha256_bytes(raw)
        result["artifact_sha512"] = sha512_bytes(raw)
        result["artifact_sha512_base64"] = sha512_base64(raw)

        if artifact_url.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip")):
            if artifact_url.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                    for name in zf.namelist():
                        basename = os.path.basename(name)
                        if basename not in PIP_EXECUTABLE_INSTALL_FILES and basename not in PIP_METADATA_FILES:
                            continue
                        if _should_ignore(name):
                            continue
                        content = _safe_member_text_from_zip(zf, name)
                        if content is None:
                            continue
                        result["scanned_files"].append(name)
                        if basename in PIP_EXECUTABLE_INSTALL_FILES:
                            result["findings"].extend(_scan_content(content, name))
                        else:
                            result["findings"].extend(_scan_python_metadata_file(content, name))
            else:
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tar:
                    for member in tar.getmembers():
                        basename = os.path.basename(member.name)
                        if basename not in PIP_EXECUTABLE_INSTALL_FILES and basename not in PIP_METADATA_FILES:
                            continue
                        if _should_ignore(member.name):
                            continue
                        content = _safe_member_text_from_tar(tar, member)
                        if content is None:
                            continue
                        result["scanned_files"].append(member.name)
                        if basename in PIP_EXECUTABLE_INSTALL_FILES:
                            result["findings"].extend(_scan_content(content, member.name))
                        else:
                            result["findings"].extend(_scan_python_metadata_file(content, member.name))

        elif artifact_url.endswith((".whl", ".zip")):
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                for name in zf.namelist():
                    basename = os.path.basename(name)
                    if basename not in PIP_EXECUTABLE_INSTALL_FILES and basename not in PIP_METADATA_FILES:
                        continue
                    if _should_ignore(name):
                        continue
                    content = _safe_member_text_from_zip(zf, name)
                    if content is None:
                        continue
                    result["scanned_files"].append(name)
                    if basename in PIP_EXECUTABLE_INSTALL_FILES:
                        result["findings"].extend(_scan_content(content, name))
                    else:
                        result["findings"].extend(_scan_python_metadata_file(content, name))

    except Exception as exc:
        result["error"] = str(exc)

    return result


def scan_package(package_name: str, ecosystem: str) -> dict:
    if ecosystem == "npm":
        return scan_npm_package(package_name)
    if ecosystem == "pip":
        return scan_pip_package(package_name)

    # V8.1: non artifact registries such as GitHub Actions, Dockerfile image
    # references, Terraform modules, Maven coordinates, etc. are handled by
    # ecosystem-specific static policy/CI scanners. They should not crash the
    # package artifact scanner.
    return {
        "ecosystem": ecosystem,
        "name": package_name,
        "scanned_files": [],
        "install_scripts": [],
        "findings": [],
        "error": None,
        "artifact_url": None,
        "artifact_sha256": None,
        "artifact_sha512": None,
        "artifact_sha512_base64": None,
        "skipped": True,
        "skip_reason": f"Artifact scanning is not implemented for {ecosystem}; handled by static ecosystem checks",
    }
