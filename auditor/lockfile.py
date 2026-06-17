"""
Dependency file parser.

Extracts package names, versions, dependency scope, and integrity/hash metadata
from common npm and Python files:
- package-lock.json
- package.json
- yarn.lock
- requirements*.txt
- Pipfile.lock
- pyproject.toml

The parser is lightweight and uses only the standard library.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except Exception:  # pragma: no cover
    tomllib = None


def _add_package(
    packages: list[dict],
    name: str,
    version: str,
    ecosystem: str,
    dev: bool = False,
    *,
    source_file: Optional[str] = None,
    source_type: str = "direct",
    is_lockfile: bool = False,
    integrity: Optional[str] = None,
    resolved: Optional[str] = None,
    raw_spec: Optional[str] = None,
    hashes: Optional[list[str]] = None,
) -> None:
    clean_name = (name or "").strip()
    if not clean_name:
        return
    packages.append({
        "name": clean_name,
        "version": version or "unknown",
        "ecosystem": ecosystem,
        "dev": dev,
        "source_file": source_file,
        "source_type": source_type,
        "is_lockfile": is_lockfile,
        "integrity": integrity,
        "resolved": resolved,
        "raw_spec": raw_spec,
        "hashes": hashes or [],
    })


def _root_dependency_names(package_lock_data: dict) -> set[str]:
    root = (package_lock_data.get("packages", {}) or {}).get("", {}) or {}
    names = set()
    for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
        deps = root.get(section, {}) or {}
        if isinstance(deps, dict):
            names.update(deps.keys())
    return names


def parse_package_lock(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        root_direct = _root_dependency_names(data)
        pkgs = data.get("packages", {}) or {}
        for pkg_path, info in pkgs.items():
            if not pkg_path:
                continue
            marker = "node_modules/"
            if marker not in pkg_path:
                continue
            name = pkg_path.split(marker)[-1]
            if not name or name.startswith("."):
                continue
            source_type = "direct" if name in root_direct else "transitive"
            _add_package(
                packages,
                name,
                str(info.get("version", "unknown")),
                "npm",
                bool(info.get("dev", False)),
                source_file=source,
                source_type=source_type,
                is_lockfile=True,
                integrity=info.get("integrity"),
                resolved=info.get("resolved"),
                raw_spec=str(info.get("version", "unknown")),
            )

        if not packages:
            deps = data.get("dependencies", {}) or {}
            for name, info in deps.items():
                if isinstance(info, dict):
                    _add_package(
                        packages,
                        name,
                        str(info.get("version", "unknown")),
                        "npm",
                        bool(info.get("dev", False)),
                        source_file=source,
                        source_type="direct",
                        is_lockfile=True,
                        integrity=info.get("integrity"),
                        resolved=info.get("resolved"),
                        raw_spec=str(info.get("version", "unknown")),
                    )
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def parse_package_json(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        sections = [
            ("dependencies", False),
            ("optionalDependencies", False),
            ("peerDependencies", False),
            ("devDependencies", True),
        ]
        for section, is_dev in sections:
            deps = data.get(section, {}) or {}
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                # package.json records version ranges, not a resolved lock.
                version = str(spec)
                _add_package(
                    packages,
                    name,
                    version,
                    "npm",
                    is_dev,
                    source_file=source,
                    source_type="direct",
                    is_lockfile=False,
                    raw_spec=version,
                )
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def _yarn_name_from_header(header: str) -> Optional[str]:
    header = header.strip().strip('"')
    first = header.split(",", 1)[0].strip().strip('"')
    if "@npm:" in first:
        first = first.split("@npm:", 1)[1]
    if first.startswith("@"):
        parts = first.split("@")
        if len(parts) >= 3:
            return "@" + parts[1]
        return None
    if "@" in first:
        return first.rsplit("@", 1)[0]
    return None


def parse_yarn_lock(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        blocks = re.split(r"\n(?=\S)", content)
        for block in blocks:
            if block.startswith("#") or not block.strip():
                continue
            header = block.split("\n", 1)[0]
            name = _yarn_name_from_header(header)
            version_match = re.search(r'^\s+version\s+"?([^"\n]+)"?', block, re.MULTILINE)
            integrity_match = re.search(r'^\s+integrity\s+([^\n]+)', block, re.MULTILINE)
            resolved_match = re.search(r'^\s+resolved\s+"?([^"\n]+)"?', block, re.MULTILINE)
            if name and version_match:
                _add_package(
                    packages,
                    name,
                    version_match.group(1).strip(),
                    "npm",
                    False,
                    source_file=source,
                    source_type="transitive",
                    is_lockfile=True,
                    integrity=integrity_match.group(1).strip() if integrity_match else None,
                    resolved=resolved_match.group(1).strip() if resolved_match else None,
                    raw_spec=header,
                )
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def _extract_requirement_hashes(line: str) -> list[str]:
    return re.findall(r"--hash\s*=\s*(sha256:[A-Fa-f0-9]{64})", line)


def parse_requirements_txt(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        is_dev = "dev" in source.lower() or "test" in source.lower()

        for raw_line in lines:
            original = raw_line.strip()
            line = original
            if not line or line.startswith("#") or line.startswith("-r") or line.startswith("--"):
                continue
            if line.startswith(("git+", "http://", "https://")):
                continue

            hashes = _extract_requirement_hashes(line)
            clean = line.split("#", 1)[0].split(";", 1)[0].strip()
            clean = re.sub(r"\s+--hash\s*=\s*sha256:[A-Fa-f0-9]{64}", "", clean)

            match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:\[.*?\])?\s*([><=!~]+\s*[^,\s]+)?", clean)
            if not match:
                continue

            name = match.group(1).strip()
            exact = re.search(r"==\s*([^,\s]+)", clean)
            version = exact.group(1) if exact else "unpinned"
            _add_package(
                packages,
                name,
                version,
                "pip",
                is_dev,
                source_file=source,
                source_type="direct",
                is_lockfile=False,
                raw_spec=original,
                hashes=hashes,
            )
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def parse_pipfile_lock(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section, is_dev in (("default", False), ("develop", True)):
            for name, info in (data.get(section, {}) or {}).items():
                if isinstance(info, dict):
                    version = str(info.get("version", "unknown")).lstrip("=")
                    hashes = [h if str(h).startswith("sha256:") else f"sha256:{h}" for h in info.get("hashes", [])]
                else:
                    version = str(info).lstrip("=")
                    hashes = []
                _add_package(
                    packages,
                    name,
                    version,
                    "pip",
                    is_dev,
                    source_file=source,
                    source_type="direct",
                    is_lockfile=True,
                    raw_spec=str(info),
                    hashes=hashes,
                )
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def _parse_pep621_dependencies(data: dict, source: str) -> list[dict]:
    packages: list[dict] = []
    project = data.get("project", {}) or {}

    for dep in project.get("dependencies", []) or []:
        match = re.match(r"^([A-Za-z0-9_.\-]+)", str(dep).strip())
        if match:
            _add_package(packages, match.group(1), "unpinned", "pip", False, source_file=source, raw_spec=str(dep))

    optional = project.get("optional-dependencies", {}) or {}
    if isinstance(optional, dict):
        for deps in optional.values():
            for dep in deps or []:
                match = re.match(r"^([A-Za-z0-9_.\-]+)", str(dep).strip())
                if match:
                    _add_package(packages, match.group(1), "unpinned", "pip", True, source_file=source, raw_spec=str(dep))
    return packages


def _parse_poetry_dependencies(data: dict, source: str) -> list[dict]:
    packages: list[dict] = []
    poetry = ((data.get("tool", {}) or {}).get("poetry", {}) or {})
    deps = poetry.get("dependencies", {}) or {}
    if isinstance(deps, dict):
        for name, spec in deps.items():
            if name.lower() == "python":
                continue
            version = str(spec)
            exact = version if re.match(r"^[0-9][^*<>=~^]*$", version) else "unpinned"
            _add_package(packages, name, exact, "pip", False, source_file=source, raw_spec=version)

    groups = poetry.get("group", {}) or {}
    if isinstance(groups, dict):
        for group in groups.values():
            group_deps = (group or {}).get("dependencies", {}) or {}
            if isinstance(group_deps, dict):
                for name, spec in group_deps.items():
                    _add_package(packages, name, "unpinned", "pip", True, source_file=source, raw_spec=str(spec))
    return packages


def parse_pyproject_toml(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        if tomllib:
            with open(path, "rb") as f:
                data = tomllib.load(f)
            packages.extend(_parse_pep621_dependencies(data, source))
            packages.extend(_parse_poetry_dependencies(data, source))
        else:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            in_deps = False
            for line in content.splitlines():
                if re.match(r"\[tool\.poetry\.dependencies\]|\[project\]", line):
                    in_deps = True
                    continue
                if line.startswith("[") and in_deps:
                    in_deps = False
                if in_deps:
                    match = re.match(r"^([A-Za-z0-9_.\-]+)\s*=", line)
                    if match and match.group(1).lower() not in {"python", "name", "version", "description"}:
                        _add_package(packages, match.group(1), "unpinned", "pip", False, source_file=source, raw_spec=line)
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def detect_and_parse(path: str) -> Optional[list[dict]]:
    basename = os.path.basename(path)
    if basename == "package-lock.json":
        return parse_package_lock(path)
    if basename == "package.json":
        return parse_package_json(path)
    if basename == "yarn.lock":
        return parse_yarn_lock(path)
    if basename == "Pipfile.lock":
        return parse_pipfile_lock(path)
    if basename == "pyproject.toml":
        return parse_pyproject_toml(path)
    if "requirements" in basename and basename.endswith(".txt"):
        return parse_requirements_txt(path)
    return None


SUPPORTED_FILES = [
    "package-lock.json",
    "package.json",
    "yarn.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "Pipfile.lock",
    "pyproject.toml",
]

# ---------------------------------------------------------------------------
# V8 multi-ecosystem parsers
# ---------------------------------------------------------------------------
# These lightweight parsers extend the auditor beyond npm/PyPI manifests. They
# intentionally extract direct dependency coordinates without trying to replace
# native ecosystem resolvers. Use --resolver exact where toolchain-level
# resolution is required.

import xml.etree.ElementTree as _ET


def _strip_xml_ns(tag: str) -> str:
    return tag.rsplit('}', 1)[-1] if '}' in tag else tag


def parse_pom_xml(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        root = _ET.parse(path).getroot()
        for dep in root.iter():
            if _strip_xml_ns(dep.tag) != 'dependency':
                continue
            vals = {}
            for child in list(dep):
                vals[_strip_xml_ns(child.tag)] = (child.text or '').strip()
            group = vals.get('groupId')
            artifact = vals.get('artifactId')
            if not group or not artifact:
                continue
            scope = vals.get('scope', '')
            _add_package(
                packages,
                f'{group}:{artifact}',
                vals.get('version') or 'unpinned',
                'maven',
                dev=scope in {'test', 'provided'},
                source_file=source,
                source_type='direct',
                raw_spec=json.dumps(vals, sort_keys=True),
            )
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def parse_gradle_file(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        content = Path(path).read_text(encoding='utf-8')
        # Handles implementation 'g:a:v', testImplementation("g:a:v"), api group: 'g', name: 'a', version: 'v'
        for match in re.finditer(r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s*\(?\s*[\"']([^:\"']+):([^:\"']+):([^\"']+)[\"']", content):
            group, artifact, version = match.groups()
            dev = match.group(0).startswith('test')
            _add_package(packages, f'{group}:{artifact}', version, 'maven', dev=dev, source_file=source, raw_spec=match.group(0))
        for match in re.finditer(r"(?:implementation|api|testImplementation)\s+group:\s*[\"']([^\"']+)[\"'],\s*name:\s*[\"']([^\"']+)[\"'],\s*version:\s*[\"']([^\"']+)[\"']", content):
            group, artifact, version = match.groups()
            dev = match.group(0).startswith('test')
            _add_package(packages, f'{group}:{artifact}', version, 'maven', dev=dev, source_file=source, raw_spec=match.group(0))
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def parse_go_mod(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        content = Path(path).read_text(encoding='utf-8')
        in_block = False
        for raw in content.splitlines():
            line = raw.split('//', 1)[0].strip()
            if not line:
                continue
            if line.startswith('require ('):
                in_block = True
                continue
            if in_block and line == ')':
                in_block = False
                continue
            if line.startswith('require '):
                line = line[len('require '):].strip()
            if in_block or raw.strip().startswith('require '):
                parts = line.split()
                if len(parts) >= 2 and re.match(r'^[\w.\-/]+$', parts[0]):
                    _add_package(packages, parts[0], parts[1], 'go', source_file=source, raw_spec=raw.strip())
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def parse_packages_lock_json(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        data = json.load(open(path, 'r', encoding='utf-8'))
        deps = data.get('dependencies', {}) or {}
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            _add_package(
                packages,
                name,
                str(info.get('resolved') or info.get('version') or 'unknown'),
                'nuget',
                dev=bool(info.get('type') == 'Project'),
                source_file=source,
                source_type='direct' if str(info.get('type', '')).lower() == 'direct' else 'transitive',
                is_lockfile=True,
                raw_spec=json.dumps(info, sort_keys=True),
            )
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def parse_csproj(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        root = _ET.parse(path).getroot()
        for node in root.iter():
            if _strip_xml_ns(node.tag) != 'PackageReference':
                continue
            name = node.attrib.get('Include') or node.attrib.get('Update')
            version = node.attrib.get('Version') or 'unpinned'
            for child in list(node):
                if _strip_xml_ns(child.tag) == 'Version' and child.text:
                    version = child.text.strip()
            if name:
                _add_package(packages, name, version, 'nuget', source_file=source, raw_spec=str(node.attrib))
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def parse_gemfile_lock(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        content = Path(path).read_text(encoding='utf-8').splitlines()
        in_specs = False
        for raw in content:
            if raw.strip() == 'GEM':
                continue
            if raw.strip() == 'specs:':
                in_specs = True
                continue
            if in_specs and raw and not raw.startswith(' '):
                in_specs = False
            if in_specs:
                m = re.match(r'\s{4}([A-Za-z0-9_.\-]+) \(([^)]+)\)', raw)
                if m:
                    _add_package(packages, m.group(1), m.group(2), 'rubygems', source_file=source, source_type='transitive', is_lockfile=True, raw_spec=raw.strip())
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def parse_dockerfile(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        for raw in Path(path).read_text(encoding='utf-8').splitlines():
            m = re.match(r'\s*FROM\s+([^\s]+)', raw, re.IGNORECASE)
            if not m:
                continue
            image = m.group(1)
            if image.lower() == 'scratch':
                continue
            name, version = image, 'latest'
            if '@sha256:' in image:
                name, digest = image.split('@sha256:', 1)
                version = 'sha256:' + digest
            elif ':' in image.rsplit('/', 1)[-1]:
                name, version = image.rsplit(':', 1)
            _add_package(packages, name, version, 'docker', source_file=source, source_type='base-image', raw_spec=raw.strip(), integrity=version if version.startswith('sha256:') else None)
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def parse_github_workflow(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        text = Path(path).read_text(encoding='utf-8')
        for m in re.finditer(r'uses:\s*([^\s#]+)', text):
            spec = m.group(1).strip().strip('"\'')
            if '@' in spec:
                name, version = spec.rsplit('@', 1)
            else:
                name, version = spec, 'unpinned'
            _add_package(packages, name, version, 'github-actions', source_file=source, source_type='workflow-action', raw_spec=spec)
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


def parse_terraform_file(path: str) -> list[dict]:
    packages: list[dict] = []
    source = os.path.basename(path)
    try:
        text = Path(path).read_text(encoding='utf-8')
        for block in re.finditer(r'required_providers\s*{(?P<body>.*?)\n\s*}', text, re.DOTALL):
            for provider in re.finditer(r'(\w+)\s*=\s*{(?P<body>.*?)}', block.group('body'), re.DOTALL):
                body = provider.group('body')
                src = re.search(r'source\s*=\s*["\']([^"\']+)', body)
                ver = re.search(r'version\s*=\s*["\']([^"\']+)', body)
                if src:
                    _add_package(packages, src.group(1), ver.group(1) if ver else 'unpinned', 'terraform', source_file=source, raw_spec=provider.group(0))
        for mod in re.finditer(r'module\s+["\'][^"\']+["\']\s*{(?P<body>.*?)}', text, re.DOTALL):
            body = mod.group('body')
            src = re.search(r'source\s*=\s*["\']([^"\']+)', body)
            ver = re.search(r'version\s*=\s*["\']([^"\']+)', body)
            if src:
                _add_package(packages, src.group(1), ver.group(1) if ver else 'unpinned', 'terraform', source_file=source, source_type='module', raw_spec=mod.group(0)[:300])
    except Exception as exc:
        print(f"  Warning: Could not parse {path}: {exc}")
    return packages


_ORIGINAL_DETECT_AND_PARSE_V8 = detect_and_parse


def detect_and_parse(path: str) -> Optional[list[dict]]:  # type: ignore[override]
    basename = os.path.basename(path)
    lower = basename.lower()
    if lower == 'pom.xml':
        return parse_pom_xml(path)
    if lower in {'build.gradle', 'build.gradle.kts'}:
        return parse_gradle_file(path)
    if lower == 'go.mod':
        return parse_go_mod(path)
    if lower == 'packages.lock.json':
        return parse_packages_lock_json(path)
    if lower.endswith('.csproj'):
        return parse_csproj(path)
    if lower == 'gemfile.lock':
        return parse_gemfile_lock(path)
    if lower == 'dockerfile' or lower.startswith('dockerfile.'):
        return parse_dockerfile(path)
    if lower.endswith(('.yml', '.yaml')) and ('.github' in path.replace('\\', '/') or 'workflow' in lower):
        return parse_github_workflow(path)
    if lower.endswith('.tf'):
        return parse_terraform_file(path)
    return _ORIGINAL_DETECT_AND_PARSE_V8(path)


SUPPORTED_FILES = [
    'package-lock.json', 'package.json', 'yarn.lock',
    'requirements.txt', 'requirements-dev.txt', 'requirements-test.txt', 'Pipfile.lock', 'pyproject.toml',
    'pom.xml', 'build.gradle', 'build.gradle.kts', 'go.mod', 'packages.lock.json', '*.csproj', 'Gemfile.lock',
    'Dockerfile', '.github/workflows/*.yml', '.github/workflows/*.yaml', '*.tf',
]
