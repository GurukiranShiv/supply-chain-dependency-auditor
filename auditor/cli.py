#!/usr/bin/env python3
"""
Supply Chain Dependency Auditor — CLI

Examples:
  python cli.py scan requests --ecosystem pip
  python cli.py audit test-project --json results.json --html report.html --sbom sbom.json
  python cli.py audit . --transitive-depth 1 --baseline baseline.json --diff-only
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from auditor.api_server import serve as serve_api  # noqa: E402

from auditor import (  # noqa: E402
    __version__,
    RiskReport,
    SUPPORTED_FILES,
    append_policy_audit_log,
    apply_fixes,
    build_remediation,
    check_breach_watchlist,
    check_dependency_policy,
    check_license_compliance,
    check_maintainer_takeover,
    check_osv,
    check_provenance,
    check_typosquat,
    detect_and_parse,
    diff_packages,
    create_branch_commit_push,
    evaluate_policy,
    export_fix_result,
    export_policy_result,
    export_remediation_plan,
    exact_resolve_project,
    sandbox_package,
    export_sandbox_results,
    audit_github_actions,
    export_ci_hardening,
    load_owner_map,
    build_sla_report,
    export_jira_import,
    create_evidence_bundle,
    export_sarif,
    expand_transitive_dependencies,
    export_cyclonedx,
    export_html,
    generate_explanation,
    load_policy,
    load_remediation_plan,
    open_github_pr,
    plan_fixes,
    get_metadata,
    save_baseline,
    validate_project_after_fix,
    scan_environment,
    scan_malware,
    scan_package,
    score_package,
)

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
WHITE = "\033[97m"


def colored(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{RESET}"


def bold(text: str) -> str:
    return colored(text, BOLD)


LEVEL_COLORS = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN, "SAFE": GREEN, "INFO": DIM}
SEV_ICONS = {"CRITICAL": "✖", "HIGH": "✖", "MEDIUM": "⚠", "LOW": "●", "SAFE": "✔", "INFO": "·", "UNKNOWN": "?"}


def _version_for_osv(requested_version: Optional[str], latest_version: Optional[str]) -> Optional[str]:
    if requested_version and requested_version not in {"unknown", "unpinned", "transitive"}:
        return requested_version
    return latest_version


def audit_package(
    name: str,
    ecosystem: str,
    version: Optional[str] = None,
    *,
    package_info: Optional[dict] = None,
    skip_scan: bool = False,
    skip_policy: bool = False,
    license_policy_path: Optional[str] = None,
    provenance_policy_path: Optional[str] = None,
    no_malware: bool = False,
    use_sandbox: bool = False,
    sandbox_network: str = "none",
) -> RiskReport:
    """Run all checks on a package and return a RiskReport."""

    print(f"  {colored('→', CYAN)} Checking registry metadata...")
    meta = get_metadata(name, ecosystem)

    print(f"  {colored('→', CYAN)} Checking for typosquatting...")
    typo = check_typosquat(name, ecosystem)

    print(f"  {colored('→', CYAN)} Querying OSV vulnerability database...")
    osv = check_osv(name, ecosystem, _version_for_osv(version, meta.get("latest_version")))

    print(f"  {colored('→', CYAN)} Checking maintainer/repository takeover signals...")
    maintainer = check_maintainer_takeover(name, ecosystem, meta)

    print(f"  {colored('→', CYAN)} Cross-referencing breach/watchlist data...")
    breach = check_breach_watchlist(name, ecosystem, meta, maintainer)

    scan = {"findings": [], "scanned_files": [], "error": None, "artifact_sha256": None, "artifact_sha512": None, "artifact_sha512_base64": None, "artifact_url": None}
    if not skip_scan:
        print(f"  {colored('→', CYAN)} Scanning install scripts and package artifact...")
        scan = scan_package(name, ecosystem)
        if scan.get("error"):
            print(f"  {colored('⚠ Scan warning:', YELLOW)} {scan['error']}")

    malware = {"findings": [], "iocs": [], "secrets": [], "binary_files": [], "error": None}
    if not no_malware:
        print(f"  {colored('→', CYAN)} Running static malware, secret, IOC, and binary analysis...")
        malware = scan_malware(name, ecosystem)
        if malware.get("error"):
            print(f"  {colored('⚠ Malware analysis warning:', YELLOW)} {malware['error']}")

    sandbox = None
    if use_sandbox:
        print(f"  {colored('→', CYAN)} Running optional dynamic sandbox analysis...")
        sandbox = sandbox_package(name, ecosystem, version, network=sandbox_network)
        for warning in sandbox.get("warnings", [])[:2]:
            print(f"  {colored('⚠ Sandbox warning:', YELLOW)} {warning}")

    print(f"  {colored('→', CYAN)} Verifying artifact integrity/provenance signals...")
    provenance = check_provenance(name, ecosystem, version, scan, meta, provenance_policy_path=provenance_policy_path)

    license_result = None
    dependency_policy = None
    if not skip_policy:
        print(f"  {colored('→', CYAN)} Checking license, pinning, lockfile, and integrity policy...")
        license_result = check_license_compliance(name, ecosystem, meta, license_policy_path)
        if package_info:
            dependency_policy = check_dependency_policy(package_info, scan)

    report = score_package(
        typo,
        meta,
        scan,
        osv,
        maintainer,
        breach,
        requested_version=version,
        license_result=license_result,
        dependency_policy_result=dependency_policy,
        provenance_result=provenance,
        malware_result=malware,
        sandbox_result=sandbox,
    )
    report.remediation = build_remediation(report)
    report.ai_explanation = generate_explanation(report)
    return report


def print_report(report: RiskReport, verbose: bool = False) -> None:
    level_color = LEVEL_COLORS.get(report.risk_level, WHITE)
    icon = SEV_ICONS.get(report.risk_level, "?")

    print()
    print(bold(f"  Package: {report.package}") + f"  ({report.ecosystem})" + (f"  v{report.version}" if report.version else ""))
    print(f"  Risk score: {colored(str(report.risk_score) + '/100', level_color)}  Level: {colored(bold(report.risk_level), level_color)}")
    print(f"  {colored(icon, level_color)} {report.recommendation}")

    if report.signals:
        print()
        print(f"  {bold('Signals detected:')}")
        for sig in report.signals:
            sev = sig.get("severity", "INFO")
            sev_color = LEVEL_COLORS.get(sev, DIM)
            sev_icon = SEV_ICONS.get(sev, "·")
            print(f"    {colored(sev_icon, sev_color)} {colored(f'[{sev}]', sev_color)} {bold(sig.get('category', 'Signal'))}: {sig.get('detail', '')}")
            if verbose and sig.get("snippet"):
                print(f"        {DIM}Code: {sig['snippet'][:140]}{RESET}")
            if verbose and sig.get("references"):
                for ref in sig["references"][:3]:
                    print(f"        {DIM}→ {ref}{RESET}")


def print_summary_table(reports: list[RiskReport]) -> None:
    print()
    print(bold("  ── Audit Summary ──────────────────────────────────────"))
    print(f"  {'Package':<35} {'Ecosystem':<8} {'Score':>5}  {'Risk Level':<10}")
    print(f"  {'─' * 35} {'─' * 8} {'─' * 5}  {'─' * 10}")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
    for r in sorted(reports, key=lambda x: -x.risk_score):
        color = LEVEL_COLORS.get(r.risk_level, WHITE)
        print(f"  {r.package[:34]:<35} {r.ecosystem:<8} {colored(str(r.risk_score).rjust(5), color)}  {colored(r.risk_level, color)}")
        counts[r.risk_level] = counts.get(r.risk_level, 0) + 1

    print()
    total = len(reports)
    print(f"  Scanned {bold(str(total))} package(s)  |  " + "  ".join(f"{colored(k, LEVEL_COLORS[k])}: {v}" for k, v in counts.items() if v > 0))

    critical_high = [r for r in reports if r.risk_level in ("CRITICAL", "HIGH")]
    if critical_high:
        print()
        print(colored(f"  ✖ {len(critical_high)} package(s) need immediate attention:", RED))
        for r in critical_high:
            print(f"    - {r.package} ({r.ecosystem}): {r.recommendation}")


def export_json(reports: list[RiskReport], path: str) -> None:
    data = []
    for r in reports:
        data.append({
            "package": r.package,
            "ecosystem": r.ecosystem,
            "version": r.version,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "recommendation": r.recommendation,
            "signals": r.signals,
            "typosquat": r.typosquat,
            "metadata": r.metadata,
            "scan": r.scan,
            "vulnerabilities": r.vulns,
            "maintainer": r.maintainer,
            "breach": r.breach,
            "license": r.license,
            "dependency_policy": r.dependency_policy,
            "provenance": getattr(r, "provenance", None),
            "malware": getattr(r, "malware", None),
            "sandbox": getattr(r, "sandbox", None),
            "remediation": getattr(r, "remediation", None),
            "policy_decision": getattr(r, "policy_decision", None),
            "ai_explanation": getattr(r, "ai_explanation", None),
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"\n  {colored('✔', GREEN)} Report saved to {bold(path)}")


def print_policy_summary(policy_result: dict) -> None:
    summary = policy_result.get("summary", {}) or {}
    blocked = summary.get("block", 0)
    warned = summary.get("warn", 0)
    allowed = summary.get("allow", 0)
    print()
    print(bold("  ── Policy-as-Code Summary ─────────────────────────"))
    print(f"  Blocked: {colored(str(blocked), RED if blocked else GREEN)}  Warned: {colored(str(warned), YELLOW if warned else GREEN)}  Allowed: {colored(str(allowed), GREEN)}")
    important = [d for d in policy_result.get("decisions", []) if d.get("action") in {"block", "warn"}]
    for decision in important[:12]:
        color = RED if decision.get("action") == "block" else YELLOW
        reasons = "; ".join(decision.get("reasons", [])[:2]) or "Policy rule matched"
        print(f"    - {colored(decision.get('action', '').upper(), color)} {decision.get('package')} ({decision.get('ecosystem')}): {reasons}")


def maybe_apply_policy(reports: list[RiskReport], args) -> Optional[dict]:
    mode = getattr(args, "policy_mode", "off")
    policy_path = getattr(args, "policy", None)
    if mode == "off" and not policy_path:
        return None
    policy = load_policy(policy_path)
    policy_result = evaluate_policy(reports, policy)
    print_policy_summary(policy_result)
    policy_report = getattr(args, "policy_report", None)
    if policy_report:
        export_policy_result(policy_result, policy_report)
        print(f"\n  {colored('✔', GREEN)} Policy report saved to {bold(policy_report)}")
    policy_audit_log = getattr(args, "policy_audit_log", None)
    if policy_audit_log:
        append_policy_audit_log(policy_result, policy_audit_log)
        print(f"\n  {colored('✔', GREEN)} Policy audit log appended to {bold(policy_audit_log)}")
    return policy_result


def _discover_files(path: str) -> list[str]:
    if not os.path.isdir(path):
        return [path]
    root = Path(path)
    found: list[str] = []
    exact_names = {
        "package-lock.json", "package.json", "yarn.lock", "requirements.txt", "requirements-dev.txt",
        "requirements-test.txt", "Pipfile.lock", "pyproject.toml", "pom.xml", "build.gradle",
        "build.gradle.kts", "go.mod", "packages.lock.json", "Gemfile.lock", "Dockerfile",
    }
    for child in root.rglob("*"):
        if not child.is_file():
            continue
        rel = child.relative_to(root).as_posix()
        name = child.name
        lower = name.lower()
        if any(part in {".git", "node_modules", ".venv", "venv", "__pycache__", ".auditor-cache"} for part in child.relative_to(root).parts):
            continue
        if name in exact_names or lower.endswith(".csproj") or lower.endswith(".tf"):
            found.append(str(child))
        elif rel.startswith(".github/workflows/") and lower.endswith((".yml", ".yaml")):
            found.append(str(child))
    # Stable order keeps reports deterministic.
    return sorted(dict.fromkeys(found))

def _dedupe_packages(packages: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for p in packages:
        key = (p.get("name", "").lower(), p.get("ecosystem"))
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def _parse_packages_from_path(path: str, no_dev: bool) -> tuple[list[dict], list[str]]:
    files = _discover_files(path)
    if not files:
        return [], []

    all_packages = []
    for fpath in files:
        pkgs = detect_and_parse(fpath)
        if pkgs is None:
            print(colored(f"  Cannot parse '{fpath}' — unsupported format.", YELLOW))
            continue
        if no_dev:
            pkgs = [p for p in pkgs if not p.get("dev", False)]
        print(f"  Parsed {bold(str(len(pkgs)))} packages from {os.path.basename(fpath)}")
        all_packages.extend(pkgs)
    return all_packages, files


def cmd_scan(args) -> int:
    eco = args.ecosystem or "npm"
    if not args.ecosystem:
        print(f"  {colored('ℹ', CYAN)} No ecosystem specified, defaulting to npm. Use --ecosystem pip for Python packages.")

    print(bold(f"\n  Auditing {args.package} ({eco})"))
    print(f"  {'─' * 50}")

    package_info = {
        "name": args.package,
        "ecosystem": eco,
        "version": args.version or "unknown",
        "source_file": "cli",
        "source_type": "direct",
        "is_lockfile": False,
        "raw_spec": args.version or "unknown",
        "hashes": [],
    }
    report = audit_package(
        args.package,
        eco,
        version=args.version,
        package_info=package_info,
        skip_scan=args.no_scan,
        skip_policy=args.no_policy,
        license_policy_path=args.license_policy,
        provenance_policy_path=getattr(args, "provenance_policy", None),
        no_malware=getattr(args, "no_malware", False),
        use_sandbox=getattr(args, "sandbox", False),
        sandbox_network=getattr(args, "sandbox_network", "none"),
    )
    print_report(report, verbose=args.verbose)

    policy_result = maybe_apply_policy([report], args)

    if args.json:
        export_json([report], args.json)
    if args.html:
        export_html([report], args.html)
        print(f"\n  {colored('✔', GREEN)} HTML report saved to {bold(args.html)}")
    if args.sbom:
        export_cyclonedx([report], args.sbom)
        print(f"\n  {colored('✔', GREEN)} CycloneDX SBOM saved to {bold(args.sbom)}")
    if args.sarif:
        export_sarif([report], args.sarif)
        print(f"\n  {colored('✔', GREEN)} SARIF report saved to {bold(args.sarif)}")
    if args.remediation:
        export_remediation_plan([report], args.remediation)
        print(f"\n  {colored('✔', GREEN)} Remediation plan saved to {bold(args.remediation)}")

    print()
    policy_blocks = 0
    if policy_result and getattr(args, "policy_mode", "off") == "enforce":
        policy_blocks = int((policy_result.get("summary") or {}).get("block", 0) or 0)
    return 0 if report.risk_level in ("SAFE", "LOW") and policy_blocks == 0 else 1


def cmd_audit(args) -> int:
    path = args.path
    files = _discover_files(path)
    if os.path.isdir(path):
        if not files and not args.environment:
            print(colored(f"\n  No supported dependency files found in '{path}'.", YELLOW))
            print(f"  Supported: {', '.join(SUPPORTED_FILES)}")
            return 1
        if files:
            print(f"\n  Found {len(files)} dependency file(s): {', '.join(os.path.basename(f) for f in files)}")

    if args.environment:
        print("\n  Scanning actual installed environment (pip inspect/list + npm ls when available)...")
        packages, env_warnings = scan_environment(path, include_npm=not args.no_npm_environment)
        for warning in env_warnings:
            print(colored(f"  ⚠ Environment warning: {warning}", YELLOW))
    else:
        packages, parsed_files = _parse_packages_from_path(path, args.no_dev)

    if not packages:
        print(colored("  No packages found to audit.", YELLOW))
        return 1

    direct_count = len(packages)
    packages = _dedupe_packages(packages)

    if (not args.environment) and args.transitive_depth > 0:
        before = len(packages)
        print(f"\n  Expanding transitive dependencies to depth {args.transitive_depth}...")
        packages = expand_transitive_dependencies(
            packages,
            max_depth=args.transitive_depth,
            include_optional=args.include_optional,
            include_peer=args.include_peer,
        )
        packages = _dedupe_packages(packages)
        added = len(packages) - before
        print(f"  Added {bold(str(max(added, 0)))} transitive package(s)")

    if args.baseline:
        diff = diff_packages(packages, args.baseline)
        print(
            f"\n  Diff-aware scan: {len(diff['added'])} added, {len(diff['changed'])} changed, "
            f"{len(diff['unchanged'])} unchanged, {len(diff['removed'])} removed"
        )
        if args.diff_only:
            packages = diff["added"] + diff["changed"]
            print(f"  Auditing only {bold(str(len(packages)))} added/changed package(s)")

    if args.save_baseline:
        save_baseline(packages, args.save_baseline)
        print(f"\n  {colored('✔', GREEN)} Baseline saved to {bold(args.save_baseline)}")

    if not packages:
        print(colored("  No added/changed packages to audit.", GREEN))
        return 0

    print(f"\n  Auditing {bold(str(len(packages)))} unique package(s) from {direct_count} parsed entries...\n")

    reports: list[RiskReport] = []
    max_workers = min(max(args.workers, 1), len(packages))

    def audit_one(pkg: dict) -> Optional[RiskReport]:
        name, eco, ver = pkg["name"], pkg["ecosystem"], pkg.get("version")
        src = pkg.get("source_type", "direct")
        print(f"  {colored('▸', CYAN)} {name} ({eco}, {src})")
        try:
            return audit_package(
                name,
                eco,
                version=ver,
                package_info=pkg,
                skip_scan=args.no_scan,
                skip_policy=args.no_policy,
                license_policy_path=args.license_policy,
                provenance_policy_path=getattr(args, "provenance_policy", None),
                no_malware=getattr(args, "no_malware", False),
                use_sandbox=getattr(args, "sandbox", False),
                sandbox_network=getattr(args, "sandbox_network", "none"),
            )
        except Exception as exc:
            print(f"  {colored('✖', RED)} Error auditing {name}: {exc}")
            return None

    if max_workers > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(audit_one, pkg): pkg for pkg in packages}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    reports.append(result)
    else:
        for pkg in packages:
            result = audit_one(pkg)
            if result:
                reports.append(result)

    flagged = [r for r in reports if r.risk_level in ("CRITICAL", "HIGH", "MEDIUM")]
    if flagged and args.verbose:
        print(bold("\n  ── Flagged Packages ───────────────────────────────"))
        for r in flagged:
            print_report(r, verbose=args.verbose)

    print_summary_table(reports)

    policy_result = maybe_apply_policy(reports, args)

    ci_result = None
    if getattr(args, "ci_hardening_report", None):
        ci_result = audit_github_actions(path)
        export_ci_hardening(ci_result, args.ci_hardening_report)
        print(f"\n  {colored('✔', GREEN)} CI/CD hardening report saved to {bold(args.ci_hardening_report)}")

    sandbox_results = []
    if getattr(args, "sandbox_report", None):
        for r in reports:
            if getattr(r, "sandbox", None):
                sandbox_results.append(r.sandbox)
        export_sandbox_results(sandbox_results, args.sandbox_report)
        print(f"\n  {colored('✔', GREEN)} Sandbox report saved to {bold(args.sandbox_report)}")

    if getattr(args, "sla_report", None) or getattr(args, "jira_export", None):
        owner_map = load_owner_map(getattr(args, "owner_map", None))
        sla = build_sla_report(reports, owner_map)
        if getattr(args, "sla_report", None):
            with open(args.sla_report, "w", encoding="utf-8") as f:
                json.dump(sla, f, indent=2)
            print(f"\n  {colored('✔', GREEN)} SLA/owner report saved to {bold(args.sla_report)}")
        if getattr(args, "jira_export", None):
            export_jira_import(sla, args.jira_export)
            print(f"\n  {colored('✔', GREEN)} Jira/ServiceNow import CSV saved to {bold(args.jira_export)}")

    if getattr(args, "evidence_bundle", None):
        create_evidence_bundle(reports=reports, policy_result=policy_result, ci_result=ci_result, sandbox_results=sandbox_results, path=args.evidence_bundle)
        print(f"\n  {colored('✔', GREEN)} Enterprise evidence bundle saved to {bold(args.evidence_bundle)}")

    if args.json:
        export_json(reports, args.json)
    if args.html:
        export_html(reports, args.html, ci_result=ci_result)
        print(f"\n  {colored('✔', GREEN)} HTML report saved to {bold(args.html)}")
    if args.sbom:
        export_cyclonedx(reports, args.sbom)
        print(f"\n  {colored('✔', GREEN)} CycloneDX SBOM saved to {bold(args.sbom)}")
    if args.sarif:
        export_sarif(reports, args.sarif)
        print(f"\n  {colored('✔', GREEN)} SARIF report saved to {bold(args.sarif)}")
    if args.remediation:
        export_remediation_plan(reports, args.remediation)
        print(f"\n  {colored('✔', GREEN)} Remediation plan saved to {bold(args.remediation)}")

    policy_blocks = 0
    if policy_result and getattr(args, "policy_mode", "off") == "enforce":
        policy_blocks = int((policy_result.get("summary") or {}).get("block", 0) or 0)
    critical_count = sum(1 for r in reports if r.risk_level in ("CRITICAL", "HIGH"))
    return 1 if critical_count > 0 or policy_blocks > 0 else 0


def cmd_fix(args) -> int:
    project_path = args.path
    remediation_path = Path(args.remediation)
    if not remediation_path.exists():
        print()
        print(colored("  ✖ Remediation plan not found", RED))
        print(f"    Expected file: {bold(str(remediation_path))}")
        print()
        print("    Generate it first with an audit command, for example:")
        print(f"    {bold('supply-chain-auditor audit ' + str(project_path) + ' --remediation ' + str(remediation_path))}")
        print()
        print("    Then re-run the fix command:")
        print(f"    {bold('supply-chain-auditor fix ' + str(project_path) + ' --remediation ' + str(remediation_path) + ' --fix-report fix-results.json')}")
        return 2
    try:
        plan = load_remediation_plan(remediation_path)
    except Exception as exc:
        print()
        print(colored("  ✖ Could not read remediation plan", RED))
        print(f"    File: {bold(str(remediation_path))}")
        print(f"    Error: {exc}")
        return 2
    operations = apply_fixes(project_path, plan, allow_unsafe=args.allow_unsafe) if args.apply else plan_fixes(project_path, plan, allow_unsafe=args.allow_unsafe)

    print()
    print(bold("  ── Auto-fix Plan ─────────────────────────────────"))
    if not operations:
        print(colored("  No manifest changes available from remediation plan.", YELLOW))
    else:
        for op in operations:
            safe_text = "safe" if op.safe else "unsafe/needs-review"
            print(f"  - {op.action} {op.package} in {op.file} ({safe_text})")
            print(f"      {op.before} -> {op.after}")

    validation_result = None
    if args.apply and operations and getattr(args, "validate_fix", False):
        validation_result = validate_project_after_fix(project_path)
        ok = validation_result.get("ok")
        print(f"\n  {colored('✔' if ok else '✖', GREEN if ok else RED)} Post-fix validation {'passed' if ok else 'failed'}")
        for check in validation_result.get("checks", [])[:5]:
            print(f"    - {check.get('name')}: {'OK' if check.get('ok') else 'FAILED'}")
        if not ok:
            print(colored("  Refusing to create branch/PR because validation failed.", RED))
            if args.fix_report:
                export_fix_result(operations, args.fix_report, {"validation": validation_result, "applied": bool(args.apply)})
                print(f"\n  {colored('✔', GREEN)} Fix report saved to {bold(args.fix_report)}")
            return 1

    git_result = None
    pr_result = None
    if args.apply and operations and args.create_branch:
        git_result = create_branch_commit_push(
            project_path,
            branch=args.branch_name,
            commit_message=args.commit_message,
            push=args.push or args.open_pr,
            remote=args.remote,
        )
        ok = git_result.get("ok")
        print(f"\n  {colored('✔' if ok else '✖', GREEN if ok else RED)} Git branch/commit{'/push' if (args.push or args.open_pr) else ''} step {'completed' if ok else 'failed'}")
        if not ok:
            for step in git_result.get("steps", []):
                if not step.get("ok"):
                    print(f"    Failed: {' '.join(step.get('command', []))}")
                    print(f"    {step.get('output', '')[:500]}")
                    break

    if args.apply and operations and args.open_pr:
        body = args.pr_body or "Automated dependency remediation generated by Supply Chain Dependency Auditor."
        pr_result = open_github_pr(
            project_path,
            title=args.pr_title,
            body=body,
            base=args.base_branch,
            head=args.branch_name,
        )
        ok = pr_result.get("ok")
        print(f"\n  {colored('✔' if ok else '✖', GREEN if ok else RED)} GitHub PR creation {'completed' if ok else 'failed'}")
        if pr_result.get("output"):
            print(f"    {pr_result['output'][:700]}")

    if args.fix_report:
        extra = {"git": git_result, "pull_request": pr_result, "validation": validation_result, "applied": bool(args.apply)}
        export_fix_result(operations, args.fix_report, extra)
        print(f"\n  {colored('✔', GREEN)} Fix report saved to {bold(args.fix_report)}")

    if operations and not args.apply:
        print(colored("\n  Dry run only. Re-run with --apply to modify files.", CYAN))
    return 0 if operations or not args.apply else 1




def cmd_serve(args) -> int:
    serve_api(args.host, args.port, args.root, token=args.token, quiet=args.quiet, timeout=args.timeout)
    return 0

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="supply-chain-auditor",
        description="Supply Chain Dependency Auditor — enterprise-style dependency, CI/CD, SBOM, SARIF, policy, and API security auditing",
    )
    parser.add_argument("--version", action="version", version=f"supply-chain-auditor {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser("scan", help="Audit a single package by name")
    scan_p.add_argument("package", help="Package name, e.g. requests or lodash")
    scan_p.add_argument("--ecosystem", "-e", choices=["npm", "pip", "maven", "go", "nuget", "rubygems", "docker", "github-actions", "terraform"], help="Package ecosystem")
    scan_p.add_argument("--version", help="Specific package version to check")
    scan_p.add_argument("--no-scan", action="store_true", help="Skip package artifact/install-script scanning")
    scan_p.add_argument("--no-malware", action="store_true", help="Skip static malware/secret/IOC artifact analysis")
    scan_p.add_argument("--sandbox", action="store_true", help="Run optional Docker-based dynamic sandbox analysis")
    scan_p.add_argument("--sandbox-network", choices=["none", "bridge"], default="none", help="Docker sandbox network mode; default none")
    scan_p.add_argument("--provenance-policy", help="Path to provenance/Sigstore/SLSA policy JSON")
    scan_p.add_argument("--no-policy", action="store_true", help="Skip license/pinning/integrity policy checks")
    scan_p.add_argument("--license-policy", help="Path to JSON license policy")
    scan_p.add_argument("--policy", help="Path to unified policy-as-code JSON file")
    scan_p.add_argument("--policy-mode", choices=["off", "report", "enforce"], default="off", help="Evaluate policy rules only, or enforce block decisions")
    scan_p.add_argument("--policy-report", metavar="FILE", help="Export policy decision report JSON")
    scan_p.add_argument("--policy-audit-log", metavar="FILE", help="Append policy decisions to a JSONL audit log")
    scan_p.add_argument("--verbose", "-v", action="store_true", help="Show snippets and references")
    scan_p.add_argument("--json", metavar="FILE", help="Export JSON report")
    scan_p.add_argument("--html", metavar="FILE", help="Export HTML report")
    scan_p.add_argument("--sbom", metavar="FILE", help="Export CycloneDX SBOM JSON")
    scan_p.add_argument("--sarif", metavar="FILE", help="Export SARIF 2.1.0 for GitHub Code Scanning")
    scan_p.add_argument("--remediation", metavar="FILE", help="Export remediation/fix suggestion plan JSON")
    scan_p.set_defaults(func=cmd_scan)

    audit_p = subparsers.add_parser("audit", help="Audit packages in dependency files")
    audit_p.add_argument("path", help="Path to dependency file or project directory")
    audit_p.add_argument("--no-dev", action="store_true", help="Skip dev/test dependencies")
    audit_p.add_argument("--environment", action="store_true", help="Scan actual installed environment using pip inspect/list and npm ls")
    audit_p.add_argument("--no-npm-environment", action="store_true", help="With --environment, skip npm ls scanning")
    audit_p.add_argument("--no-scan", action="store_true", help="Skip package artifact/install-script scanning")
    audit_p.add_argument("--no-malware", action="store_true", help="Skip static malware/secret/IOC artifact analysis")
    audit_p.add_argument("--sandbox", action="store_true", help="Run optional Docker-based dynamic sandbox analysis")
    audit_p.add_argument("--sandbox-network", choices=["none", "bridge"], default="none", help="Docker sandbox network mode; default none")
    audit_p.add_argument("--sandbox-report", metavar="FILE", help="Export dynamic sandbox analysis results JSON")
    audit_p.add_argument("--resolver", choices=["registry", "exact"], default="registry", help="Use registry transitive expansion or native package-manager exact resolution")
    audit_p.add_argument("--resolver-report", metavar="FILE", help="Export exact resolver package list/warnings JSON")
    audit_p.add_argument("--provenance-policy", help="Path to provenance/Sigstore/SLSA policy JSON")
    audit_p.add_argument("--no-policy", action="store_true", help="Skip license/pinning/integrity policy checks")
    audit_p.add_argument("--license-policy", help="Path to JSON license policy")
    audit_p.add_argument("--policy", help="Path to unified policy-as-code JSON file")
    audit_p.add_argument("--policy-mode", choices=["off", "report", "enforce"], default="off", help="Evaluate policy rules only, or enforce block decisions")
    audit_p.add_argument("--policy-report", metavar="FILE", help="Export policy decision report JSON")
    audit_p.add_argument("--policy-audit-log", metavar="FILE", help="Append policy decisions to a JSONL audit log")
    audit_p.add_argument("--transitive-depth", type=int, default=1, help="Registry transitive dependency depth, 0 disables (default: 1)")
    audit_p.add_argument("--include-optional", action="store_true", help="Include optional dependencies during transitive expansion")
    audit_p.add_argument("--include-peer", action="store_true", help="Include npm peer dependencies during transitive expansion")
    audit_p.add_argument("--baseline", help="Existing dependency baseline JSON for diff-aware scanning")
    audit_p.add_argument("--save-baseline", help="Write current dependency baseline JSON")
    audit_p.add_argument("--diff-only", action="store_true", help="With --baseline, audit only added/changed packages")
    audit_p.add_argument("--workers", "-w", type=int, default=5, help="Parallel workers (default: 5)")
    audit_p.add_argument("--verbose", "-v", action="store_true", help="Print detailed report for flagged packages")
    audit_p.add_argument("--json", metavar="FILE", help="Export JSON report")
    audit_p.add_argument("--html", metavar="FILE", help="Export HTML report")
    audit_p.add_argument("--sbom", metavar="FILE", help="Export CycloneDX SBOM JSON")
    audit_p.add_argument("--sarif", metavar="FILE", help="Export SARIF 2.1.0 for GitHub Code Scanning")
    audit_p.add_argument("--remediation", metavar="FILE", help="Export remediation/fix suggestion plan JSON")
    audit_p.add_argument("--ci-hardening-report", metavar="FILE", help="Export GitHub Actions hardening findings JSON")
    audit_p.add_argument("--owner-map", metavar="FILE", help="JSON/CSV package owner map for governance reporting")
    audit_p.add_argument("--sla-report", metavar="FILE", help="Export owner/SLA report JSON")
    audit_p.add_argument("--jira-export", metavar="FILE", help="Export Jira/ServiceNow-compatible remediation CSV")
    audit_p.add_argument("--evidence-bundle", metavar="FILE", help="Export enterprise evidence bundle JSON")
    audit_p.set_defaults(func=cmd_audit)

    fix_p = subparsers.add_parser("fix", help="Apply safe remediation changes and optionally open a PR")
    fix_p.add_argument("path", help="Project directory containing requirements.txt/package.json")
    fix_p.add_argument("--remediation", required=True, help="Remediation plan JSON from --remediation")
    fix_p.add_argument("--apply", action="store_true", help="Actually modify files. Default is dry-run.")
    fix_p.add_argument("--allow-unsafe", action="store_true", help="Allow risky edits such as typosquat package replacement")
    fix_p.add_argument("--create-branch", action="store_true", help="Create a git branch and commit applied fixes")
    fix_p.add_argument("--branch-name", default="scda/auto-remediation", help="Branch name for auto-remediation PR")
    fix_p.add_argument("--commit-message", default="Apply supply chain dependency remediations", help="Commit message for auto-fix branch")
    fix_p.add_argument("--push", action="store_true", help="Push the auto-fix branch")
    fix_p.add_argument("--remote", default="origin", help="Git remote for push")
    fix_p.add_argument("--open-pr", action="store_true", help="Create a GitHub pull request using the gh CLI")
    fix_p.add_argument("--base-branch", default="main", help="Base branch for GitHub PR")
    fix_p.add_argument("--pr-title", default="Automated supply chain dependency remediation", help="GitHub PR title")
    fix_p.add_argument("--pr-body", default=None, help="GitHub PR body")
    fix_p.add_argument("--fix-report", metavar="FILE", help="Export auto-fix operation report JSON")
    fix_p.add_argument("--validate-fix", action="store_true", help="After --apply, run lightweight installability checks before PR creation")
    fix_p.set_defaults(func=cmd_fix)

    serve_p = subparsers.add_parser("serve", help="Run REST API / webhook server")
    serve_p.add_argument("--host", default="127.0.0.1", help="Bind host; default 127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8080, help="Bind port; default 8080")
    serve_p.add_argument("--root", default=".", help="Only allow audits under this root directory")
    serve_p.add_argument("--token", default=None, help="Optional API token required via X-Auditor-Token or Bearer token")
    serve_p.add_argument("--timeout", type=int, default=180, help="Audit timeout in seconds")
    serve_p.add_argument("--quiet", action="store_true", help="Suppress HTTP request logs")
    serve_p.set_defaults(func=cmd_serve)

    args = parser.parse_args()

    print(bold(colored("\n  ┌─ Supply Chain Auditor ─────────────────────────┐", CYAN)))
    print(bold(colored("  │  Enterprise supply-chain security auditor      │", CYAN)))
    print(bold(colored("  └────────────────────────────────────────────────┘", CYAN)))

    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
