"""Supply Chain Dependency Auditor — core package."""

from .version import __version__
from .ai_explainer import generate_explanation
from .breach_watchlist import check_breach_watchlist
from .dependency_policy import check_dependency_policy
from .diff_scan import diff_packages, save_baseline
from .environment_scan import scan_environment
from .license_policy import check_license_compliance
from .lockfile import SUPPORTED_FILES, detect_and_parse
from .maintainer import check_maintainer_takeover
from .osv_check import check_osv
from .registry import get_metadata
from .provenance import check_provenance
from .remediation import build_remediation, export_remediation_plan
from .policy_engine import load_policy, validate_policy, evaluate_policy, export_policy_result, append_policy_audit_log
from .autofix import load_remediation_plan, plan_fixes, apply_fixes, validate_project_after_fix, create_branch_commit_push, open_github_pr, export_fix_result
from .report_html import export_html
from .sarif import export_sarif
from .sbom import export_cyclonedx
from .scanner import scan_package
from .malware_analysis import scan_malware
from .scorer import RiskReport, score_package
from .transitive import expand_transitive_dependencies
from .typosquat import check_typosquat

from .resolver import exact_resolve_project
from .sandbox import sandbox_package, export_sandbox_results
from .ci_hardening import audit_github_actions, export_ci_hardening
from .enterprise_governance import load_owner_map, build_sla_report, export_jira_import, create_evidence_bundle

__all__ = [
    "__version__",
    "exact_resolve_project",
    "check_typosquat",
    "get_metadata",
    "scan_package",
    "scan_malware",
    "check_osv",
    "score_package",
    "RiskReport",
    "detect_and_parse",
    "SUPPORTED_FILES",
    "check_maintainer_takeover",
    "check_breach_watchlist",
    "check_license_compliance",
    "check_dependency_policy",
    "expand_transitive_dependencies",
    "scan_environment",
    "diff_packages",
    "save_baseline",
    "generate_explanation",
    "check_provenance",
    "build_remediation",
    "export_remediation_plan",
    "load_policy",
    "validate_policy",
    "evaluate_policy",
    "export_policy_result",
    "append_policy_audit_log",
    "load_remediation_plan",
    "plan_fixes",
    "apply_fixes",
    "validate_project_after_fix",
    "create_branch_commit_push",
    "open_github_pr",
    "export_fix_result",
    "export_html",
    "export_sarif",
    "export_cyclonedx",
    "exact_resolve_project",
    "sandbox_package",
    "export_sandbox_results",
    "audit_github_actions",
    "export_ci_hardening",
    "load_owner_map",
    "build_sla_report",
    "export_jira_import",
    "create_evidence_bundle",
    "run_audit_for_api",
    "openapi_schema",
]

from .api_server import run_audit_for_api, openapi_schema
