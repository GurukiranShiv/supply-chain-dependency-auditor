"""Policy-as-code enforcement with governance controls.

V7 adds schema validation, expiring exceptions, approver/ticket metadata, and
JSONL audit logs so policy decisions are reviewable in CI/CD and incident
response workflows.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ACTION_RANK = {"allow": 0, "warn": 1, "block": 2}
VALID_ACTIONS = set(ACTION_RANK)
SUPPORTED_SCHEMAS = {"supply-chain-auditor-policy-v1", "supply-chain-auditor-policy-v2"}


@dataclass
class PolicyDecision:
    package: str
    ecosystem: str
    action: str
    reasons: list[str]
    matched_rules: list[str]
    exception: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_policy() -> dict:
    return {
        "schema": "supply-chain-auditor-policy-v2",
        "default_action": "allow",
        "allowlist": [],
        "blocklist": [],
        "exceptions": [],
        "governance": {
            "require_exception_expiry": True,
            "require_exception_approver": True,
            "require_exception_ticket": True,
        },
        "rules": [
            {"id": "block-critical-risk", "description": "Block critical risk packages unless explicitly allowlisted.", "when": {"risk_score_gte": 85, "not_allowlisted": True}, "action": "block", "message": "Package risk score is critical."},
            {"id": "block-high-risk", "description": "Block high risk packages unless explicitly allowlisted.", "when": {"risk_score_gte": 60, "not_allowlisted": True}, "action": "block", "message": "Package risk score is high."},
            {"id": "block-malware-signals", "description": "Block static malware, secret, and suspicious binary indicators.", "when": {"signal_category_in": ["Secret exposure", "Malware behavior", "Binary inspection"], "signal_severity_in": ["CRITICAL", "HIGH"]}, "action": "block", "message": "Package contains high-severity malware-analysis indicators."},
            {"id": "block-denied-license", "description": "Block dependencies with denied licenses.", "when": {"license_status_in": ["DENY"]}, "action": "block", "message": "Package license is denied by policy."},
            {"id": "warn-medium-risk", "description": "Warn on medium risk dependencies.", "when": {"risk_score_gte": 35, "risk_score_lt": 60, "not_allowlisted": True}, "action": "warn", "message": "Package has medium supply-chain risk."},
            {"id": "warn-unpinned-direct-dependency", "description": "Warn when direct manifest dependencies are not pinned.", "when": {"signal_category_in": ["Dependency pinning"], "source_type_in": ["direct"]}, "action": "warn", "message": "Direct dependency is not pinned to an exact version."},
        ],
    }


def validate_policy(policy: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(policy, dict):
        return ["Policy must be a JSON object"]
    if policy.get("schema") not in SUPPORTED_SCHEMAS:
        errors.append(f"Unsupported policy schema: {policy.get('schema')}")
    if str(policy.get("default_action", "allow")).lower() not in VALID_ACTIONS:
        errors.append("default_action must be one of allow, warn, block")
    for section in ("allowlist", "blocklist", "rules", "exceptions"):
        if section in policy and not isinstance(policy.get(section), list):
            errors.append(f"{section} must be a list")
    for idx, rule in enumerate(policy.get("rules", []) or []):
        if not isinstance(rule, dict):
            errors.append(f"rules[{idx}] must be an object")
            continue
        if not rule.get("id"):
            errors.append(f"rules[{idx}] must include id")
        if str(rule.get("action", "warn")).lower() not in VALID_ACTIONS:
            errors.append(f"rules[{idx}].action must be allow, warn, or block")
        if not isinstance(rule.get("when", {}), dict):
            errors.append(f"rules[{idx}].when must be an object")
    governance = policy.get("governance", {}) or {}
    for idx, exc in enumerate(policy.get("exceptions", []) or []):
        if not isinstance(exc, dict):
            errors.append(f"exceptions[{idx}] must be an object")
            continue
        if not (exc.get("package") or exc.get("package_pattern") or exc.get("package_regex")):
            errors.append(f"exceptions[{idx}] must select a package")
        if governance.get("require_exception_expiry", True) and not exc.get("expires"):
            errors.append(f"exceptions[{idx}] must include expires")
        if governance.get("require_exception_approver", True) and not exc.get("approved_by"):
            errors.append(f"exceptions[{idx}] must include approved_by")
        if governance.get("require_exception_ticket", True) and not exc.get("ticket"):
            errors.append(f"exceptions[{idx}] must include ticket")
    return errors


def load_policy(path: str | None = None) -> dict:
    default = _default_policy()
    if not path:
        return default
    chosen = Path(path)
    if not chosen.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")
    data = json.loads(chosen.read_text(encoding="utf-8"))
    policy = {
        "schema": data.get("schema", default["schema"]),
        "default_action": str(data.get("default_action", default["default_action"])).lower(),
        "allowlist": data.get("allowlist", []),
        "blocklist": data.get("blocklist", []),
        "exceptions": data.get("exceptions", []),
        "governance": {**default.get("governance", {}), **(data.get("governance", {}) or {})},
        "rules": data.get("rules", default["rules"]),
    }
    errors = validate_policy(policy)
    if errors:
        raise ValueError("Invalid policy file: " + "; ".join(errors))
    return policy


def _package(report: Any) -> str:
    return str(getattr(report, "package", "") or "")


def _ecosystem(report: Any) -> str:
    return str(getattr(report, "ecosystem", "") or "")


def _source_type(report: Any) -> str:
    policy = getattr(report, "dependency_policy", None) or {}
    return str(policy.get("source_type") or "unknown")


def _license_status(report: Any) -> str:
    lic = getattr(report, "license", None) or {}
    return str(lic.get("status") or "UNKNOWN")


def _signals(report: Any) -> list[dict]:
    return list(getattr(report, "signals", None) or [])


def _item_matches(item: Any, report: Any) -> bool:
    name = _package(report).lower()
    eco = _ecosystem(report).lower()
    if isinstance(item, str):
        return item.lower() == name
    if not isinstance(item, dict):
        return False
    item_eco = item.get("ecosystem")
    if item_eco and str(item_eco).lower() != eco:
        return False
    exact = item.get("package") or item.get("name")
    if exact and str(exact).lower() != name:
        return False
    pattern = item.get("package_pattern") or item.get("pattern")
    if pattern and not fnmatch.fnmatch(name, str(pattern).lower()):
        return False
    regex = item.get("package_regex")
    if regex and not re.search(str(regex), name):
        return False
    return bool(exact or pattern or regex or item_eco)


def _is_allowlisted(report: Any, policy: dict) -> bool:
    return any(_item_matches(item, report) for item in policy.get("allowlist", []) or [])


def _is_blocklisted(report: Any, policy: dict) -> bool:
    return any(_item_matches(item, report) for item in policy.get("blocklist", []) or [])


def _value_in(value: str, allowed: Iterable[str]) -> bool:
    values = {str(v).lower() for v in allowed or []}
    return str(value).lower() in values


def _exception_expired(exc: dict) -> bool:
    expires = exc.get("expires")
    if not expires:
        return False
    try:
        raw = str(expires).replace("Z", "+00:00")
        return datetime.fromisoformat(raw) < datetime.now(timezone.utc)
    except Exception:
        return True


def _matching_exception(report: Any, policy: dict) -> dict | None:
    for exc in policy.get("exceptions", []) or []:
        if not _item_matches(exc, report):
            continue
        if _exception_expired(exc):
            continue
        max_score = exc.get("max_risk_score")
        if max_score is not None and int(getattr(report, "risk_score", 0) or 0) > int(max_score):
            continue
        allowed_levels = exc.get("risk_level_in")
        if allowed_levels and not _value_in(str(getattr(report, "risk_level", "UNKNOWN")), allowed_levels):
            continue
        return {
            "id": exc.get("id"),
            "approved_by": exc.get("approved_by"),
            "ticket": exc.get("ticket"),
            "expires": exc.get("expires"),
            "justification": exc.get("justification"),
        }
    return None


def _when_matches(when: dict, report: Any, policy: dict) -> bool:
    if not isinstance(when, dict):
        return False
    score = int(getattr(report, "risk_score", 0) or 0)
    level = str(getattr(report, "risk_level", "UNKNOWN") or "UNKNOWN")
    name = _package(report).lower()
    eco = _ecosystem(report).lower()
    source_type = _source_type(report).lower()
    license_status = _license_status(report)
    categories = {str(s.get("category", "")).lower() for s in _signals(report)}
    severities = {str(s.get("severity", "")).lower() for s in _signals(report)}

    if when.get("not_allowlisted") and _is_allowlisted(report, policy):
        return False
    if when.get("allowlisted") and not _is_allowlisted(report, policy):
        return False
    if "risk_score_gte" in when and score < int(when["risk_score_gte"]):
        return False
    if "risk_score_gt" in when and score <= int(when["risk_score_gt"]):
        return False
    if "risk_score_lte" in when and score > int(when["risk_score_lte"]):
        return False
    if "risk_score_lt" in when and score >= int(when["risk_score_lt"]):
        return False
    if "risk_level_in" in when and not _value_in(level, when["risk_level_in"]):
        return False
    if "ecosystem" in when and str(when["ecosystem"]).lower() != eco:
        return False
    if "package_in" in when and name not in {str(p).lower() for p in when["package_in"]}:
        return False
    if "package_pattern" in when and not fnmatch.fnmatch(name, str(when["package_pattern"]).lower()):
        return False
    if "license_status_in" in when and not _value_in(license_status, when["license_status_in"]):
        return False
    if "source_type_in" in when and source_type not in {str(x).lower() for x in when["source_type_in"]}:
        return False
    if "signal_category_in" in when:
        expected = {str(x).lower() for x in when["signal_category_in"]}
        if categories.isdisjoint(expected):
            return False
    if "signal_severity_in" in when:
        expected = {str(x).lower() for x in when["signal_severity_in"]}
        if severities.isdisjoint(expected):
            return False
    return True


def evaluate_policy(reports: list[Any], policy: dict | None = None) -> dict:
    policy = policy or _default_policy()
    decisions: list[PolicyDecision] = []

    for report in reports:
        action = str(policy.get("default_action", "allow")).lower()
        if action not in VALID_ACTIONS:
            action = "allow"
        reasons: list[str] = []
        matched_rules: list[str] = []
        exception = _matching_exception(report, policy)

        allowlisted = _is_allowlisted(report, policy)
        blocklisted = _is_blocklisted(report, policy)

        if allowlisted:
            action = "allow"
            reasons.append("Package matched policy allowlist")
            matched_rules.append("allowlist")

        if blocklisted:
            action = "block"
            reasons.append("Package matched policy blocklist")
            matched_rules.append("blocklist")

        if allowlisted and not blocklisted:
            decision = PolicyDecision(_package(report), _ecosystem(report), action, reasons, matched_rules, exception)
            report.policy_decision = decision.to_dict()
            decisions.append(decision)
            continue

        for rule in policy.get("rules", []) or []:
            if not isinstance(rule, dict):
                continue
            rule_action = str(rule.get("action", "warn")).lower()
            if rule_action not in VALID_ACTIONS:
                rule_action = "warn"
            if not _when_matches(rule.get("when", {}), report, policy):
                continue
            matched_rules.append(str(rule.get("id") or "unnamed-rule"))
            reasons.append(str(rule.get("message") or rule.get("description") or f"Policy rule {rule.get('id', 'unnamed')} matched"))
            if ACTION_RANK[rule_action] > ACTION_RANK[action]:
                action = rule_action

        if exception and action in {"block", "warn"}:
            action = "allow"
            matched_rules.append("exception")
            reasons.append(f"Approved exception {exception.get('id') or ''} until {exception.get('expires')}")

        decision = PolicyDecision(_package(report), _ecosystem(report), action, reasons, matched_rules, exception)
        try:
            report.policy_decision = decision.to_dict()
        except Exception:
            pass
        decisions.append(decision)

    summary = {"block": 0, "warn": 0, "allow": 0}
    for d in decisions:
        summary[d.action] = summary.get(d.action, 0) + 1
    return {"schema": "supply-chain-auditor-policy-result-v2", "generated_at": _now_iso(), "summary": summary, "decisions": [d.to_dict() for d in decisions]}


def export_policy_result(result: dict, path: str) -> None:
    Path(path).write_text(json.dumps(result, indent=2), encoding="utf-8")


def append_policy_audit_log(result: dict, path: str | Path) -> None:
    record = {"schema": "supply-chain-auditor-policy-audit-log-v1", "timestamp": _now_iso(), "result": result}
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True) if target.parent != Path("") else None
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
