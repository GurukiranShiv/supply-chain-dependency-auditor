"""Enterprise governance helpers: owners, SLAs, evidence bundles, and ticket exports."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

DEFAULT_SLA_DAYS = {"CRITICAL": 2, "HIGH": 7, "MEDIUM": 30, "LOW": 90, "SAFE": 0}


def load_owner_map(path: str | None) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Owner map not found: {path}")
    if p.suffix.lower() == ".csv":
        rows = csv.DictReader(p.read_text(encoding="utf-8").splitlines())
        return {row.get("package", "").lower(): row for row in rows if row.get("package")}
    data = json.loads(p.read_text(encoding="utf-8"))
    return {str(k).lower(): v for k, v in (data.get("owners", data) or {}).items()}


def build_sla_report(reports: list, owner_map: dict | None = None, sla_days: dict | None = None) -> dict:
    owner_map = owner_map or {}
    sla_days = sla_days or DEFAULT_SLA_DAYS
    now = datetime.now(timezone.utc)
    items = []
    for r in reports:
        level = r.risk_level
        days = int(sla_days.get(level, 0) or 0)
        due = (now + timedelta(days=days)).date().isoformat() if days else None
        owner = owner_map.get(r.package.lower(), {})
        items.append({
            "package": r.package,
            "ecosystem": r.ecosystem,
            "risk_level": level,
            "risk_score": r.risk_score,
            "owner": owner.get("owner") if isinstance(owner, dict) else owner,
            "team": owner.get("team") if isinstance(owner, dict) else None,
            "ticket_project": owner.get("ticket_project") if isinstance(owner, dict) else None,
            "sla_days": days,
            "due_date": due,
            "recommendation": r.recommendation,
        })
    return {"generated_at": now.isoformat(), "items": items, "summary": {lvl: sum(1 for i in items if i["risk_level"] == lvl) for lvl in DEFAULT_SLA_DAYS}}


def export_jira_import(sla_report: dict, path: str) -> None:
    # CSV suitable for Jira/ServiceNow-style bulk import.
    rows = []
    for item in sla_report.get("items", []):
        if item.get("risk_level") not in {"CRITICAL", "HIGH", "MEDIUM"}:
            continue
        rows.append({
            "Summary": f"[{item['risk_level']}] Review {item['ecosystem']} dependency {item['package']}",
            "Description": item.get("recommendation", ""),
            "Priority": "Highest" if item["risk_level"] == "CRITICAL" else ("High" if item["risk_level"] == "HIGH" else "Medium"),
            "Assignee": item.get("owner") or "",
            "Due date": item.get("due_date") or "",
            "Labels": "supply-chain-security,dependency-risk",
        })
    p = Path(path)
    with p.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["Summary", "Description", "Priority", "Assignee", "Due date", "Labels"])
        writer.writeheader()
        writer.writerows(rows)


def create_evidence_bundle(*, reports: list, policy_result: dict | None = None, ci_result: dict | None = None, sandbox_results: list | None = None, path: str = "evidence-bundle.json") -> dict:
    bundle = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "supply-chain-auditor",
        "control_mapping": {
            "NIST_SSDF": ["RV.1", "RV.2", "PW.4", "PS.3"],
            "SLSA": ["provenance", "build-integrity", "dependency-tracking"],
            "OWASP_SCVS": ["component-inventory", "known-vulnerability-management", "artifact-integrity", "malware-detection"],
        },
        "summary": {
            "packages_scanned": len(reports),
            "critical_or_high": sum(1 for r in reports if r.risk_level in {"CRITICAL", "HIGH"}),
        },
        "reports": [
            {"package": r.package, "ecosystem": r.ecosystem, "risk_level": r.risk_level, "risk_score": r.risk_score, "signals": r.signals[:10]}
            for r in reports
        ],
        "policy": policy_result,
        "ci_hardening": ci_result,
        "sandbox": sandbox_results or [],
    }
    Path(path).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return bundle
