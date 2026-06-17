"""HTML report generator for audit results."""

from __future__ import annotations

from html import escape
from datetime import datetime, timezone
from typing import Any


def _level_class(level: str) -> str:
    return level.lower() if level else "info"


def _remediation_html(remediation: dict | None) -> str:
    suggestions = (remediation or {}).get("suggestions", []) or []
    if not suggestions:
        return "<li>No remediation suggestions generated.</li>"
    items = []
    for sug in suggestions[:8]:
        command = f"<code>{escape(str(sug.get('command')))}</code>" if sug.get("command") else ""
        fixed = f"<br><small>Fixed versions: {escape(', '.join(sug.get('fixed_versions', [])))}</small>" if sug.get("fixed_versions") else ""
        line = f"<br><small>Suggested line: <code>{escape(str(sug.get('suggested_line')))}</code></small>" if sug.get("suggested_line") else ""
        items.append(
            f"<li><span class='badge info'>{escape(str(sug.get('priority','info')).upper())}</span> "
            f"{escape(str(sug.get('summary','')))} {command}{fixed}{line}</li>"
        )
    return "".join(items)


def _ci_hardening_html(ci_result: dict | None) -> str:
    if not ci_result:
        return ""
    summary = ci_result.get("summary", {}) or {}
    findings = ci_result.get("findings", []) or []
    rows = []
    for item in findings[:30]:
        sev = escape(str(item.get("severity", "INFO"))).upper()
        workflow = escape(str(item.get("workflow", item.get("file", "workflow"))))
        detail = escape(str(item.get("detail", item.get("message", ""))))
        rule = escape(str(item.get("rule", item.get("category", "CI/CD hardening"))))
        rows.append(
            f"<tr><td><span class='badge {_level_class(sev)}'>{sev}</span></td>"
            f"<td>{workflow}</td><td><strong>{rule}</strong><br>{detail}</td></tr>"
        )
    if not rows:
        rows.append("<tr><td colspan='3'>No CI/CD hardening findings.</td></tr>")
    workflows = summary.get("workflows_scanned", summary.get("files_scanned", 0))
    return f"""
<h2>CI/CD Hardening</h2>
<div class="card summary">
  <strong>{escape(str(workflows))}</strong> workflow file(s) scanned<br>
  <span>Critical: {escape(str(summary.get('critical', 0)))}</span>
  <span>High: {escape(str(summary.get('high', 0)))}</span>
  <span>Medium: {escape(str(summary.get('medium', 0)))}</span>
  <span>Low: {escape(str(summary.get('low', 0)))}</span>
</div>
<table><thead><tr><th>Severity</th><th>Workflow</th><th>Finding</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
"""


def export_html(reports: list[Any], path: str, ci_result: dict | None = None) -> None:
    rows = []
    detail_blocks = []
    for r in sorted(reports, key=lambda x: -x.risk_score):
        rows.append(f"""
        <tr>
          <td>{escape(r.package)}</td><td>{escape(r.ecosystem)}</td><td>{escape(str(r.version or ''))}</td>
          <td><strong>{r.risk_score}</strong></td><td><span class="badge {_level_class(r.risk_level)}">{escape(r.risk_level)}</span></td>
          <td>{escape(r.recommendation)}</td>
        </tr>""")
        sigs = "".join(
            f"<li><span class='badge {_level_class(s.get('severity','INFO'))}'>{escape(s.get('severity','INFO'))}</span> "
            f"<strong>{escape(s.get('category','Signal'))}</strong>: {escape(s.get('detail',''))}</li>"
            for s in r.signals[:18]
        ) or "<li>No significant signals.</li>"
        explanation = escape(getattr(r, "ai_explanation", "") or "")
        provenance = getattr(r, "provenance", None) or {}
        remediation = getattr(r, "remediation", None) or {}
        prov_flags = "".join(f"<li>{escape(str(flag))}</li>" for flag in provenance.get("flags", [])[:6]) or "<li>No provenance details.</li>"
        detail_blocks.append(f"""
        <section class="card">
          <h2>{escape(r.package)} <small>{escape(r.ecosystem)}</small></h2>
          <p><span class="score">{r.risk_score}/100</span> <span class="badge {_level_class(r.risk_level)}">{escape(r.risk_level)}</span></p>
          <pre>{explanation}</pre>
          <h3>Signals</h3><ul>{sigs}</ul>
          <h3>Artifact integrity / provenance</h3><ul>{prov_flags}</ul>
          <h3>Fix suggestions</h3><ul>{_remediation_html(remediation)}</ul>
        </section>""")

    counts = {k: sum(1 for r in reports if r.risk_level == k) for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]}
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Supply Chain Audit Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 32px; background: #f7f7f7; color: #222; }}
h1 {{ margin-bottom: 4px; }}
.card {{ background: white; padding: 18px; margin: 18px 0; border-radius: 12px; box-shadow: 0 1px 4px #ccc; }}
table {{ width: 100%; border-collapse: collapse; background: white; }}
th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #ddd; vertical-align: top; }}
th {{ background: #111827; color: white; }}
.badge {{ border-radius: 999px; padding: 4px 9px; color: white; font-size: 12px; font-weight: bold; }}
.critical {{ background: #7f1d1d; }} .high {{ background: #dc2626; }} .medium {{ background: #d97706; }}
.low {{ background: #2563eb; }} .safe {{ background: #16a34a; }} .info {{ background: #6b7280; }}
.score {{ font-size: 20px; font-weight: bold; }}
pre {{ white-space: pre-wrap; background: #111827; color: #f9fafb; padding: 14px; border-radius: 8px; }}
.summary span {{ margin-right: 12px; }}
code {{ background: #eef2ff; padding: 2px 5px; border-radius: 4px; }}
</style>
</head>
<body>
<h1>Supply Chain Dependency Audit</h1>
<p>Generated {datetime.now(timezone.utc).isoformat()}</p>
<div class="card summary">
  <strong>{len(reports)}</strong> packages scanned<br>
  <span>Critical: {counts['CRITICAL']}</span><span>High: {counts['HIGH']}</span><span>Medium: {counts['MEDIUM']}</span><span>Low: {counts['LOW']}</span><span>Safe: {counts['SAFE']}</span>
</div>
<h2>Summary</h2>
<table><thead><tr><th>Package</th><th>Eco</th><th>Version</th><th>Score</th><th>Risk</th><th>Recommendation</th></tr></thead><tbody>
{''.join(rows)}
</tbody></table>
{_ci_hardening_html(ci_result)}
<h2>Details</h2>
{''.join(detail_blocks)}
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
