"""AI/rule-based explanation generator for risk reports.

Default behavior is deterministic and offline so the scanner does not hang or
fail when Ollama is not running. To use Ollama, set:

    AUDITOR_AI_PROVIDER=ollama
    AUDITOR_AI_MODEL=llama3
"""

import json
import os
import urllib.error
import urllib.request

OLLAMA_URL = os.getenv("AUDITOR_OLLAMA_URL", "http://localhost:11434/api/generate")
DEFAULT_MODEL = os.getenv("AUDITOR_AI_MODEL", "llama3")


def _fallback_explanation(report) -> str:
    """Create a useful explanation without any external AI dependency."""
    package = getattr(report, "package", "unknown")
    risk_level = getattr(report, "risk_level", "UNKNOWN")
    risk_score = getattr(report, "risk_score", 0)
    signals = getattr(report, "signals", []) or []

    high_signals = [
        s for s in signals
        if s.get("severity") in {"CRITICAL", "HIGH", "MEDIUM"}
    ]
    important = high_signals[:3] if high_signals else signals[:3]

    if important:
        findings = "\n".join(
            f"- {s.get('category', 'Signal')}: {s.get('detail', 'No detail')}"
            for s in important
        )
    else:
        findings = "- No major suspicious signals were detected."

    if risk_level in {"CRITICAL", "HIGH"}:
        recommendation = "Do not install this package until the source code, maintainers, and registry history are manually reviewed."
    elif risk_level == "MEDIUM":
        recommendation = "Use caution. Review the listed signals and prefer a trusted alternative if the package is not required."
    elif risk_level == "LOW":
        recommendation = "The package appears low risk, but review the minor signals before using it in production."
    else:
        recommendation = "The package appears safe based on the checks performed. Continue normal dependency hygiene."

    return (
        f"Executive Summary:\n"
        f"{package} is rated {risk_level} with a score of {risk_score}/100.\n\n"
        f"Key Findings:\n{findings}\n\n"
        f"Security Recommendation:\n{recommendation}"
    )


def _ollama_explanation(report) -> str:
    prompt = f"""
You are a senior Application Security Engineer.

Analyze this package risk report.

Package:
{report.package}

Risk Level:
{report.risk_level}

Risk Score:
{report.risk_score}

Signals:
{json.dumps(report.signals, indent=2)}

Provide:

1. Executive Summary
2. Key Findings
3. Security Recommendation

Keep response under 200 words.
"""

    payload = json.dumps({
        "model": DEFAULT_MODEL,
        "prompt": prompt,
        "stream": False,
    }).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.loads(response.read().decode("utf-8", errors="replace"))

    return data.get("response") or "No AI explanation generated."


def generate_explanation(report) -> str:
    """Generate an explanation. Ollama is optional and opt-in."""
    provider = os.getenv("AUDITOR_AI_PROVIDER", "local").strip().lower()

    if provider != "ollama":
        return _fallback_explanation(report)

    try:
        return _ollama_explanation(report)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, Exception) as exc:
        fallback = _fallback_explanation(report)
        return f"AI explanation unavailable: {exc}\n\n{fallback}"


# Compatibility wrapper
def explain_report(report):
    return generate_explanation(report)
