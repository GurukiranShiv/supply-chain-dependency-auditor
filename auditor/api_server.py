"""Small REST API and webhook server for Supply Chain Dependency Auditor.

The server intentionally uses only the Python standard library so the package
remains lightweight. It is designed for internal engineering portals, CI tools,
Backstage plugins, and webhook-style automation.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .version import __version__


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    raw = json.dumps(payload, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or 0)
    if length <= 0:
        return {}
    body = handler.rfile.read(length).decode("utf-8")
    if not body.strip():
        return {}
    return json.loads(body)


def _safe_target(root: Path, requested_path: str | None) -> Path:
    target = (root / (requested_path or ".")).resolve()
    root_resolved = root.resolve()
    try:
        target.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"path must stay inside allowed root: {root_resolved}") from exc
    return target


def _build_audit_command(target: Path, output_dir: Path, payload: dict[str, Any]) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "auditor.cli",
        "audit",
        str(target),
        "--json",
        str(output_dir / "results.json"),
        "--html",
        str(output_dir / "report.html"),
        "--sbom",
        str(output_dir / "sbom.json"),
        "--sarif",
        str(output_dir / "results.sarif"),
        "--remediation",
        str(output_dir / "remediation.json"),
    ]
    if payload.get("no_scan"):
        command.append("--no-scan")
    if payload.get("no_malware"):
        command.append("--no-malware")
    if payload.get("environment"):
        command.append("--environment")
    if payload.get("resolver") in {"registry", "exact"}:
        command.extend(["--resolver", payload["resolver"]])
    if payload.get("policy"):
        command.extend(["--policy", str(payload["policy"])])
        command.extend(["--policy-mode", str(payload.get("policy_mode", "report"))])
        command.extend(["--policy-report", str(output_dir / "policy-results.json")])
    if payload.get("ci_hardening", True):
        command.extend(["--ci-hardening-report", str(output_dir / "ci-hardening.json")])
    if payload.get("transitive_depth") is not None:
        command.extend(["--transitive-depth", str(int(payload["transitive_depth"]))])
    return command


def run_audit_for_api(root: Path, payload: dict[str, Any], timeout: int = 180) -> dict[str, Any]:
    target = _safe_target(root, payload.get("path") or ".")
    with tempfile.TemporaryDirectory(prefix="scda-api-") as temp:
        outdir = Path(temp)
        command = _build_audit_command(target, outdir, payload)
        env = os.environ.copy()
        # The CLI prints Unicode box-drawing characters. On Windows API subprocesses
        # may inherit cp1252 output encoding and fail before the audit starts.
        # Force UTF-8 so REST/webhook mode works reliably across Windows/Linux/macOS.
        env.setdefault("PYTHONUTF8", "1")
        env.setdefault("PYTHONIOENCODING", "utf-8")
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            env=env,
            encoding="utf-8",
            errors="replace",
        )
        results_path = outdir / "results.json"
        results = json.loads(results_path.read_text(encoding="utf-8")) if results_path.exists() else []
        summary = {
            "total": len(results),
            "critical": sum(1 for r in results if r.get("risk_level") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("risk_level") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk_level") == "MEDIUM"),
            "low": sum(1 for r in results if r.get("risk_level") == "LOW"),
            "safe": sum(1 for r in results if r.get("risk_level") == "SAFE"),
        }
        artifacts = {}
        for name in ["results.json", "sbom.json", "results.sarif", "remediation.json", "policy-results.json", "ci-hardening.json"]:
            p = outdir / name
            if p.exists():
                try:
                    artifacts[name] = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    artifacts[name] = p.read_text(encoding="utf-8")[:2000]
        audit_completed = results_path.exists()
        return {
            "ok": audit_completed and completed.returncode in (0, 1),
            "exit_code": completed.returncode,
            "version": __version__,
            "target": str(target),
            "summary": summary,
            "results": results,
            "artifacts": artifacts,
            "stdout_tail": completed.stdout[-4000:],
            "stderr_tail": completed.stderr[-2000:],
        }


class AuditorAPIHandler(BaseHTTPRequestHandler):
    server_version = f"SupplyChainAuditorAPI/{__version__}"

    def _authorized(self) -> bool:
        token = getattr(self.server, "token", None)
        if not token:
            return True
        return self.headers.get("X-Auditor-Token") == token or self.headers.get("Authorization") == f"Bearer {token}"

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        route = urlparse(self.path).path
        if route in {"/", "/health"}:
            _json_response(self, 200, {"ok": True, "service": "supply-chain-auditor", "version": __version__, "paths": ["/health", "/audit", "/webhook/audit", "/webhook/github", "/openapi.json"]})
            return
        if route == "/openapi.json":
            _json_response(self, 200, openapi_schema())
            return
        _json_response(self, 404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        if not self._authorized():
            _json_response(self, 401, {"ok": False, "error": "unauthorized"})
            return
        route = urlparse(self.path).path
        if route not in {"/audit", "/webhook/audit", "/webhook/github"}:
            _json_response(self, 404, {"ok": False, "error": "not found"})
            return
        try:
            payload = _read_json(self)
            if route == "/webhook/github":
                payload = _github_webhook_to_audit_payload(payload)
            result = run_audit_for_api(getattr(self.server, "root"), payload, timeout=getattr(self.server, "audit_timeout", 180))
            _json_response(self, 200 if result.get("ok") else 500, result)
        except Exception as exc:
            _json_response(self, 400, {"ok": False, "error": str(exc), "version": __version__})

    def log_message(self, fmt: str, *args: Any) -> None:
        if getattr(self.server, "quiet", False):
            return
        super().log_message(fmt, *args)


def _github_webhook_to_audit_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Map a simple GitHub webhook payload to an audit payload.

    Hosted systems normally clone the repo into a worker directory first. For a
    local developer demo, callers can include `local_path` to audit an already
    checked-out repository.
    """
    return {
        "path": payload.get("local_path") or payload.get("path") or ".",
        "resolver": payload.get("resolver", "registry"),
        "no_scan": bool(payload.get("no_scan", True)),
        "no_malware": bool(payload.get("no_malware", True)),
        "ci_hardening": True,
    }


def openapi_schema() -> dict[str, Any]:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Supply Chain Dependency Auditor API", "version": __version__},
        "paths": {
            "/health": {"get": {"summary": "Health check"}},
            "/audit": {
                "post": {
                    "summary": "Run an audit against a project path under the configured server root",
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                    "responses": {"200": {"description": "Audit result"}},
                }
            },
            "/webhook/audit": {"post": {"summary": "Webhook-compatible audit endpoint"}},
            "/webhook/github": {"post": {"summary": "GitHub webhook adapter for local checked-out repositories"}},
        },
    }


def serve(host: str, port: int, root: str, token: str | None = None, quiet: bool = False, timeout: int = 180) -> None:
    root_path = Path(root).resolve()
    httpd = ThreadingHTTPServer((host, port), AuditorAPIHandler)
    httpd.root = root_path  # type: ignore[attr-defined]
    httpd.token = token  # type: ignore[attr-defined]
    httpd.quiet = quiet  # type: ignore[attr-defined]
    httpd.audit_timeout = timeout  # type: ignore[attr-defined]
    print(f"Supply Chain Auditor API {__version__} listening on http://{host}:{port}")
    print(f"Allowed root: {root_path}")
    if token:
        print("Authentication: enabled with X-Auditor-Token / Bearer token")
    httpd.serve_forever()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the Supply Chain Dependency Auditor REST API server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("SCDA_PORT", "8080")))
    parser.add_argument("--root", default=os.environ.get("SCDA_ROOT", "."), help="Only audit paths under this root")
    parser.add_argument("--token", default=os.environ.get("SCDA_TOKEN"), help="Optional API token")
    parser.add_argument("--timeout", type=int, default=180, help="Per-audit timeout in seconds")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    serve(args.host, args.port, args.root, token=args.token, quiet=args.quiet, timeout=args.timeout)


if __name__ == "__main__":
    main()
