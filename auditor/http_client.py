"""
Small HTTP client with file caching, retry/backoff, and polite rate limiting.

The project intentionally uses only the Python standard library, so this module
replaces the repeated urllib calls that would otherwise hammer registry APIs.

Environment variables:
  AUDITOR_CACHE_DIR      Override cache directory. Default: .auditor-cache/http
  AUDITOR_CACHE_TTL      Cache TTL in seconds. Default: 86400
  AUDITOR_DISABLE_CACHE  Set to 1/true/yes to bypass cache
  AUDITOR_HTTP_RETRIES   Retry count. Default: 3
  AUDITOR_HTTP_DELAY     Minimum delay between live HTTP requests. Default: 0.2
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

USER_AGENT = "supply-chain-auditor/3.0"
_DEFAULT_TIMEOUT = 12
_last_request_time = 0.0


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _cache_dir() -> Path:
    override = os.getenv("AUDITOR_CACHE_DIR")
    if override:
        return Path(override)
    return _project_root() / ".auditor-cache" / "http"


def _cache_enabled() -> bool:
    return os.getenv("AUDITOR_DISABLE_CACHE", "").strip().lower() not in {"1", "true", "yes"}


def _cache_ttl_seconds() -> int:
    try:
        return max(int(os.getenv("AUDITOR_CACHE_TTL", "86400")), 0)
    except ValueError:
        return 86400


def _cache_key(url: str, body: Optional[bytes] = None) -> str:
    h = hashlib.sha256()
    h.update(url.encode("utf-8"))
    if body:
        h.update(b"\0")
        h.update(body)
    return h.hexdigest()


def _cache_path(url: str, body: Optional[bytes] = None) -> Path:
    return _cache_dir() / f"{_cache_key(url, body)}.bin"


def _read_cache(url: str, body: Optional[bytes] = None) -> Optional[bytes]:
    if not _cache_enabled():
        return None
    path = _cache_path(url, body)
    if not path.exists():
        return None
    ttl = _cache_ttl_seconds()
    if ttl and time.time() - path.stat().st_mtime > ttl:
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def _write_cache(url: str, content: bytes, body: Optional[bytes] = None) -> None:
    if not _cache_enabled():
        return
    try:
        path = _cache_path(url, body)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    except OSError:
        pass


def _respect_rate_limit() -> None:
    global _last_request_time
    try:
        min_delay = float(os.getenv("AUDITOR_HTTP_DELAY", "0.2"))
    except ValueError:
        min_delay = 0.2
    now = time.monotonic()
    wait = min_delay - (now - _last_request_time)
    if wait > 0:
        time.sleep(wait)
    _last_request_time = time.monotonic()


def fetch_bytes(
    url: str,
    *,
    timeout: int = _DEFAULT_TIMEOUT,
    method: str = "GET",
    data: Optional[bytes] = None,
    headers: Optional[dict[str, str]] = None,
    use_cache: bool = True,
) -> tuple[Optional[bytes], Optional[dict]]:
    """Fetch bytes with cache, retry, and backoff.

    Returns (content, error). HTTP 404 is returned as an error dict rather than
    an exception so callers can distinguish not-found from network failures.
    """
    if use_cache:
        cached = _read_cache(url, data)
        if cached is not None:
            return cached, None

    try:
        retries = max(int(os.getenv("AUDITOR_HTTP_RETRIES", "3")), 1)
    except ValueError:
        retries = 3

    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)

    last_error: Optional[dict] = None

    for attempt in range(retries):
        try:
            _respect_rate_limit()
            req = urllib.request.Request(url, data=data, headers=request_headers, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                content = resp.read()
                if use_cache and method.upper() == "GET":
                    _write_cache(url, content, data)
                return content, None
        except urllib.error.HTTPError as exc:
            # Retry common transient rate-limit/server errors. Respect Retry-After when present.
            last_error = {"type": "http_error", "status": exc.code, "detail": str(exc)}
            if exc.code == 404:
                return None, {"type": "not_found", "status": 404, "detail": str(exc)}
            if exc.code in {429, 500, 502, 503, 504} and attempt < retries - 1:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    delay = float(retry_after) if retry_after else min(2 ** attempt, 8)
                except ValueError:
                    delay = min(2 ** attempt, 8)
                time.sleep(delay)
                continue
            return None, last_error
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = {"type": "fetch_failed", "detail": str(exc)}
            if attempt < retries - 1:
                time.sleep(min(2 ** attempt, 8))
                continue
        except Exception as exc:  # pragma: no cover - defensive
            last_error = {"type": "unexpected_error", "detail": str(exc)}
            break

    return None, last_error or {"type": "fetch_failed", "detail": "unknown error"}


def fetch_json(
    url: str,
    *,
    timeout: int = _DEFAULT_TIMEOUT,
    method: str = "GET",
    payload: Optional[dict] = None,
    headers: Optional[dict[str, str]] = None,
    use_cache: bool = True,
) -> dict:
    """Fetch JSON and return either parsed data or a structured __error__ dict."""
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request_headers = {"Accept": "application/json"}
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)

    # Cache POST requests too when payload is identical, but only if caller allows it.
    content, error = fetch_bytes(
        url,
        timeout=timeout,
        method=method,
        data=body,
        headers=request_headers,
        use_cache=use_cache,
    )
    if error:
        return {"__error__": error.get("type", "fetch_failed"), **error}
    if content is None:
        return {"__error__": "empty_response"}
    try:
        return json.loads(content.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        return {"__error__": "parse_failed", "detail": str(exc)}


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha512_bytes(content: bytes) -> str:
    return hashlib.sha512(content).hexdigest()


def sha512_base64(content: bytes) -> str:
    import base64
    return base64.b64encode(hashlib.sha512(content).digest()).decode('ascii')
