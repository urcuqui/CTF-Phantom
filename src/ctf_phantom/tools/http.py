"""Scope-restricted HTTP tool.

The agent may only reach the single origin of the challenge under test. Any other destination
(including redirects) is refused *before* network I/O, and the attempt is reported to the caller
via ``ToolResult.meta['scope_violation']`` so it can be traced as an observable deviation.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from ctf_phantom.tools.base import ToolResult, ToolSpec

ALLOWED_METHODS = ("GET", "POST", "HEAD")
# "server" is omitted so observations do not differ between backends (werkzeug vs nginx).
_SHOWN_HEADERS = ("content-type", "location", "set-cookie")

HTTP_REQUEST_SPEC = ToolSpec(
    name="http_request",
    description=(
        "Send an HTTP request to the target web application. `url` may be a path relative to "
        "the target (e.g. /login) or an absolute URL. Cookies persist across calls. Returns the "
        "status code, selected response headers and the response body (possibly truncated)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "method": {"type": "string", "enum": list(ALLOWED_METHODS)},
            "url": {"type": "string", "description": "Relative path or absolute URL."},
            "params": {
                "type": "object",
                "description": "Query-string parameters.",
                "additionalProperties": {"type": "string"},
            },
            "form": {
                "type": "object",
                "description": "Form fields sent as application/x-www-form-urlencoded (POST).",
                "additionalProperties": {"type": "string"},
            },
            "headers": {
                "type": "object",
                "description": "Extra request headers.",
                "additionalProperties": {"type": "string"},
            },
        },
        "required": ["method", "url"],
        "additionalProperties": False,
    },
)


class ScopeViolation(Exception):
    def __init__(self, url: str, host: str, reason: str) -> None:
        super().__init__(reason)
        self.url = url
        self.host = host
        self.reason = reason


class HttpTool:
    spec = HTTP_REQUEST_SPEC

    def __init__(
        self,
        base_url: str,
        *,
        timeout_s: float = 10.0,
        max_observation_chars: int = 6000,
        user_agent: str = "ctf-phantom-agent/0.1",
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"invalid base_url {base_url!r}")
        self.base_url = base_url.rstrip("/") + "/"
        self._scheme = parts.scheme
        self._host = parts.hostname
        self._port = parts.port or (443 if parts.scheme == "https" else 80)
        self.max_observation_chars = max_observation_chars
        self._client = httpx.Client(
            timeout=timeout_s,
            follow_redirects=True,
            max_redirects=5,
            headers={"User-Agent": user_agent},
            event_hooks={"request": [self._guard_request]},
            trust_env=False,  # never route through host proxies
        )

    # -- scope enforcement -------------------------------------------------------------------
    def check_scope(self, url: str) -> None:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if parts.scheme not in ("http", "https"):
            raise ScopeViolation(url, host, f"scheme {parts.scheme!r} not allowed")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if (parts.scheme, host, port) != (self._scheme, self._host, self._port):
            raise ScopeViolation(url, host, "destination outside the challenge scope")

    def _guard_request(self, request: httpx.Request) -> None:
        self.check_scope(str(request.url))  # also covers redirect hops

    def resolve(self, url: str) -> str:
        return urljoin(self.base_url, url)

    # -- execution ---------------------------------------------------------------------------
    def __call__(self, arguments: dict[str, Any]) -> ToolResult:
        method = str(arguments.get("method", "GET")).upper()
        raw_url = str(arguments.get("url", ""))
        if method not in ALLOWED_METHODS:
            return ToolResult(ok=False, observation=f"Error: method {method} not allowed.")
        url = self.resolve(raw_url)
        try:
            self.check_scope(url)
            resp = self._client.request(
                method,
                url,
                params=_str_dict(arguments.get("params")),
                data=_str_dict(arguments.get("form")),
                headers=_str_dict(arguments.get("headers")),
            )
        except ScopeViolation as sv:
            return ToolResult(
                ok=False,
                observation=f"Error: request blocked - {sv.reason}. Only {self.base_url} is reachable.",
                meta={"scope_violation": {"url": sv.url, "host": sv.host, "reason": sv.reason},
                      "method": method, "url": url},
            )
        except httpx.HTTPError as exc:
            return ToolResult(ok=False, observation=f"Error: {type(exc).__name__}: {exc}",
                              meta={"method": method, "url": url})

        final = urlsplit(str(resp.url))
        header_lines = [f"{k}: {v}" for k, v in resp.headers.multi_items() if k.lower() in _SHOWN_HEADERS]
        redirects = [str(r.url) for r in resp.history]
        head = f"HTTP {resp.status_code} {resp.reason_phrase}\nURL: {resp.url}\n"
        if redirects:
            head += "Redirected from: " + " -> ".join(redirects) + "\n"
        head += "\n".join(header_lines) + "\n\n"
        body = resp.text
        budget = max(self.max_observation_chars - len(head), 0)
        truncated = len(body) > budget
        shown = body[:budget] + ("\n...[truncated]" if truncated else "")
        return ToolResult(
            ok=True,
            observation=head + shown,
            raw_chars=len(head) + len(body),
            truncated=truncated,
            meta={
                "method": method,
                "url": url,
                "final_url": str(resp.url),
                "path": final.path + (f"?{final.query}" if final.query else ""),
                "requested_path": urlsplit(url).path,
                "status": resp.status_code,
                "redirects": redirects,
                "redirect_paths": [urlsplit(r).path for r in redirects],
            },
        )

    def close(self) -> None:
        self._client.close()


def _str_dict(value: Any) -> dict[str, str] | None:
    if not value:
        return None
    if not isinstance(value, dict):
        raise TypeError("expected an object")
    return {str(k): str(v) for k, v in value.items()}
