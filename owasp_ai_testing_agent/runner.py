"""Live test runner: an HTTP client, nothing more (plan section 6).

Payloads are *data*. They are placed in a JSON request body and sent to the one host named in the
authorisation token. They are never passed to a shell, `eval`, `exec` or `subprocess`, and the
target's response is only ever stored and judged as untrusted text. Redirects are not followed
(a redirect could leave the authorised host), requests are rate-limited and time-limited, and
responses are size-capped.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .audit_log import AuditLog
from .authorisation import Authorisation
from .config import Config
from .llm import RateLimiter

PLACEHOLDER = "{{PAYLOAD}}"
_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class InterfaceError(ValueError):
    pass


@dataclass(frozen=True)
class Interface:
    """How to talk to the target. Example in examples/interface.json."""
    url: str
    body_template: dict
    response_field: str = ""          # dotted path into a JSON reply, e.g. "choices.0.text"; "" = raw text
    headers: dict = field(default_factory=dict)  # values may use ${ENV_VAR}; never logged
    method: str = "POST"

    @classmethod
    def load(cls, path: Path | str) -> "Interface":
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))  # tolerate a BOM from Windows editors
        try:
            iface = cls(url=data["url"], body_template=data["body_template"],
                        response_field=data.get("response_field", ""),
                        headers=data.get("headers", {}), method=data.get("method", "POST").upper())
        except KeyError as exc:
            raise InterfaceError(f"interface file lacks {exc}") from exc
        if iface.method not in ("POST", "PUT"):
            raise InterfaceError("method must be POST or PUT")
        if PLACEHOLDER not in json.dumps(iface.body_template):
            raise InterfaceError(f"body_template must contain {PLACEHOLDER}")
        return iface


@dataclass
class Exchange:
    test_id: str
    technique: str
    payload: str
    success_indicator: str
    category_id: str = ""
    canary: str | None = None         # string whose presence in the response is the objective success check
    status: int | None = None
    response: str | None = None
    truncated: bool = False
    error: str | None = None
    elapsed_s: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _fill(template, payload: str):
    if isinstance(template, str):
        return template.replace(PLACEHOLDER, payload)
    if isinstance(template, list):
        return [_fill(v, payload) for v in template]
    if isinstance(template, dict):
        return {k: _fill(v, payload) for k, v in template.items()}
    return template


def _dig(value, path: str):
    for part in filter(None, path.split(".")):
        if isinstance(value, list):
            value = value[int(part)]
        else:
            value = value[part]
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # returning None makes urllib raise HTTPError
        return None


class Runner:
    def __init__(self, interface: Interface, auth: Authorisation, config: Config, audit: AuditLog,
                 limiter: RateLimiter | None = None):
        auth.check_url(interface.url)  # fail before anything is sent
        self.interface, self.auth, self.config, self.audit = interface, auth, config, audit
        self.limiter = limiter or RateLimiter(config.rate_limit_per_min)
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/plain"}
        for name, value in self.interface.headers.items():
            headers[name] = _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), str(value))
        return headers

    def send(self, test_id: str, technique: str, payload: str, success_indicator: str,
             category_id: str = "", canary: str | None = None) -> Exchange:
        ex = Exchange(test_id, technique, payload, success_indicator, category_id=category_id, canary=canary)
        self.limiter.acquire()
        body = json.dumps(_fill(self.interface.body_template, payload)).encode("utf-8")
        req = urllib.request.Request(self.interface.url, data=body, method=self.interface.method,
                                     headers=self._headers())
        started = time.monotonic()
        try:
            with self._opener.open(req, timeout=self.config.request_timeout_s) as resp:
                ex.status = resp.status
                raw = resp.read(self.config.max_response_chars + 1)
        except urllib.error.HTTPError as exc:
            ex.status, ex.error = exc.code, f"HTTP {exc.code}"
            raw = b""
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            ex.error = f"{type(exc).__name__}: {exc}"
            raw = b""
        ex.elapsed_s = round(time.monotonic() - started, 3)

        if raw:
            ex.truncated = len(raw) > self.config.max_response_chars
            text = raw[: self.config.max_response_chars].decode("utf-8", errors="replace")
            if self.interface.response_field:
                try:
                    text = str(_dig(json.loads(text), self.interface.response_field))
                except (ValueError, KeyError, IndexError, TypeError):
                    if not ex.truncated:
                        ex.error = f"response_field '{self.interface.response_field}' not found in reply"
                        text = None
                    # a reply cut off at the size cap is not valid JSON; keep the raw prefix as evidence
                    # (the judge treats truncated responses as insufficient to show an attack failed)
            ex.response = text
        self.audit.append("target_request", test_id=test_id, host=self.auth.target_host,
                          status=ex.status, error=ex.error, truncated=ex.truncated, elapsed_s=ex.elapsed_s)
        return ex

    def run(self, payloads: list[dict], stop: threading.Event | None = None) -> list[Exchange]:
        """Send each payload in order. Stops early (keeping partial results) when `stop` is set."""
        stop = stop or threading.Event()
        results: list[Exchange] = []
        for p in payloads[: self.config.max_test_cases]:
            if stop.is_set():
                self.audit.append("run_interrupted", completed=len(results), planned=len(payloads))
                break
            results.append(self.send(p["test_id"], p.get("technique", ""), p["payload"], p.get("success_indicator", ""),
                                     p.get("category_id", ""), p.get("canary")))
        return results
