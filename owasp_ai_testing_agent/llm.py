"""Claude API wrapper: rate limiting, bounded retries, usage logging and strict JSON parsing."""
from __future__ import annotations

import json
import re
import threading
import time
from collections import deque

from .audit_log import AuditLog
from .config import Config
from .usage import UsageLedger


class ModelOutputError(ValueError):
    """The model returned something that is not the JSON the pipeline asked for."""


class RateLimiter:
    """Sliding-window limiter: at most `per_minute` acquisitions in any 60-second window."""

    def __init__(self, per_minute: int, clock=time.monotonic, sleep=time.sleep):
        self.per_minute = per_minute
        self._clock, self._sleep = clock, sleep
        self._stamps: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = self._clock()
                while self._stamps and now - self._stamps[0] >= 60:
                    self._stamps.popleft()
                if len(self._stamps) < self.per_minute:
                    self._stamps.append(now)
                    return
                wait = 60 - (now - self._stamps[0])
            self._sleep(max(wait, 0.01))


def extract_json(text: str):
    """Parse the first JSON value in text, tolerating ``` fences and surrounding prose."""
    text = text.strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.S)
    if fenced:
        text = fenced.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch in "[{":
            try:
                value, _ = decoder.raw_decode(text[i:])
                return value
            except json.JSONDecodeError:
                continue
    raise ModelOutputError("no JSON value found in model output")


class LLM:
    def __init__(self, config: Config, audit: AuditLog, client=None, limiter: RateLimiter | None = None,
                 ledger: UsageLedger | None = None):
        if client is None:
            import anthropic  # imported lazily so tests and --help work without a key
            client = anthropic.Anthropic()
        self.config, self.audit, self.client = config, audit, client
        self.limiter = limiter or RateLimiter(config.rate_limit_per_min)
        self.ledger = ledger or UsageLedger(config)
        self._send_temperature = True

    def complete(self, system: str, user: str, purpose: str) -> str:
        import anthropic

        retryable = (anthropic.RateLimitError, anthropic.APIConnectionError, anthropic.InternalServerError)
        last_exc: Exception | None = None
        for attempt in range(4):
            self.ledger.check_before_call()
            self.limiter.acquire()
            kwargs = dict(model=self.config.model, max_tokens=self.config.max_tokens, system=system,
                          messages=[{"role": "user", "content": user}])
            if self._send_temperature:
                kwargs["temperature"] = self.config.temperature
            try:
                msg = self.client.messages.create(**kwargs)
            except anthropic.BadRequestError as exc:
                if self._send_temperature and "temperature" in str(exc).lower():
                    # some models reject the parameter; run without it from now on and say so in the log
                    self._send_temperature = False
                    self.audit.append("llm_temperature_unsupported", model=self.config.model)
                    continue
                raise
            except retryable as exc:
                last_exc = exc
                self.audit.append("llm_retry", purpose=purpose, attempt=attempt + 1, error=type(exc).__name__)
                time.sleep(2 ** attempt)
                continue
            text = "".join(b.text for b in msg.content if getattr(b, "type", "text") == "text")
            usage = getattr(msg, "usage", None)
            self.audit.append(
                "llm_call",
                purpose=purpose,
                model=self.config.model,
                input_tokens=getattr(usage, "input_tokens", None),
                output_tokens=getattr(usage, "output_tokens", None),
                stop_reason=getattr(msg, "stop_reason", None),
                temperature=self.config.temperature if self._send_temperature else None,
            )
            alert = self.ledger.record(self.config.model, getattr(usage, "input_tokens", None),
                                       getattr(usage, "output_tokens", None))
            if alert:
                self.audit.append("cost_alert", message=alert)
            if getattr(msg, "stop_reason", None) == "max_tokens":
                raise ModelOutputError(f"{purpose}: output was cut off at max_tokens={self.config.max_tokens}; "
                                       "raise it with OWASP_AI_AGENT_MAX_TOKENS")
            return text
        raise RuntimeError(f"{purpose}: API call failed after 3 attempts: {last_exc}")

    def complete_json(self, system: str, user: str, purpose: str):
        return extract_json(self.complete(system, user, purpose))
