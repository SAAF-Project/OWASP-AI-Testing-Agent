"""Runtime configuration. Defaults are the limits from section 9 of the plan."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Plan open question 6 (model choice) is undecided; override with OWASP_AI_AGENT_MODEL.
DEFAULT_MODEL = "claude-opus-4-6"


def _float_env(name: str) -> float | None:
    raw = os.environ.get(name)
    return float(raw) if raw else None


@dataclass(frozen=True)
class Config:
    model: str = DEFAULT_MODEL
    max_tokens: int = 2048              # per API call
    temperature: float = 0.0            # as deterministic as the API allows; verdicts can still vary a little
    max_test_cases: int = 50            # per audit run
    max_input_chars: int = 50_000       # for SYSTEM_DESCRIPTION and other untrusted fields
    rag_retrieval_limit: int = 10       # chunks per query
    rate_limit_per_min: int = 10        # LLM requests and target requests, each per minute
    request_timeout_s: float = 30.0     # per request to the target system
    max_response_chars: int = 20_000    # target responses are cut off beyond this
    max_chunk_chars: int = 4_000        # retrieved corpus chunks are validated against this
    max_cases_per_category: int = 5     # Prompt 2 asks for 3-5
    # cost alert (usage.py). Prices are per million tokens, in euro, and must be supplied by the operator.
    cost_alert_threshold_eur: float = 5.0
    price_in_eur_per_mtok: float | None = None
    price_out_eur_per_mtok: float | None = None
    cost_hard_stop: bool = False        # True: refuse further calls once the daily threshold is reached
    usage_file: str = str(Path.home() / ".owasp-ai-testing-agent" / "usage.jsonl")

    @classmethod
    def from_env(cls) -> "Config":
        """Overrides: OWASP_AI_AGENT_MODEL, _MAX_TOKENS, _PRICE_IN_EUR_PER_MTOK, _PRICE_OUT_EUR_PER_MTOK,
        _COST_ALERT_EUR, _HARD_STOP (set to 1), _USAGE_FILE."""
        e = os.environ.get
        return cls(model=e("OWASP_AI_AGENT_MODEL", DEFAULT_MODEL),
                   max_tokens=int(e("OWASP_AI_AGENT_MAX_TOKENS", cls.max_tokens)),
                   price_in_eur_per_mtok=_float_env("OWASP_AI_AGENT_PRICE_IN_EUR_PER_MTOK"),
                   price_out_eur_per_mtok=_float_env("OWASP_AI_AGENT_PRICE_OUT_EUR_PER_MTOK"),
                   cost_alert_threshold_eur=float(e("OWASP_AI_AGENT_COST_ALERT_EUR", cls.cost_alert_threshold_eur)),
                   cost_hard_stop=e("OWASP_AI_AGENT_HARD_STOP") == "1",
                   usage_file=e("OWASP_AI_AGENT_USAGE_FILE", cls.usage_file))
