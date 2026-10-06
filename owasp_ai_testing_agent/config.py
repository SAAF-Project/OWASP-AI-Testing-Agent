"""Runtime configuration. Defaults are the limits from section 9 of the plan."""
from __future__ import annotations

import os
from dataclasses import dataclass

# Plan open question 6 (model choice) is undecided; override with OWASP_AI_AGENT_MODEL.
DEFAULT_MODEL = "claude-opus-4-6"


@dataclass(frozen=True)
class Config:
    model: str = DEFAULT_MODEL
    max_tokens: int = 2048              # per API call
    max_test_cases: int = 50            # per audit run
    max_input_chars: int = 50_000       # for SYSTEM_DESCRIPTION and other untrusted fields
    rag_retrieval_limit: int = 10       # chunks per query
    rate_limit_per_min: int = 10        # LLM requests and target requests, each per minute
    request_timeout_s: float = 30.0     # per request to the target system
    max_response_chars: int = 20_000    # target responses are cut off beyond this
    max_chunk_chars: int = 4_000        # retrieved corpus chunks are validated against this
    max_cases_per_category: int = 5     # Prompt 2 asks for 3-5

    @classmethod
    def from_env(cls) -> "Config":
        """OWASP_AI_AGENT_MODEL and OWASP_AI_AGENT_MAX_TOKENS override the defaults."""
        return cls(model=os.environ.get("OWASP_AI_AGENT_MODEL", DEFAULT_MODEL),
                   max_tokens=int(os.environ.get("OWASP_AI_AGENT_MAX_TOKENS", cls.max_tokens)))
