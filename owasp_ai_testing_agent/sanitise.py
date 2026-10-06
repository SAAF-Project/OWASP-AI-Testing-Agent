"""Untrusted-input handling and PII redaction (plan section 6: LLM01, LLM02).

Pattern detection here is a best-effort *alerting* aid. The real defence is structural: untrusted
data is delimited, size-capped, never reaches a shell, and every model output is schema-validated.
"""
from __future__ import annotations

import re

OPEN_TAG = "<untrusted_input>"
CLOSE_TAG = "</untrusted_input>"

_TAG_RE = re.compile(r"</?\s*untrusted_input\s*>", re.IGNORECASE)

INJECTION_PATTERNS = {
    "ignore-instructions": re.compile(r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above)\s+instructions", re.I),
    "role-override": re.compile(r"\byou\s+are\s+now\b|\bact\s+as\b|\bnew\s+instructions?\s*:", re.I),
    "system-marker": re.compile(r"^\s*(system|assistant)\s*:", re.I | re.M),
    "delimiter-attack": re.compile(r"</?\s*untrusted_input\s*>", re.I),
    "reveal-prompt": re.compile(r"(reveal|repeat|print)\s+(your\s+)?(system\s+)?(prompt|instructions)", re.I),
}


class InputTooLarge(ValueError):
    """An untrusted field exceeds the configured size cap."""


def detect_injection(text: str) -> list[str]:
    """Names of injection patterns found in text (for logging and alerting only)."""
    return [name for name, rx in INJECTION_PATTERNS.items() if rx.search(text)]


def wrap_untrusted(text: str, max_chars: int) -> str:
    """Delimit untrusted text for inclusion in a prompt.

    Oversized input is rejected instead of silently truncated: an audit must not run on a
    partial description without anyone noticing. Embedded delimiter tags are neutralised so the
    content cannot close its own trust boundary.
    """
    if len(text) > max_chars:
        raise InputTooLarge(f"input is {len(text)} characters; the limit is {max_chars}")
    cleaned = _TAG_RE.sub("[delimiter removed]", text)
    return f"{OPEN_TAG}\n{cleaned}\n{CLOSE_TAG}"


# --- PII / secret redaction -------------------------------------------------------------------

_REDACTIONS = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    ("API_KEY", re.compile(r"\b(?:sk-[A-Za-z0-9_\-]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9\-]{10,})\b")),
    ("BEARER", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{16,}", re.I)),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]


def redact_pii(text: str) -> str:
    """Replace e-mail addresses, API keys, bearer tokens and US SSNs with [REDACTED:<kind>].

    Regex based; the plan names Presidio, which is a heavier optional upgrade (see README).
    """
    for kind, rx in _REDACTIONS:
        text = rx.sub(f"[REDACTED:{kind}]", text)
    return text


def redact_obj(obj):
    """Apply redact_pii to every string in a JSON-like structure."""
    if isinstance(obj, str):
        return redact_pii(obj)
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj
