"""Written authorisation for live tests (plan section 6, LLM06).

The system owner mints a signed token naming the one host that may be tested and an expiry. The
agent refuses to send anything unless the token verifies. Token format is a proposal (plan open
question: it was unspecified). Signing is HMAC-SHA256 with a shared secret, which proves the token
was minted by someone holding the secret and was not edited; it does not prove who that person is.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

SECRET_ENV = "OWASP_AI_AUTH_SECRET"
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class AuthorisationError(PermissionError):
    pass


def _secret() -> bytes:
    secret = os.environ.get(SECRET_ENV, "")
    if len(secret) < 16:
        raise AuthorisationError(f"set {SECRET_ENV} to a secret of at least 16 characters")
    return secret.encode("utf-8")


def _canonical(fields: dict) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(fields: dict) -> str:
    return hmac.new(_secret(), _canonical(fields), hashlib.sha256).hexdigest()


def mint(target_host: str, authorised_by: str, valid_hours: float = 24,
         allow_adversarial: bool = False, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    fields = {
        "target_host": target_host.lower(),
        "authorised_by": authorised_by,
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(hours=valid_hours)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "allow_adversarial": allow_adversarial,
    }
    return {**fields, "signature": _sign(fields)}


@dataclass(frozen=True)
class Authorisation:
    target_host: str
    authorised_by: str
    expires_at: datetime
    allow_adversarial: bool

    def check_url(self, url: str) -> None:
        """Raise unless url points at the authorised host (https, or http for loopback only)."""
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if host != self.target_host:
            raise AuthorisationError(f"{host or url!r} is not the authorised host {self.target_host!r}")
        if parsed.scheme != "https" and not (parsed.scheme == "http" and host in _LOCAL_HOSTS):
            raise AuthorisationError("target must use https (http is allowed for loopback hosts only)")


def verify(token: dict, now: datetime | None = None) -> Authorisation:
    now = now or datetime.now(timezone.utc)
    try:
        fields = {k: token[k] for k in ("target_host", "authorised_by", "issued_at", "expires_at", "allow_adversarial")}
        signature = token["signature"]
    except (KeyError, TypeError) as exc:
        raise AuthorisationError(f"token is missing a field: {exc}") from exc
    if not hmac.compare_digest(_sign(fields), str(signature)):
        raise AuthorisationError("token signature is invalid (edited, or minted with a different secret)")
    expires = datetime.strptime(fields["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if now >= expires:
        raise AuthorisationError(f"token expired at {fields['expires_at']}")
    return Authorisation(fields["target_host"], fields["authorised_by"], expires, bool(fields["allow_adversarial"]))
