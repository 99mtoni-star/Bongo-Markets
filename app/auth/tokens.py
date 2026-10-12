"""Random secrets and their at-rest hashes."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from app.core.config import Settings


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def keyed_hash(settings: Settings, purpose: str, value: str) -> str:
    """HMAC-SHA256 with the server secret. Used for OTPs (low entropy, so a plain hash
    would be brute-forceable offline) and for pseudonymous IP/identifier keys."""
    key = settings.secret_key.get_secret_value().encode()
    return hmac.new(key, f"{purpose}:{value}".encode(), hashlib.sha256).hexdigest()


def equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
