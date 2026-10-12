"""Identifier normalization (AUTH-002, ID-002)."""

from __future__ import annotations

import re

import phonenumbers

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[a-z]{2,24}$")


class IdentifierError(ValueError):
    pass


def normalize_phone(raw: str, default_region: str = "TZ") -> str:
    """Return E.164 (e.g. +255712345678). Accepts local formats such as 0712 345 678."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 32:
        raise IdentifierError("Namba ya simu si sahihi.")
    try:
        number = phonenumbers.parse(raw, default_region)
    except phonenumbers.NumberParseException as exc:
        raise IdentifierError("Namba ya simu si sahihi.") from exc
    if not phonenumbers.is_valid_number(number):
        raise IdentifierError("Namba ya simu si sahihi.")
    return phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)


def normalize_email(raw: str) -> str:
    """Trimmed and lower-cased (AUTH-002)."""
    email = (raw or "").strip().lower()
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise IdentifierError("Barua pepe si sahihi.")
    return email


def classify(identifier: str, default_region: str = "TZ") -> tuple[str, str]:
    """Return ("email"|"phone", normalized) for a login/reset identifier."""
    if "@" in (identifier or ""):
        return "email", normalize_email(identifier)
    return "phone", normalize_phone(identifier, default_region)


def mask_phone(e164: str) -> str:
    return e164[:6] + "*" * max(len(e164) - 9, 0) + e164[-3:] if len(e164) > 9 else "***"
