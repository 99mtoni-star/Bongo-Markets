"""Password hashing and policy (AUTH-003, SEC-001, SEC-PWD-001/003/004).

Argon2id parameters (documented in docs/security/password-hashing.md):
  memory 64 MiB, iterations 3, parallelism 2, 16-byte salt, 32-byte hash.
These exceed the OWASP minimum (19 MiB, t=2, p=1). Hashes created with older
parameters are upgraded transparently at the next successful login.
"""

from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.auth.common_passwords import COMMON_PASSWORDS

MIN_LENGTH = 8
# Generous ceiling so nothing is ever silently truncated (SEC-PWD-004). Longer input is
# rejected with an explicit error, not cut short. Argon2 has no 72-byte limit like bcrypt.
MAX_LENGTH = 256

HASHER = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2, hash_len=32, salt_len=16,
                        type=Type.ID)
# Used to equalize timing when an account does not exist.
_DUMMY_HASH = HASHER.hash("timing-equalizer-not-a-real-password")


class PasswordPolicyError(ValueError):
    """Raised with a Swahili message suitable for the user."""


def check_policy(password: str, *, personal: list[str] | None = None) -> None:
    if len(password) < MIN_LENGTH:
        raise PasswordPolicyError(f"Nenosiri liwe na angalau herufi {MIN_LENGTH}.")
    if len(password) > MAX_LENGTH:
        raise PasswordPolicyError(f"Nenosiri lisizidi herufi {MAX_LENGTH}.")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS or len(set(lowered)) <= 2:
        raise PasswordPolicyError("Nenosiri hili ni maarufu sana na ni rahisi kukisia. Chagua jingine.")
    for item in personal or []:
        item = (item or "").lower().lstrip("+")
        if len(item) >= 4 and (item in lowered or lowered in item):
            raise PasswordPolicyError("Nenosiri lisiwe na jina lako, namba ya simu au barua pepe.")


def hash_password(password: str) -> str:
    return HASHER.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Constant-work verification; returns False on any mismatch or malformed hash."""
    try:
        return HASHER.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return HASHER.check_needs_rehash(stored_hash)
