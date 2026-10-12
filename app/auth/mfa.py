"""TOTP (RFC 6238), secret encryption at rest and recovery codes (M04).

TOTP is the minimum second factor for privileged accounts (SEC-MFA-004, ID-007);
SMS/email OTP is never accepted as the sole MFA factor for them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import Settings

STEP_SECONDS = 30
DIGITS = 6
DRIFT_STEPS = 1  # accept the previous/next 30 s window for clock skew
RECOVERY_CODE_COUNT = 10
ISSUER = "Bongo Markets"


# ---------------------------------------------------------------- TOTP
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _b32decode(secret: str) -> bytes:
    padded = secret.upper() + "=" * (-len(secret) % 8)
    return base64.b32decode(padded)


def totp_at(secret: str, step: int) -> str:
    digest = hmac.new(_b32decode(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 10 ** DIGITS:0{DIGITS}d}"


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def verify_totp(secret: str, code: str, *, last_used_step: int | None, now: float | None = None) -> int | None:
    """Return the matched time step, or None.

    A step at or before ``last_used_step`` is refused, so a code can never be replayed
    (single-use within its window; V13-SEC-002 replay protection).
    """
    code = (code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    now_step = current_step(now)
    for step in range(now_step - DRIFT_STEPS, now_step + DRIFT_STEPS + 1):
        if last_used_step is not None and step <= last_used_step:
            continue
        if hmac.compare_digest(totp_at(secret, step), code):
            return step
    return None


def provisioning_uri(secret: str, account: str) -> str:
    label = quote(f"{ISSUER}:{account}")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}")


def qr_svg(data: str) -> str:
    import io

    import segno

    buf = io.BytesIO()
    segno.make(data, error="m").save(buf, kind="svg", scale=5, border=2, dark="#1d2a24", light="#ffffff",
                                     xmldecl=False, svgns=True)
    return buf.getvalue().decode()


# ---------------------------------------------------------------- secret encryption (AES-256-GCM)
def _key(settings: Settings) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"bongo-markets/totp/v1", info=b"totp-secret") \
        .derive(settings.secret_key.get_secret_value().encode())


def encrypt_secret(settings: Settings, secret: str, *, user_id: int) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(_key(settings)).encrypt(nonce, secret.encode(), f"user:{user_id}".encode())
    return "v1:" + base64.b64encode(nonce + ct).decode()


def decrypt_secret(settings: Settings, blob: str, *, user_id: int) -> str:
    if not blob.startswith("v1:"):
        raise ValueError("unknown TOTP secret format")
    raw = base64.b64decode(blob[3:])
    return AESGCM(_key(settings)).decrypt(raw[:12], raw[12:], f"user:{user_id}".encode()).decode()


# ---------------------------------------------------------------- recovery codes
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I confusion


def new_recovery_codes() -> list[str]:
    return ["-".join("".join(secrets.choice(_ALPHABET) for _ in range(5)) for _ in range(2))
            for _ in range(RECOVERY_CODE_COUNT)]


def normalize_recovery(code: str) -> str:
    c = (code or "").upper().replace(" ", "").replace("-", "")
    return f"{c[:5]}-{c[5:]}" if len(c) == 10 else c


def hash_recovery(code: str) -> str:
    # 50 bits of entropy per code; SHA-256 is adequate and lets us look codes up directly.
    return hashlib.sha256(normalize_recovery(code).encode()).hexdigest()
