"""Database-backed fixed-window rate limiting (SEC-009).

Counters are committed on their own connection so that a request which later fails
(and rolls back) still counts against the limit.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import Engine, delete
from sqlalchemy.dialects.postgresql import insert

from app.auth.models import RateLimitBucket


@dataclass(frozen=True)
class Limit:
    name: str
    max_hits: int
    window_seconds: int


# Policy table (documented in docs/security/rate-limits.md).
LOGIN_PER_IP = Limit("login-ip", 30, 300)
LOGIN_PER_ID = Limit("login-id", 10, 900)
REGISTER_PER_IP = Limit("register-ip", 10, 3600)
REGISTER_PER_PHONE = Limit("register-phone", 3, 3600)
OTP_VERIFY_PER_IP = Limit("otp-ip", 30, 900)
RESEND_PER_ID = Limit("resend-id", 3, 900)
RESET_PER_IP = Limit("reset-ip", 10, 3600)
RESET_PER_ID = Limit("reset-id", 3, 3600)
# SMS pumping / toll fraud (ID-011)
SMS_PER_DESTINATION = Limit("sms-dest", 6, 3600)
SMS_PER_IP = Limit("sms-ip", 20, 3600)
SMS_GLOBAL = Limit("sms-global", 2000, 3600)
STEP_UP_PER_USER = Limit("step-up-user", 10, 900)


class RateLimited(Exception):
    def __init__(self, retry_after: int):
        super().__init__("rate limited")
        self.retry_after = retry_after


def hit(engine: Engine, limit: Limit, subject: str, *, now: datetime | None = None) -> None:
    """Count one hit; raise RateLimited when the window is exhausted."""
    now = now or datetime.now(UTC)
    epoch = int(now.timestamp())
    window_start_epoch = epoch - epoch % limit.window_seconds
    window_start = datetime.fromtimestamp(window_start_epoch, UTC)
    key = f"{limit.name}:{subject}"[:200]
    stmt = insert(RateLimitBucket).values(key=key, window_start=window_start, count=1)
    stmt = stmt.on_conflict_do_update(
        index_elements=[RateLimitBucket.key, RateLimitBucket.window_start],
        set_={"count": RateLimitBucket.count + 1},
    ).returning(RateLimitBucket.count)
    with engine.begin() as conn:
        count = conn.execute(stmt).scalar_one()
        if epoch % 97 == 0:  # occasional housekeeping of expired windows
            conn.execute(delete(RateLimitBucket).where(
                RateLimitBucket.window_start < datetime.fromtimestamp(epoch - 86400, UTC)))
    if count > limit.max_hits:
        raise RateLimited(retry_after=window_start_epoch + limit.window_seconds - epoch)
