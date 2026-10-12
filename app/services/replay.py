"""Replay protection for timestamped, identified events (V13-SEC-002).

Used by every inbound signed event (payment webhooks in M13, provider callbacks):
the event timestamp must be within the replay window and its ID must not have been
processed before. The check and the insert happen atomically.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.auth.models import ProcessedEvent

REPLAY_WINDOW = timedelta(minutes=5)


class ReplayRejected(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def accept_event(db: Session, *, source: str, event_id: str, event_time: datetime,
                 now: datetime | None = None, window: timedelta = REPLAY_WINDOW) -> None:
    """Raise ReplayRejected unless the event is fresh and unseen. Caller commits."""
    now = now or datetime.now(UTC)
    if not source or not event_id or len(event_id) > 128:
        raise ReplayRejected("missing_or_invalid_event_id")
    if event_time.tzinfo is None:
        raise ReplayRejected("timestamp_without_timezone")
    if abs(now - event_time) > window:
        raise ReplayRejected("outside_replay_window")
    stmt = insert(ProcessedEvent).values(source=source, event_id=event_id, event_time=event_time) \
        .on_conflict_do_nothing(index_elements=[ProcessedEvent.source, ProcessedEvent.event_id]) \
        .returning(ProcessedEvent.event_id)
    if db.execute(stmt).first() is None:
        raise ReplayRejected("duplicate_event")
