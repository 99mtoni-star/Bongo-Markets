"""Outbound SMS/email.

Production providers (e.g. an SMS gateway) are configured in M20. In development and
test the ``dev`` notifier keeps messages in memory so they can be shown on /dev/sms.
The production configuration validator refuses to start with the dev notifier.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol


@dataclass(frozen=True)
class Message:
    channel: str  # "sms" | "email"
    to: str
    body: str
    sent_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class Notifier(Protocol):
    def send(self, channel: str, to: str, body: str) -> None: ...


class DevNotifier:
    def __init__(self, keep: int = 50) -> None:
        self.outbox: deque[Message] = deque(maxlen=keep)

    def send(self, channel: str, to: str, body: str) -> None:
        self.outbox.appendleft(Message(channel, to, body))

    def last_to(self, to: str) -> Message | None:
        return next((m for m in self.outbox if m.to == to), None)


class UnconfiguredNotifier:
    """Placeholder until the production provider adapter lands (M20). Fails loudly on use."""

    def __init__(self, name: str) -> None:
        self.name = name

    def send(self, channel: str, to: str, body: str) -> None:
        raise RuntimeError(f"notifier '{self.name}' has no provider adapter yet (M20)")


def build_notifier(name: str) -> Notifier:
    return DevNotifier() if name == "dev" else UnconfiguredNotifier(name)
