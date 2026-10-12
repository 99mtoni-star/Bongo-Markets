#!/usr/bin/env python3
"""Expire unpaid orders and release their stock (ORD-LC-006), then release any other expired stock
reservations (STK-003). Run every minute from cron/systemd timer."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.catalog.stock import expire_all  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.db.session import session_factory  # noqa: E402
from app.orders.payments import expire_unpaid  # noqa: E402

if __name__ == "__main__":
    with session_factory(Settings())() as db:
        orders = expire_unpaid(db)
        n = expire_all(db)
        db.commit()
    print(f"unpaid orders expired: {orders}; expired reservations released: {n}")
