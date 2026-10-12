#!/usr/bin/env python3
"""Release expired stock reservations (STK-003). Run every minute from cron/systemd timer."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.catalog.stock import expire_all  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.db.session import session_factory  # noqa: E402

if __name__ == "__main__":
    with session_factory(Settings())() as db:
        n = expire_all(db)
        db.commit()
    print(f"expired reservations released: {n}")
