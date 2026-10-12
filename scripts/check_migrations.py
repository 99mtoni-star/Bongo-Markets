#!/usr/bin/env python3
"""SEC-SDLC-004: migrations that touch authentication, authorization, financial,
audit or personal data must carry an explicit review line:

    Sensitive-Review: approved by <reviewer> <YYYY-MM-DD>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SENSITIVE = re.compile(
    r"(?i)\b(audit|users?|roles?|permissions?|sessions?|password|mfa|otp|token|payments?|refunds?|ledger|"
    r"settlements?|commissions?|donations?|orders?|address(es)?|phone|email|grant|revoke|privilege)\b"
)
APPROVED = re.compile(r"Sensitive-Review:\s*approved by\s+\S.*\d{4}-\d{2}-\d{2}")


def body_without_review(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if "Sensitive-Review:" not in line)


def check(versions_dir: Path = ROOT / "migrations" / "versions") -> list[str]:
    problems = []
    for path in sorted(versions_dir.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        if SENSITIVE.search(body_without_review(text)) and not APPROVED.search(text):
            problems.append(f"{path.name}: touches sensitive data but has no 'Sensitive-Review: approved by ...' line")
    return problems


def main() -> int:
    problems = check()
    if problems:
        print("MIGRATION REVIEW CHECK: FAIL")
        print("\n".join("  - " + p for p in problems))
        return 1
    print("MIGRATION REVIEW CHECK: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
