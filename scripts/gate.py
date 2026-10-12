#!/usr/bin/env python3
"""Developer Complete gate (STD-002 / DEV-005).

Order: lint -> catalogue check -> focused tests for the module ->
full regression of protected controls -> full suite. Stops at first failure.

Usage: python scripts/gate.py M01
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def step(title: str, cmd: list[str]) -> None:
    print(f"\n=== {title} ===\n$ {' '.join(cmd)}", flush=True)
    rc = subprocess.run(cmd, cwd=ROOT).returncode
    if rc != 0:
        print(f"\nGATE FAILED at: {title} (exit {rc})")
        sys.exit(rc)


def main() -> None:
    if len(sys.argv) != 2 or not sys.argv[1].startswith("M"):
        print("usage: gate.py M01")
        sys.exit(2)
    module = sys.argv[1]
    py = sys.executable
    step("Lint", [py, "-m", "ruff", "check", "."])
    step("Test catalogue", [py, "scripts/check_catalogue.py"])
    step(f"Focused tests {module}", [py, "-m", "pytest", "-q", "-m", f"module_{module.lower()}"])
    step("Protected-control regression", [py, "-m", "pytest", "-q", "-m", "protected"])
    step("Full regression", [py, "-m", "pytest", "-q"])
    print(f"\nGATE PASSED for {module} (Developer Complete is not independent closure – DEV-007)")


if __name__ == "__main__":
    main()
