#!/usr/bin/env python3
"""DEV-004: verify every test ID exists exactly once in the authoritative catalogue,
and every catalogue entry is implemented by exactly one test."""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "tests" / "catalogue.yaml"
TID_RE = re.compile(r"""pytest\.mark\.tid\(\s*["']([A-Z0-9]+-T\d{3})["']\s*\)""")
ID_RE = re.compile(r"^M(0[1-9]|1[0-9]|20)-T\d{3}$")


def collect_test_ids(tests_dir: Path) -> Counter:
    ids: Counter = Counter()
    for path in sorted(tests_dir.rglob("test_*.py")):
        ids.update(TID_RE.findall(path.read_text(encoding="utf-8")))
    return ids


def check(catalogue_path: Path = CATALOGUE, tests_dir: Path | None = None) -> list[str]:
    tests_dir = tests_dir or catalogue_path.parent
    data = yaml.safe_load(catalogue_path.read_text(encoding="utf-8")) or {}
    entries = data.get("tests", [])
    errors: list[str] = []

    cat_ids = Counter(e.get("id") for e in entries)
    for tid, n in cat_ids.items():
        if n > 1:
            errors.append(f"catalogue: {tid} appears {n} times")
    for e in entries:
        tid = e.get("id", "")
        if not ID_RE.match(tid or ""):
            errors.append(f"catalogue: invalid id {tid!r}")
        if not e.get("requirements"):
            errors.append(f"catalogue: {tid} has no requirement trace")
        if tid and e.get("module") != tid.split("-")[0]:
            errors.append(f"catalogue: {tid} module field does not match id prefix")

    impl = collect_test_ids(tests_dir)
    for tid, n in impl.items():
        if n > 1:
            errors.append(f"tests: {tid} implemented {n} times")
        if tid not in cat_ids:
            errors.append(f"tests: {tid} is not in the catalogue")
    for tid in cat_ids:
        if tid not in impl:
            errors.append(f"catalogue: {tid} has no implementing test")
    return errors


def main() -> int:
    errors = check()
    if errors:
        print("TEST CATALOGUE CHECK: FAIL")
        for e in errors:
            print("  -", e)
        return 1
    print("TEST CATALOGUE CHECK: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
