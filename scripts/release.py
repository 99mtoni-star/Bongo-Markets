#!/usr/bin/env python3
"""Release checksums (SEC-CFG-006).

  make    Write RELEASE.SHA256SUMS for every git-tracked file (run when cutting a release).
  verify  Recompute and compare. Any mismatch, missing file or unlisted tracked file
          rejects the release. Run before migration or deployment.

Usage: python scripts/release.py make|verify [--root DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

MANIFEST = "RELEASE.SHA256SUMS"


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True).stdout
    return sorted(f for f in out.splitlines() if f and f != MANIFEST)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make(root: Path) -> Path:
    lines = [f"{digest(root / f)}  {f}" for f in tracked_files(root)]
    out = root / MANIFEST
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def verify(root: Path, files: list[str] | None = None) -> list[str]:
    manifest = root / MANIFEST
    if not manifest.exists():
        return [f"{MANIFEST} is missing"]
    expected: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if line.strip():
            h, name = line.split("  ", 1)
            expected[name] = h
    problems = []
    for name, h in expected.items():
        p = root / name
        if not p.exists():
            problems.append(f"MISSING  {name}")
        elif digest(p) != h:
            problems.append(f"MISMATCH {name}")
    for name in files if files is not None else tracked_files(root):
        if name not in expected:
            problems.append(f"UNLISTED {name}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["make", "verify"])
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = ap.parse_args()
    if args.mode == "make":
        print(f"wrote {make(args.root)}")
        return 0
    problems = verify(args.root)
    if problems:
        print("RELEASE VERIFICATION: REJECTED")
        print("\n".join("  " + p for p in problems))
        return 1
    print("RELEASE VERIFICATION: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
