#!/usr/bin/env python3
"""Secret scanning for release control (SEC-SDLC-002).

Scans every git-tracked file for high-confidence credential patterns and for committed .env
files. A line may be exempted only with an inline `scan:allow` marker and a reason.
Usage: python scripts/scan_secrets.py [--root DIR]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

PATTERNS = {
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "stripe-live-key": re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}\b"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "generic-secret-assignment": re.compile(
        r"""(?i)\b(?:secret_key|api_key|apikey|access_token|auth_token|client_secret)\s*[:=]\s*["'][A-Za-z0-9/+_=-]{24,}["']"""
    ),
}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".pdf", ".zip", ".ico"}


def tracked(root: Path) -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True).stdout
    return [f for f in out.splitlines() if f]


def scan(root: Path, files: list[str] | None = None) -> list[str]:
    findings = []
    for name in files if files is not None else tracked(root):
        path = root / name
        if Path(name).name in (".env", ".env.local", ".env.production"):
            findings.append(f"{name}: environment file must never be committed")
            continue
        if path.suffix.lower() in SKIP_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if "scan:allow" in line:
                continue
            for kind, pat in PATTERNS.items():
                if pat.search(line):
                    findings.append(f"{name}:{lineno}: possible {kind}")
    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    findings = scan(ap.parse_args().root)
    if findings:
        print("SECRET SCAN: FAIL")
        print("\n".join("  - " + f for f in findings))
        return 1
    print("SECRET SCAN: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
