#!/usr/bin/env python3
"""DEV-006: run commands and capture an evidence bundle.

Each record captures: command, UTC start/end timestamps, environment summary,
tool versions, stdout/stderr, exit code and SHA-256 of the output. A manifest
lists every file with its hash plus a bundle digest over the manifest.

Usage: python scripts/evidence.py --module M01 -- "pytest -q" "ruff check ."
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAFE_ENV_KEYS = ("BM_ENVIRONMENT", "CI", "PYTHONHASHSEED")


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def tool_versions() -> dict:
    versions = {"python": platform.python_version()}
    for pkg in ("fastapi", "pydantic", "sqlalchemy", "pytest", "ruff"):
        try:
            from importlib.metadata import version

            versions[pkg] = version(pkg)
        except Exception:
            versions[pkg] = "not-installed"
    try:
        versions["git_commit"] = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False
        ).stdout.strip() or "uncommitted"
    except FileNotFoundError:
        versions["git_commit"] = "git-unavailable"
    return versions


def run_bundle(module: str, commands: list[str], out_root: Path) -> tuple[Path, int]:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = out_root / module / stamp
    out.mkdir(parents=True, exist_ok=True)

    env_summary = {
        "os": platform.platform(),
        "machine": platform.machine(),
        "env": {k: os.environ.get(k) for k in SAFE_ENV_KEYS if k in os.environ},
    }
    records = []
    worst = 0
    for i, cmd in enumerate(commands, start=1):
        started = utc_now()
        proc = subprocess.run(shlex.split(cmd), cwd=ROOT, capture_output=True)
        ended = utc_now()
        log_name = f"{i:02d}.log"
        body = b"$ " + cmd.encode() + b"\n--- stdout ---\n" + proc.stdout + b"\n--- stderr ---\n" + proc.stderr
        (out / log_name).write_bytes(body)
        records.append({
            "step": i, "command": cmd, "started_utc": started, "ended_utc": ended,
            "exit_code": proc.returncode, "log": log_name, "log_sha256": sha256_bytes(body),
        })
        worst = worst or proc.returncode

    evidence = {
        "module": module, "generated_utc": utc_now(), "environment": env_summary,
        "versions": tool_versions(), "records": records,
        "result": "PASS" if worst == 0 else "FAIL",
    }
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    manifest = {p.name: sha256_bytes(p.read_bytes()) for p in sorted(out.iterdir()) if p.is_file()}
    manifest_text = "".join(f"{h}  {name}\n" for name, h in manifest.items())
    (out / "MANIFEST.sha256").write_text(manifest_text, encoding="utf-8")
    (out / "BUNDLE_DIGEST").write_text(sha256_bytes(manifest_text.encode()) + "\n", encoding="utf-8")
    return out, worst


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", required=True)
    ap.add_argument("--out", default=str(ROOT / "evidence"))
    ap.add_argument("commands", nargs="+")
    args = ap.parse_args()
    out, code = run_bundle(args.module, args.commands, Path(args.out))
    digest = (out / "BUNDLE_DIGEST").read_text().strip()
    print(f"Evidence: {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out}")
    print(f"Bundle digest: {digest}")
    print("RESULT:", "PASS" if code == 0 else "FAIL")
    return code


if __name__ == "__main__":
    sys.exit(main())
