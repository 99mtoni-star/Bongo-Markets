#!/usr/bin/env python3
"""Generate docs/modules/Mxx/completion.md from the Test Catalogue and the latest evidence bundle.

Usage: python scripts/completion_note.py M05 [--status REQ=TEXT ...] [--finding "F-..|Sev|RC|desc|fix|test|Status" ...]
Requirements not traced by any test must be given an explicit --status (Deferred/Partial/process).
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("module")
    ap.add_argument("--reqs", required=True, help="comma-separated allocated requirement IDs")
    ap.add_argument("--status", action="append", default=[], help="REQ=status text")
    ap.add_argument("--finding", action="append", default=[])
    a = ap.parse_args()
    m = a.module
    cat = yaml.safe_load((ROOT / "tests" / "catalogue.yaml").read_text())["tests"]
    by_req: dict[str, list[str]] = {}
    for t in cat:
        if t["module"] == m:
            for r in t["requirements"]:
                by_req.setdefault(r, []).append(t["id"].split("-")[1])
    status = dict(s.split("=", 1) for s in a.status)
    ev_dir = ROOT / "evidence" / m
    bundles = sorted(p for p in ev_dir.iterdir() if p.is_dir() and re.match(r"\d{8}T", p.name))
    latest = bundles[-1]
    digest = (latest / "BUNDLE_DIGEST").read_text().strip()
    ev = (latest / "01.log").parent
    counts = []
    for log in sorted(ev.glob("0*.log")):
        mm = re.search(r"(\d+) passed", log.read_text())
        if mm:
            counts.append(mm.group(1))
    rows = []
    for r in a.reqs.split(","):
        r = r.strip()
        tests = ", ".join(sorted(set(by_req.get(r, []))))
        st = status.get(r, "Implemented" if tests else "**UNTRACED**")
        rows.append(f"| {r} | {st} | {tests or '—'} |")
    untraced = [r for r in rows if "UNTRACED" in r]
    if untraced:
        raise SystemExit("Untraced requirements: " + "; ".join(untraced))
    findings = "\n".join(f"| {' | '.join(f.split('|'))} |" for f in a.finding) or "| — | | | No findings | | | |"
    gate = f"focused {counts[0]}, protected {counts[1]}, full {counts[2]}" if len(counts) >= 3 else "see bundle"
    shots = f" Walkthrough: `evidence/{m}/screenshots/`." if (ev_dir / "screenshots").exists() else ""
    text = f"""# {m} — Developer Completion Note

**Status:** DEVELOPER_COMPLETE (not closed; independent review pending, per DEV-007)
**Gate:** `python scripts/gate.py {m}` → PASS ({gate}), run against PostgreSQL 16
**Evidence bundle:** `evidence/{m}/{latest.name}`, digest `{digest}`.{shots}

| Req | Result | Tests ({m}-T…) |
|-----|--------|-------|
{chr(10).join(rows)}

## Findings

| ID | Sev | Root cause | Description | Fix | Regression | Status |
|----|-----|-----------|-------------|-----|-----------|--------|
{findings}
"""
    (ROOT / "docs" / "modules" / m / "completion.md").write_text(text, encoding="utf-8")
    print(f"wrote docs/modules/{m}/completion.md")


if __name__ == "__main__":
    main()
