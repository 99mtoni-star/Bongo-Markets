"""Server-rendered system status page (Swahili). No JavaScript; all values escaped."""

from __future__ import annotations

from html import escape

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.core.modules import MODULES, TOTAL_REQUIREMENTS, ModuleStatus

router = APIRouter(include_in_schema=False)

STATUS_LABEL = {
    ModuleStatus.NOT_STARTED: ("Haijaanza", "todo"),
    ModuleStatus.DESIGN_READY: ("Muundo tayari", "design"),
    ModuleStatus.DEVELOPER_COMPLETE: ("Imejengwa – inasubiri ukaguzi", "built"),
    ModuleStatus.CLOSED: ("Imefungwa", "closed"),
}

CSS = """
:root{--bg:#f6f4ef;--card:#fff;--ink:#1d2a24;--muted:#5d6b64;--line:#e3ded3;--brand:#1f6f4a;
--todo:#9aa39e;--design:#b7791f;--built:#1f6f4a;--closed:#2b4c7e}
@media (prefers-color-scheme:dark){:root{--bg:#121714;--card:#1a211d;--ink:#e8efe9;--muted:#9fb0a6;
--line:#2a342e;--brand:#4fbf86;--built:#4fbf86}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{background:var(--brand);color:#fff;padding:28px 16px}
.wrap{max-width:980px;margin:0 auto;padding:0 16px}
header h1{margin:0;font-size:28px}header p{margin:4px 0 0;opacity:.9}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:20px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.stat b{display:block;font-size:26px}.stat span{color:var(--muted);font-size:14px}
.bar{height:10px;background:var(--line);border-radius:6px;overflow:hidden;margin-top:8px}
.bar i{display:block;height:100%;background:var(--brand)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);font-size:15px}
th{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
td small{display:block;color:var(--muted)}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:13px;color:#fff;white-space:nowrap}
.todo{background:var(--todo)}.design{background:var(--design)}.built{background:var(--built)}.closed{background:var(--closed)}
footer{color:var(--muted);font-size:13px;padding:20px 0 40px}
@media (max-width:600px){.hide-sm{display:none}.pill{white-space:normal;border-radius:10px}th,td{padding:10px 8px}}
"""


@router.get("/", response_class=HTMLResponse)
def status_page(request: Request) -> HTMLResponse:
    s = request.app.state.settings
    built = sum(1 for m in MODULES if m.status in (ModuleStatus.DEVELOPER_COMPLETE, ModuleStatus.CLOSED))
    covered = sum(m.requirements for m in MODULES if m.status in (ModuleStatus.DEVELOPER_COMPLETE, ModuleStatus.CLOSED))
    pct = round(covered * 100 / TOTAL_REQUIREMENTS, 1)

    rows = []
    for m in MODULES:
        label, cls = STATUS_LABEL[m.status]
        rows.append(
            f"<tr><td><b>{escape(m.code)}</b></td>"
            f"<td>{escape(m.name)}<small>{escape(m.name_sw)}</small></td>"
            f"<td class='hide-sm'>{m.requirements}</td>"
            f"<td><span class='pill {cls}'>{escape(label)}</span></td></tr>"
        )

    html = f"""<!doctype html><html lang="sw"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bongo Markets – Hali ya Mfumo</title><style>{CSS}</style></head><body>
<header><div class="wrap"><h1>Bongo Markets</h1>
<p>Hali ya ujenzi wa mfumo · toleo {escape(s.version)} · mazingira: {escape(s.environment.value)}</p></div></header>
<main class="wrap">
<div class="stats">
<div class="stat"><b>{built} / {len(MODULES)}</b><span>Module zilizojengwa</span></div>
<div class="stat"><b>{covered} / {TOTAL_REQUIREMENTS}</b><span>Mahitaji yaliyoshughulikiwa</span>
<div class="bar"><i style="width:{pct}%"></i></div></div>
<div class="stat"><b>OK</b><span>Server inafanya kazi (/health/live)</span></div>
</div>
<table><thead><tr><th>Module</th><th>Jina</th><th class="hide-sm">Mahitaji</th><th>Hali</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<footer>Chanzo: KAR-PROJ-SA-RTM-006 v1.3 · "Imejengwa" si ruhusa ya production; ruhusa hutolewa na M20.</footer>
</main></body></html>"""
    return HTMLResponse(html)
