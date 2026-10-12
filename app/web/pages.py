"""Server-rendered system status page (Swahili). No JavaScript; all values escaped."""

from __future__ import annotations

from html import escape

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.api.health import database_status
from app.core.modules import MODULES, TOTAL_REQUIREMENTS, ModuleStatus
from app.web.layout import page

router = APIRouter(include_in_schema=False)

STATUS_LABEL = {
    ModuleStatus.NOT_STARTED: ("Haijaanza", "todo"),
    ModuleStatus.DESIGN_READY: ("Muundo tayari", "design"),
    ModuleStatus.DEVELOPER_COMPLETE: ("Imejengwa – inasubiri ukaguzi", "built"),
    ModuleStatus.CLOSED: ("Imefungwa", "closed"),
}




@router.get("/", response_class=HTMLResponse)
def status_page(request: Request) -> HTMLResponse:
    s = request.app.state.settings
    built = sum(1 for m in MODULES if m.status in (ModuleStatus.DEVELOPER_COMPLETE, ModuleStatus.CLOSED))
    covered = sum(m.requirements for m in MODULES if m.status in (ModuleStatus.DEVELOPER_COMPLETE, ModuleStatus.CLOSED))
    pct = round(covered * 100 / TOTAL_REQUIREMENTS, 1)
    db = database_status(request)
    if db.get("database") == "ok":
        db_value = "OK"
        db_label = f"{db['server']} \u00b7 migrations: {db['migrations']}"
    else:
        db_value = "HAIPATIKANI"
        db_label = "Database haipatikani"

    rows = []
    for m in MODULES:
        label, cls = STATUS_LABEL[m.status]
        rows.append(
            f"<tr><td><b>{escape(m.code)}</b></td>"
            f"<td>{escape(m.name)}<small>{escape(m.name_sw)}</small></td>"
            f"<td class='hide-sm'>{m.requirements}</td>"
            f"<td><span class='pill {cls}'>{escape(label)}</span></td></tr>"
        )

    body = f"""<div class="hero"><h1>Hali ya ujenzi wa mfumo</h1>
<p>Toleo {escape(s.version)} · mazingira: {escape(s.environment.value)}</p></div>
<div class="stats">
<div class="stat"><b>{built} / {len(MODULES)}</b><span>Module zilizojengwa</span></div>
<div class="stat"><b>{covered} / {TOTAL_REQUIREMENTS}</b><span>Mahitaji yaliyoshughulikiwa</span>
<div class="bar"><i style="width:{pct}%"></i></div></div>
<div class="stat"><b>OK</b><span>Server inafanya kazi (/health/live)</span></div>
<div class="stat"><b>{escape(db_value)}</b><span>{escape(db_label)}</span></div>
</div>
<table><thead><tr><th>Module</th><th>Jina</th><th class="hide-sm">Mahitaji</th><th>Hali</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<footer>Chanzo: KAR-PROJ-SA-RTM-006 v1.3 · "Imejengwa" si ruhusa ya production; ruhusa hutolewa na M20.</footer>"""
    html = page("Hali ya Mfumo", body)
    return HTMLResponse(html)
