"""Server-rendered system status page (Swahili). No JavaScript; all values escaped."""

from __future__ import annotations

from html import escape

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from app.api.health import database_status
from app.auth.deps import optional_session
from app.auth.service import SessionContext
from app.auth.web import _html
from app.core.modules import MODULES, TOTAL_REQUIREMENTS, ModuleStatus

router = APIRouter(include_in_schema=False)

STATUS_LABEL = {
    ModuleStatus.NOT_STARTED: ("Haijaanza", "todo"),
    ModuleStatus.DESIGN_READY: ("Muundo tayari", "design"),
    ModuleStatus.DEVELOPER_COMPLETE: ("Imejengwa – inasubiri ukaguzi", "built"),
    ModuleStatus.CLOSED: ("Imefungwa", "closed"),
}




@router.get("/", response_class=HTMLResponse)
def home(request: Request, ctx: SessionContext | None = Depends(optional_session)) -> HTMLResponse:
    greet = f"Karibu tena, {escape(ctx.user.full_name.split()[0])}!" if ctx else "Karibu Bongo Markets"
    cta = ('<a class="btn" href="/soko">Ingia sokoni</a><a class="btn ghost" href="/maduka">Simamia maduka yako</a>'
           if ctx else
           '<a class="btn" href="/jisajili">Fungua akaunti</a><a class="btn ghost" href="/ingia">Ingia</a>')
    body = f"""<section class="hero big"><h1>{greet}</h1>
<p>Soko la mtandaoni la maduka mengi: nunua kutoka kwa wauzaji wengi, au fungua duka lako na uuze bidhaa zako,
kama kuku, mayai na zaidi, sehemu moja.</p><div class="cta">{cta}</div></section>
<div class="tiles">
<div class="tile"><h3>Nunua kwa usalama</h3><p>Bei na stock zinathibitishwa na mfumo, si na simu yako.</p></div>
<div class="tile"><h3>Uza bidhaa zako</h3><p>Fungua duka moja au zaidi, ongeza wasimamizi na wafanyakazi.</p></div>
<div class="tile"><h3>Akaunti salama</h3><p>Uthibitisho wa SMS, MFA ya programu na udhibiti wa vifaa vyako.</p></div>
</div>"""
    return _html(request, "Karibu", body, ctx=ctx)


@router.get("/hali", response_class=HTMLResponse)
def status_page(request: Request, ctx: SessionContext | None = Depends(optional_session)) -> HTMLResponse:
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
<progress class="bar" value="{covered}" max="{TOTAL_REQUIREMENTS}">{pct}%</progress></div>
<div class="stat"><b>OK</b><span>Server inafanya kazi (/health/live)</span></div>
<div class="stat"><b>{escape(db_value)}</b><span>{escape(db_label)}</span></div>
</div>
<table><thead><tr><th>Module</th><th>Jina</th><th class="hide-sm">Mahitaji</th><th>Hali</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<footer>Chanzo: KAR-PROJ-SA-RTM-006 v1.3 · "Imejengwa" si ruhusa ya production; ruhusa hutolewa na M20.</footer>"""
    return _html(request, "Hali ya Mfumo", body, ctx=ctx)


PRIVACY = """<div class="prose"><h1>Sera ya faragha</h1>
<p>Toleo la awali: litakamilishwa na mshauri wa sheria kabla ya kwenda live (M20).</p>
<h2>Taarifa tunazokusanya</h2><p>Jina, namba ya simu, barua pepe (si lazima), na historia ya oda zako. Hatukusanyi
eneo lako kwa siri (GPS) na hatukisii umri au jinsia yako.</p>
<h2>Muda wa kuhifadhi</h2><p>Ukifunga akaunti, taarifa zako binafsi zinafutwa (zinafanywa zisijulikane) baada ya
siku 365. Rekodi za fedha huhifadhiwa kwa miaka 10 kama sheria inavyotaka.</p>
<h2>Taarifa kwenda nje ya nchi</h2><p>Taarifa zako hazipelekwi nje ya Tanzania bila msingi wa kisheria
ulioidhinishwa na kinga zinazohitajika.</p>
<h2>Uvujaji wa taarifa</h2><p>Kukitokea uvujaji, tutakujulisha wewe na mamlaka husika kama sheria inavyotaka.</p></div>"""

TERMS = """<div class="prose"><h1>Masharti ya matumizi</h1>
<p>Toleo la awali: litakamilishwa kabla ya kwenda live (M20).</p>
<h2>Wauzaji</h2><p>Kila duka linawajibika kwa bidhaa zake. Bei na hali ya malipo huthibitishwa na mfumo.</p>
<h2>Wanunuzi</h2><p>Malipo yanathibitishwa na mtoa huduma wa malipo; hakuna mtu anayeweza kuweka oda kuwa
"imelipwa" kwa mkono.</p></div>"""


@router.get("/faragha", response_class=HTMLResponse)
def privacy(request: Request, ctx: SessionContext | None = Depends(optional_session)) -> HTMLResponse:
    return _html(request, "Faragha", PRIVACY, ctx=ctx)


@router.get("/masharti", response_class=HTMLResponse)
def terms(request: Request, ctx: SessionContext | None = Depends(optional_session)) -> HTMLResponse:
    return _html(request, "Masharti", TERMS, ctx=ctx)


