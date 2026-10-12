"""Server-rendered Swahili pages for sign-up, sign-in and account security (M03).

Plain HTML forms (no JavaScript). Every POST is CSRF-protected; messages shown to the
user come from a fixed table, never from the query string.
"""

from __future__ import annotations

from html import escape
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.auth.deps import (
    check_csrf,
    clear_session_cookie,
    csrf_token,
    ensure_csrf_cookie,
    get_auth_service,
    optional_session,
    set_session_cookie,
)
from app.auth.identifiers import mask_phone
from app.auth.notify import DevNotifier
from app.auth.service import RESET_ACCEPTED, AuthError, AuthService, SessionContext
from app.web.layout import alert, field, page

router = APIRouter(include_in_schema=False)

NOTICES = {
    "imesajiliwa": ("Karibu! Akaunti yako iko tayari.", "ok"),
    "nenosiri-limerejeshwa": ("Nenosiri limerejeshwa. Ingia kwa nenosiri jipya.", "ok"),
    "nenosiri-limebadilishwa": ("Nenosiri limebadilishwa. Vifaa vingine vyote vimetolewa kwenye akaunti.", "ok"),
    "umetoka": ("Umetoka kwenye akaunti.", "ok"),
    "ingia-kwanza": ("Tafadhali ingia kwanza.", "err"),
}


def _html(request: Request, title: str, body: str, *, ctx: SessionContext | None = None,
          status: int = 200) -> HTMLResponse:
    csrf = csrf_token(request)
    resp = HTMLResponse(page(title, body, user_name=ctx.user.full_name if ctx else None, csrf=csrf),
                        status_code=status)
    ensure_csrf_cookie(request, resp)
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _notice(key: str | None) -> str:
    text, kind = NOTICES.get(key or "", (None, "ok"))
    return alert(text, kind)


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _csrf_input(request: Request) -> str:
    return f'<input type="hidden" name="csrf" value="{escape(csrf_token(request))}">'


# ------------------------------------------------------------------ register
def _register_form(request: Request, error: str | None = None, *, full_name: str = "", phone: str = "",
                   email: str = "") -> str:
    return f"""<div class="card"><h1>Fungua akaunti</h1>
<p class="sub">Nunua na uuze kwenye maduka mengi, sehemu moja.</p>{alert(error)}
<form method="post" action="/jisajili" novalidate>{_csrf_input(request)}
{field("full_name", "Jina kamili", value=full_name, extra='autocomplete="name" required')}
{field("phone", "Namba ya simu", type_="tel", value=phone, hint="mf. 0712 345 678",
       extra='autocomplete="tel" inputmode="tel" required')}
{field("email", "Barua pepe", type_="email", value=email, hint="(si lazima)", extra='autocomplete="email"')}
{field("password", "Nenosiri", type_="password", hint="angalau herufi 8",
       extra='autocomplete="new-password" required')}
<button class="primary" type="submit">Jisajili</button></form>
<div class="links"><span>Una akaunti tayari? <a href="/ingia">Ingia</a></span></div></div>"""


@router.get("/jisajili", response_class=HTMLResponse)
def register_page(request: Request, ctx: SessionContext | None = Depends(optional_session)):
    if ctx:
        return _redirect("/akaunti")
    return _html(request, "Jisajili", _register_form(request))


@router.post("/jisajili")
def register_submit(request: Request, csrf: str = Form(""), full_name: str = Form(""), phone: str = Form(""),
                    email: str = Form(""), password: str = Form(""), svc: AuthService = Depends(get_auth_service)):
    check_csrf(request, csrf)
    try:
        vid = svc.register(full_name=full_name[:200], phone=phone[:32], password=password[:1024],
                           email=email[:254] or None)
    except AuthError as exc:
        return _html(request, "Jisajili", _register_form(request, exc.message, full_name=full_name[:200],
                                                         phone=phone[:32], email=email[:254]),
                     status=exc.status)
    return _redirect(f"/thibitisha?v={quote(vid)}")


# ------------------------------------------------------------------ verify phone
def _verify_form(request: Request, vid: str, error: str | None = None, info: str | None = None) -> str:
    return f"""<div class="card"><h1>Thibitisha namba ya simu</h1>
<p class="sub">Tumekutumia SMS yenye namba ya tarakimu 6.</p>{alert(info, "ok")}{alert(error)}
<form method="post" action="/thibitisha">{_csrf_input(request)}
<input type="hidden" name="v" value="{escape(vid)}">
{field("code", "Namba ya uthibitisho", extra='class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required')}
<button class="primary" type="submit">Thibitisha</button></form>
<form method="post" action="/thibitisha/tuma-tena" class="links">{_csrf_input(request)}
<input type="hidden" name="v" value="{escape(vid)}"><span>Hukupata SMS?</span>
<button type="submit" style="background:none;border:0;color:var(--brand);font:inherit;cursor:pointer;padding:0">
Tuma tena</button></form></div>"""


@router.get("/thibitisha", response_class=HTMLResponse)
def verify_page(request: Request, v: str = ""):
    return _html(request, "Thibitisha", _verify_form(request, v[:64]))


@router.post("/thibitisha")
def verify_submit(request: Request, csrf: str = Form(""), v: str = Form(""), code: str = Form(""),
                  svc: AuthService = Depends(get_auth_service)):
    check_csrf(request, csrf)
    try:
        token = svc.verify_phone(v[:64], code[:12])
    except AuthError as exc:
        return _html(request, "Thibitisha", _verify_form(request, v[:64], exc.message), status=exc.status)
    resp = _redirect("/akaunti?ujumbe=imesajiliwa")
    set_session_cookie(resp, request, token)
    return resp


@router.post("/thibitisha/tuma-tena")
def resend_submit(request: Request, csrf: str = Form(""), v: str = Form(""),
                  svc: AuthService = Depends(get_auth_service)):
    check_csrf(request, csrf)
    try:
        new_vid = svc.resend_code(v[:64])
    except AuthError as exc:
        return _html(request, "Thibitisha", _verify_form(request, v[:64], exc.message), status=exc.status)
    return _html(request, "Thibitisha", _verify_form(request, new_vid, info="Tumetuma namba mpya kwa SMS."))


# ------------------------------------------------------------------ login
def _login_form(request: Request, error: str | None = None, notice: str = "", identifier: str = "") -> str:
    return f"""<div class="card"><h1>Ingia</h1><p class="sub">Karibu tena Bongo Markets.</p>{notice}{alert(error)}
<form method="post" action="/ingia">{_csrf_input(request)}
{field("identifier", "Namba ya simu au barua pepe", value=identifier, extra='autocomplete="username" required')}
{field("password", "Nenosiri", type_="password", extra='autocomplete="current-password" required')}
<button class="primary" type="submit">Ingia</button></form>
<div class="links"><a href="/umesahau-nenosiri">Umesahau nenosiri?</a>
<span>Huna akaunti? <a href="/jisajili">Jisajili</a></span></div></div>"""


@router.get("/ingia", response_class=HTMLResponse)
def login_page(request: Request, ujumbe: str = "", ctx: SessionContext | None = Depends(optional_session)):
    if ctx:
        return _redirect("/akaunti")
    return _html(request, "Ingia", _login_form(request, notice=_notice(ujumbe)))


@router.post("/ingia")
def login_submit(request: Request, csrf: str = Form(""), identifier: str = Form(""), password: str = Form(""),
                 svc: AuthService = Depends(get_auth_service)):
    check_csrf(request, csrf)
    try:
        token = svc.login(identifier[:254], password[:1024])
    except AuthError as exc:
        if exc.code == "verification_required" and exc.verification_id:
            return _redirect(f"/thibitisha?v={quote(exc.verification_id)}")
        return _html(request, "Ingia", _login_form(request, exc.message, identifier=identifier[:254]),
                     status=exc.status)
    resp = _redirect("/akaunti")
    set_session_cookie(resp, request, token)
    return resp


@router.post("/toka")
def logout_submit(request: Request, csrf: str = Form(""), ctx: SessionContext | None = Depends(optional_session),
                  svc: AuthService = Depends(get_auth_service)):
    check_csrf(request, csrf)
    if ctx:
        svc.logout(ctx)
    resp = _redirect("/ingia?ujumbe=umetoka")
    clear_session_cookie(resp, request)
    return resp


# ------------------------------------------------------------------ account
def _account_body(request: Request, ctx: SessionContext, notice: str = "", error: str | None = None) -> str:
    u = ctx.user
    email = escape(u.email) + (" ✓" if u.email_verified_at else " (haijathibitishwa)") if u.email else "—"
    return f"""<div class="card"><h1>Akaunti yangu</h1><p class="sub">Habari, {escape(u.full_name)}.</p>{notice}
<dl><dt>Jina</dt><dd>{escape(u.full_name)}</dd>
<dt>Simu</dt><dd>{escape(mask_phone(u.phone_e164))} ✓</dd>
<dt>Barua pepe</dt><dd>{email}</dd>
<dt>Hali</dt><dd>Akaunti hai</dd></dl></div>
<div class="card"><h1 style="font-size:20px">Badilisha nenosiri</h1>
<p class="sub">Ukibadilisha, vifaa vingine vyote vitatolewa kwenye akaunti.</p>{alert(error)}
<form method="post" action="/akaunti/nenosiri">{_csrf_input(request)}
{field("current_password", "Nenosiri la sasa", type_="password", extra='autocomplete="current-password" required')}
{field("new_password", "Nenosiri jipya", type_="password", hint="angalau herufi 8",
       extra='autocomplete="new-password" required')}
<button class="primary" type="submit">Badilisha nenosiri</button></form></div>"""


@router.get("/akaunti", response_class=HTMLResponse)
def account_page(request: Request, ujumbe: str = "", ctx: SessionContext | None = Depends(optional_session)):
    if not ctx:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    return _html(request, "Akaunti", _account_body(request, ctx, _notice(ujumbe)), ctx=ctx)


@router.post("/akaunti/nenosiri")
def change_password_submit(request: Request, csrf: str = Form(""), current_password: str = Form(""),
                           new_password: str = Form(""), ctx: SessionContext | None = Depends(optional_session),
                           svc: AuthService = Depends(get_auth_service)):
    check_csrf(request, csrf)
    if not ctx:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    try:
        token = svc.change_password(ctx, current_password[:1024], new_password[:1024])
    except AuthError as exc:
        return _html(request, "Akaunti", _account_body(request, ctx, error=exc.message), ctx=ctx,
                     status=exc.status)
    resp = _redirect("/akaunti?ujumbe=nenosiri-limebadilishwa")
    set_session_cookie(resp, request, token)
    return resp


# ------------------------------------------------------------------ forgot / reset
def _forgot_form(request: Request, error: str | None = None) -> str:
    return f"""<div class="card"><h1>Umesahau nenosiri?</h1>
<p class="sub">Andika namba ya simu uliyojisajili nayo. Tutakutumia namba ya kurejesha.</p>{alert(error)}
<form method="post" action="/umesahau-nenosiri">{_csrf_input(request)}
{field("identifier", "Namba ya simu au barua pepe", extra='autocomplete="username" required')}
<button class="primary" type="submit">Tuma namba</button></form>
<div class="links"><a href="/ingia">Rudi kuingia</a></div></div>"""


@router.get("/umesahau-nenosiri", response_class=HTMLResponse)
def forgot_page(request: Request):
    return _html(request, "Umesahau nenosiri", _forgot_form(request))


@router.post("/umesahau-nenosiri")
def forgot_submit(request: Request, csrf: str = Form(""), identifier: str = Form(""),
                  svc: AuthService = Depends(get_auth_service)):
    check_csrf(request, csrf)
    try:
        rid = svc.forgot_password(identifier[:254])
    except AuthError as exc:
        return _html(request, "Umesahau nenosiri", _forgot_form(request, exc.message), status=exc.status)
    return _redirect(f"/weka-nenosiri-upya?r={quote(rid)}")


def _reset_form(request: Request, rid: str, error: str | None = None) -> str:
    return f"""<div class="card"><h1>Weka nenosiri jipya</h1>{alert(RESET_ACCEPTED, "ok")}{alert(error)}
<form method="post" action="/weka-nenosiri-upya">{_csrf_input(request)}
<input type="hidden" name="r" value="{escape(rid)}">
{field("code", "Namba uliyotumiwa", extra='class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required')}
{field("new_password", "Nenosiri jipya", type_="password", hint="angalau herufi 8",
       extra='autocomplete="new-password" required')}
<button class="primary" type="submit">Hifadhi nenosiri</button></form></div>"""


@router.get("/weka-nenosiri-upya", response_class=HTMLResponse)
def reset_page(request: Request, r: str = ""):
    return _html(request, "Nenosiri jipya", _reset_form(request, r[:64]))


@router.post("/weka-nenosiri-upya")
def reset_submit(request: Request, csrf: str = Form(""), r: str = Form(""), code: str = Form(""),
                 new_password: str = Form(""), svc: AuthService = Depends(get_auth_service)):
    check_csrf(request, csrf)
    try:
        svc.reset_password(r[:64], code[:12], new_password[:1024])
    except AuthError as exc:
        return _html(request, "Nenosiri jipya", _reset_form(request, r[:64], exc.message), status=exc.status)
    return _redirect("/ingia?ujumbe=nenosiri-limerejeshwa")


# ------------------------------------------------------------------ development SMS inbox
@router.get("/dev/sms", response_class=HTMLResponse)
def dev_sms(request: Request):
    notifier = request.app.state.notifier
    if request.app.state.settings.environment.value not in ("development", "test") \
            or not isinstance(notifier, DevNotifier):
        raise HTTPException(status_code=404)
    rows = "".join(
        f"<tr><td>{escape(m.sent_at.strftime('%H:%M:%S'))}</td><td>{escape(m.channel.upper())}</td>"
        f"<td>{escape(m.to)}</td><td>{escape(m.body)}</td></tr>" for m in notifier.outbox
    ) or '<tr><td colspan="4">Hakuna ujumbe bado.</td></tr>'
    body = f"""<div class="hero"><h1>SMS za majaribio</h1>
<p>Ukurasa huu upo kwenye mazingira ya majaribio tu. Kwenye production, SMS zinatumwa kwa simu halisi.</p></div>
<table class="dev"><thead><tr><th>Saa (UTC)</th><th>Njia</th><th>Kwa</th><th>Ujumbe</th></tr></thead>
<tbody>{rows}</tbody></table>"""
    return _html(request, "SMS za majaribio", body)
