"""Swahili account-security pages (M04): MFA, devices, phone change.

High-risk actions submitted from a form perform step-up and the action in the same
request: the grant is created and consumed at once, so it never leaves the server.
"""

from __future__ import annotations

from html import escape
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse

from app.auth.deps import check_csrf, optional_session
from app.auth.security import SecurityService, StepUpAction
from app.auth.security_api import get_security_service
from app.auth.service import AuthError, SessionContext
from app.auth.web import _csrf_input, _html, _redirect
from app.web.layout import alert, field

router = APIRouter(include_in_schema=False)

NOTICES = {
    "mfa-imezimwa": "MFA imezimwa.",
    "kifaa-kimetolewa": "Kifaa kimetolewa kwenye akaunti.",
    "vifaa-vimetolewa": "Vifaa vingine vyote vimetolewa kwenye akaunti.",
    "simu-imebadilishwa": "Namba ya simu imebadilishwa. Vifaa vingine vimetolewa kwenye akaunti.",
}


def _fmt(dt) -> str:
    return dt.strftime("%d/%m/%Y %H:%M") + " UTC"


def _device(ua: str | None) -> str:
    ua = ua or ""
    for needle, name in (("Android", "Simu ya Android"), ("iPhone", "iPhone"), ("Windows", "Kompyuta (Windows)"),
                         ("Macintosh", "Kompyuta (Mac)"), ("Linux", "Kompyuta (Linux)")):
        if needle in ua:
            return name
    return "Kifaa kisichojulikana"


def _reauth_fields(has_totp: bool) -> str:
    out = field("password", "Nenosiri lako", type_="password", extra='autocomplete="current-password" required')
    if has_totp:
        out += field("mfa_code", "Namba ya programu ya uthibitishaji",
                     extra='class="code" autocomplete="one-time-code" maxlength="11" required')
    return out


def _security_body(request: Request, ctx: SessionContext, svc: SecurityService, *, notice: str | None = None,
                   error: str | None = None, section: str = "") -> str:
    u = ctx.user
    has_totp = u.totp_enabled_at is not None
    err = lambda s: alert(error) if section == s else ""  # noqa: E731

    if has_totp:
        mfa = f"""<p>✅ <b>MFA imewashwa</b> tangu {escape(_fmt(u.totp_enabled_at))}.
Kila ukiingia, utaombwa namba kutoka kwenye programu ya uthibitishaji.</p>{err("mfa")}
<details><summary>Zima MFA</summary>
<form method="post" action="/akaunti/usalama/mfa/zima">{_csrf_input(request)}{_reauth_fields(True)}
<button class="primary" type="submit">Zima MFA</button></form></details>"""
    else:
        mfa = f"""<p>MFA bado haijawashwa. Ukiiwasha, mwizi akipata nenosiri lako bado hataweza kuingia
bila simu yako.</p>{err("mfa")}
<form method="post" action="/akaunti/usalama/mfa/anza">{_csrf_input(request)}
<button class="primary" type="submit">Washa MFA</button></form>"""

    rows = []
    for s in svc.list_sessions(ctx):
        action = "<b>Kifaa hiki</b>" if s["current"] else (
            f'<form method="post" action="/akaunti/usalama/vifaa/{escape(s["id"])}/toa" style="margin:0">'
            f'{_csrf_input(request)}<button type="submit">Toa</button></form>')
        rows.append(f"<tr><td>{escape(_device(s['user_agent']))}{' · MFA ✓' if s['mfa'] else ''}"
                    f"<small>Kilianza {escape(_fmt(s['created_at']))}</small></td><td>{action}</td></tr>")
    devices = f"""<table><tbody>{''.join(rows)}</tbody></table>
<form method="post" action="/akaunti/usalama/vifaa/toa-vingine">{_csrf_input(request)}
<button class="primary" type="submit">Toa vifaa vingine vyote</button></form>"""

    phone = f"""{err("simu")}<form method="post" action="/akaunti/usalama/simu">{_csrf_input(request)}
{field("new_phone", "Namba mpya ya simu", type_="tel", extra='inputmode="tel" required')}
{_reauth_fields(has_totp)}
<button class="primary" type="submit">Tuma namba ya uthibitisho</button></form>"""

    return f"""<div class="hero"><h1>Usalama wa akaunti</h1><p><a href="/akaunti">← Rudi kwenye akaunti</a></p></div>
{alert(notice, "ok")}
<div class="card"><h1 style="font-size:20px">Uthibitisho wa hatua mbili (MFA)</h1>{mfa}</div>
<div class="card"><h1 style="font-size:20px">Vifaa vilivyoingia</h1>
<p class="sub">Ukiona kifaa usichokijua, kitoe mara moja kisha ubadilishe nenosiri.</p>{err("vifaa")}{devices}</div>
<div class="card"><h1 style="font-size:20px">Badilisha namba ya simu</h1>
<p class="sub">Kwa usalama, tutakuomba nenosiri{' na namba ya MFA' if has_totp else ''} kwanza.</p>{phone}</div>"""


def _need_login(ctx):
    return _redirect("/ingia?ujumbe=ingia-kwanza") if ctx is None else None


@router.get("/akaunti/usalama", response_class=HTMLResponse)
def security_page(request: Request, ujumbe: str = "", ctx: SessionContext | None = Depends(optional_session),
                  svc: SecurityService = Depends(get_security_service)):
    if (r := _need_login(ctx)) is not None:
        return r
    return _html(request, "Usalama", _security_body(request, ctx, svc, notice=NOTICES.get(ujumbe)), ctx=ctx)


# ---------------------------------------------------------------- MFA enrollment
@router.post("/akaunti/usalama/mfa/anza", response_class=HTMLResponse)
def mfa_begin(request: Request, csrf: str = Form(""), ctx: SessionContext | None = Depends(optional_session),
              svc: SecurityService = Depends(get_security_service)):
    check_csrf(request, csrf)
    if (r := _need_login(ctx)) is not None:
        return r
    try:
        setup = svc.begin_totp_setup(ctx)
    except AuthError as exc:
        return _html(request, "Usalama", _security_body(request, ctx, svc, error=exc.message, section="mfa"),
                     ctx=ctx, status=exc.status)
    return _html(request, "Washa MFA", _enroll_body(request, setup["qr_svg"], setup["secret"]), ctx=ctx)


def _enroll_body(request: Request, qr: str, secret: str, error: str | None = None) -> str:
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return f"""<div class="card"><h1>Washa MFA</h1>
<p class="sub">1. Pakua programu ya uthibitishaji (Google Authenticator, Microsoft Authenticator au Authy).<br>
2. Scan picha hii ya QR kwa programu hiyo.<br>3. Andika namba ya tarakimu 6 inayoonekana.</p>
<div style="background:#fff;border-radius:8px;padding:8px;width:max-content;margin:0 auto">{qr}</div>
<p style="text-align:center;font-size:13px;color:var(--muted)">Huwezi kuscan? Andika ufunguo huu:<br>
<code style="font-size:15px;letter-spacing:.05em">{escape(grouped)}</code></p>{alert(error)}
<form method="post" action="/akaunti/usalama/mfa/thibitisha">{_csrf_input(request)}
{field("code", "Namba kutoka kwenye programu", extra='class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required')}
<button class="primary" type="submit">Thibitisha na uwashe</button></form></div>"""


@router.post("/akaunti/usalama/mfa/thibitisha", response_class=HTMLResponse)
def mfa_confirm(request: Request, csrf: str = Form(""), code: str = Form(""),
                ctx: SessionContext | None = Depends(optional_session),
                svc: SecurityService = Depends(get_security_service)):
    check_csrf(request, csrf)
    if (r := _need_login(ctx)) is not None:
        return r
    try:
        codes = svc.confirm_totp_setup(ctx, code[:16])
    except AuthError as exc:
        # Show the same secret again so the user can retry without rescanning.
        from app.auth.identifiers import mask_phone
        from app.auth.mfa import decrypt_secret, provisioning_uri, qr_svg

        user = ctx.user
        svc.db.refresh(user)
        if not user.totp_secret_enc:
            return _redirect("/akaunti/usalama")
        secret = decrypt_secret(svc.settings, user.totp_secret_enc, user_id=user.id)
        qr = qr_svg(provisioning_uri(secret, mask_phone(user.phone_e164)))
        return _html(request, "Washa MFA", _enroll_body(request, qr, secret, exc.message), ctx=ctx,
                     status=exc.status)
    items = "".join(f"<li><code>{escape(c)}</code></li>" for c in codes)
    body = f"""<div class="card"><h1>MFA imewashwa ✅</h1>
<p class="sub">Hizi ni <b>namba zako za dharura</b>. Kila moja inatumika mara moja tu, kama umepoteza simu.
Ziandike au zichapishe, uziweke mahali salama. Hazitaonyeshwa tena.</p>
<ol style="columns:2;font-size:17px;line-height:1.9">{items}</ol>
<p class="sub">Vifaa vingine vyote vimetolewa kwenye akaunti kwa usalama.</p>
<a class="primary" href="/akaunti/usalama" style="display:block;text-align:center;padding:12px;border-radius:8px;
background:var(--brand);color:var(--brand-ink);text-decoration:none;font-weight:700">Nimezihifadhi</a></div>"""
    resp = _html(request, "Namba za dharura", body, ctx=ctx)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@router.post("/akaunti/usalama/mfa/zima")
def mfa_disable(request: Request, csrf: str = Form(""), password: str = Form(""), mfa_code: str = Form(""),
                ctx: SessionContext | None = Depends(optional_session),
                svc: SecurityService = Depends(get_security_service)):
    check_csrf(request, csrf)
    if (r := _need_login(ctx)) is not None:
        return r
    try:
        token = svc.step_up(ctx, StepUpAction.MFA_DISABLE.value, password[:1024], mfa_code[:16])
        svc.disable_totp(ctx, token)
    except AuthError as exc:
        return _html(request, "Usalama", _security_body(request, ctx, svc, error=exc.message, section="mfa"),
                     ctx=ctx, status=exc.status)
    return _redirect("/akaunti/usalama?ujumbe=mfa-imezimwa")


# ---------------------------------------------------------------- devices
@router.post("/akaunti/usalama/vifaa/{sid}/toa")
def device_revoke(sid: str, request: Request, csrf: str = Form(""),
                  ctx: SessionContext | None = Depends(optional_session),
                  svc: SecurityService = Depends(get_security_service)):
    check_csrf(request, csrf)
    if (r := _need_login(ctx)) is not None:
        return r
    svc.revoke_session(ctx, sid[:40])
    return _redirect("/akaunti/usalama?ujumbe=kifaa-kimetolewa")


@router.post("/akaunti/usalama/vifaa/toa-vingine")
def devices_revoke_others(request: Request, csrf: str = Form(""),
                          ctx: SessionContext | None = Depends(optional_session),
                          svc: SecurityService = Depends(get_security_service)):
    check_csrf(request, csrf)
    if (r := _need_login(ctx)) is not None:
        return r
    svc.revoke_other_sessions(ctx)
    return _redirect("/akaunti/usalama?ujumbe=vifaa-vimetolewa")


# ---------------------------------------------------------------- phone change
@router.post("/akaunti/usalama/simu")
def phone_change(request: Request, csrf: str = Form(""), new_phone: str = Form(""), password: str = Form(""),
                 mfa_code: str = Form(""), ctx: SessionContext | None = Depends(optional_session),
                 svc: SecurityService = Depends(get_security_service)):
    check_csrf(request, csrf)
    if (r := _need_login(ctx)) is not None:
        return r
    try:
        token = svc.step_up(ctx, StepUpAction.PHONE_CHANGE.value, password[:1024], mfa_code[:16] or None)
        vid = svc.request_phone_change(ctx, new_phone[:32], token)
    except AuthError as exc:
        return _html(request, "Usalama", _security_body(request, ctx, svc, error=exc.message, section="simu"),
                     ctx=ctx, status=exc.status)
    return _redirect(f"/akaunti/usalama/simu/thibitisha?v={quote(vid)}")


def _phone_confirm_body(request: Request, vid: str, error: str | None = None) -> str:
    return f"""<div class="card"><h1>Thibitisha namba mpya</h1>
<p class="sub">Tumetuma SMS kwa namba mpya. Andika namba ya tarakimu 6.</p>{alert(error)}
<form method="post" action="/akaunti/usalama/simu/thibitisha">{_csrf_input(request)}
<input type="hidden" name="v" value="{escape(vid)}">
{field("code", "Namba ya uthibitisho", extra='class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required')}
<button class="primary" type="submit">Thibitisha</button></form></div>"""


@router.get("/akaunti/usalama/simu/thibitisha", response_class=HTMLResponse)
def phone_confirm_page(request: Request, v: str = "", ctx: SessionContext | None = Depends(optional_session)):
    if (r := _need_login(ctx)) is not None:
        return r
    return _html(request, "Thibitisha namba", _phone_confirm_body(request, v[:64]), ctx=ctx)


@router.post("/akaunti/usalama/simu/thibitisha")
def phone_confirm(request: Request, csrf: str = Form(""), v: str = Form(""), code: str = Form(""),
                  ctx: SessionContext | None = Depends(optional_session),
                  svc: SecurityService = Depends(get_security_service)):
    check_csrf(request, csrf)
    if (r := _need_login(ctx)) is not None:
        return r
    try:
        svc.confirm_phone_change(ctx, v[:64], code[:12])
    except AuthError as exc:
        return _html(request, "Thibitisha namba", _phone_confirm_body(request, v[:64], exc.message), ctx=ctx,
                     status=exc.status)
    return _redirect("/akaunti/usalama?ujumbe=simu-imebadilishwa")
