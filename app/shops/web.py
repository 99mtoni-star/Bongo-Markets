"""Swahili shop pages (M07): my shops, shop management, public shop page, admin verification."""

from __future__ import annotations

from html import escape
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse

from app.auth.deps import check_csrf, optional_session
from app.auth.security import StepUpAction
from app.auth.service import AuthError, SessionContext
from app.auth.web import _csrf_input, _html, _redirect
from app.shops.api import get_shop_service
from app.shops.models import ShopStatus
from app.shops.service import ShopService
from app.web.layout import alert, field

router = APIRouter(include_in_schema=False)

STATUS_SW = {"PENDING_VERIFICATION": ("Linasubiri uthibitisho", "design"), "ACTIVE": ("Limethibitishwa", "built"),
             "SUSPENDED": ("Limesimamishwa", "todo"), "REJECTED": ("Limekataliwa", "todo"), "CLOSED": ("Limefungwa", "todo")}
ROLE_SW = {"OWNER": "Mmiliki", "MANAGER": "Meneja", "STAFF": "Mfanyakazi"}
NOTICES = {"limefunguliwa": "Duka limefunguliwa! Linasubiri uthibitisho wa Bongo Markets kabla ya kuonekana sokoni.",
           "mwanachama-ameongezwa": "Mwanachama ameongezwa.", "mwanachama-ameondolewa": "Mwanachama ameondolewa.",
           "umiliki-umehamishwa": "Umiliki umehamishwa. Sasa wewe ni Meneja wa duka hili.",
           "imehifadhiwa": "Taarifa za duka zimehifadhiwa.", "hali-imebadilishwa": "Hali ya duka imebadilishwa."}


def pill(status: str) -> str:
    label, cls = STATUS_SW.get(status, (status, "todo"))
    return f"<span class='pill {cls}'>{escape(label)}</span>"


# ---------------------------------------------------------------- my shops
def _my_shops_body(request: Request, svc: ShopService, ctx: SessionContext, notice: str | None = None,
                   error: str | None = None) -> str:
    shops = svc.my_shops(ctx)
    rows = "".join(
        f"<tr><td><a href='/maduka/{escape(s['slug'])}'><b>{escape(s['name'])}</b></a><small>/duka/{escape(s['slug'])}"
        f"</small></td><td>{escape(ROLE_SW.get(s['my_role'], s['my_role']))}</td><td>{pill(s['status'])}</td></tr>"
        for s in shops) or "<tr><td colspan='3'>Bado huna duka. Fungua la kwanza hapa chini.</td></tr>"
    return f"""<div class="hero"><h1>Maduka yangu</h1><p>Maduka unayomiliki au unayofanyia kazi.</p></div>
{alert(notice, "ok")}<table><thead><tr><th>Duka</th><th>Jukumu</th><th>Hali</th></tr></thead><tbody>{rows}</tbody></table>
<div class="card"><h1 class="sm">Fungua duka jipya</h1><p class="sub">Unaweza kuwa mnunuzi na muuzaji kwa akaunti moja.</p>
{alert(error)}<form method="post" action="/maduka">{_csrf_input(request)}
{field("name", "Jina la duka", extra='required maxlength="80"')}
{field("region", "Mkoa / eneo", hint="(mf. Arusha)", extra='maxlength="60"')}
{field("description", "Maelezo mafupi", extra='maxlength="300"')}
<button class="primary" type="submit">Fungua duka</button></form></div>"""


@router.get("/maduka", response_class=HTMLResponse)
def my_shops(request: Request, ujumbe: str = "", ctx: SessionContext | None = Depends(optional_session),
             svc: ShopService = Depends(get_shop_service)):
    if ctx is None:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    return _html(request, "Maduka yangu", _my_shops_body(request, svc, ctx, NOTICES.get(ujumbe)), ctx=ctx)


@router.post("/maduka")
def create_shop(request: Request, csrf: str = Form(""), name: str = Form(""), region: str = Form(""),
                description: str = Form(""), ctx: SessionContext | None = Depends(optional_session),
                svc: ShopService = Depends(get_shop_service)):
    check_csrf(request, csrf)
    if ctx is None:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    try:
        shop = svc.create_shop(ctx, name[:120], description[:300], region[:60])
    except AuthError as exc:
        return _html(request, "Maduka yangu", _my_shops_body(request, svc, ctx, error=exc.message), ctx=ctx,
                     status=exc.status)
    return _redirect(f"/maduka/{quote(shop.slug)}?ujumbe=limefunguliwa")


# ---------------------------------------------------------------- manage one shop
def _manage_body(request: Request, svc: ShopService, ctx: SessionContext, slug: str, *, notice: str | None = None,
                 error: str | None = None, section: str = "") -> str:
    shop = svc.shop_for(ctx, slug, "shop.admin.view")
    can = {p: svc.authz.can(ctx.user.id, p, shop_id=shop.id) for p in
           ("shop.profile.update", "shop.staff.manage", "shop.managers.manage", "shop.ownership.transfer")}
    me = svc.membership(shop.id, ctx.user.id)
    err = lambda s: alert(error) if section == s else ""  # noqa: E731
    members = svc.members(ctx, slug)
    rows = []
    for m in members:
        removable = m["role"] != "OWNER" and (
            (m["role"] == "MANAGER" and can["shop.managers.manage"]) or (m["role"] == "STAFF" and can["shop.staff.manage"])
            or m["user_id"] == str(ctx.user.public_id))
        btn = (f"<form method='post' action='/maduka/{escape(slug)}/wanachama/{escape(m['user_id'])}/ondoa' class='inline'>"
               f"{_csrf_input(request)}<button type='submit' class='linkbtn'>Ondoa</button></form>") if removable else ""
        rows.append(f"<tr><td>{escape(m['name'])}</td><td>{escape(ROLE_SW[m['role']])}</td><td>{btn}</td></tr>")
    add_roles = [r for r, p in (("STAFF", "shop.staff.manage"), ("MANAGER", "shop.managers.manage")) if can[p]]
    add_form = ""
    if add_roles:
        opts = "".join(f"<option value='{r}'>{ROLE_SW[r]}</option>" for r in add_roles)
        add_form = f"""<form method="post" action="/maduka/{escape(slug)}/wanachama">{_csrf_input(request)}{err("ongeza")}
{field("phone", "Namba ya simu ya mwanachama", type_="tel", extra='inputmode="tel" required')}
<label for="role">Jukumu</label><select id="role" name="role">{opts}</select>
<button class="primary" type="submit">Ongeza mwanachama</button></form>"""
    profile = ""
    if can["shop.profile.update"]:
        profile = f"""<div class="card"><h1 class="sm">Taarifa za duka</h1>{err("profile")}
<form method="post" action="/maduka/{escape(slug)}/taarifa">{_csrf_input(request)}
{field("name", "Jina", value=shop.name, extra='required maxlength="80"')}
{field("region", "Mkoa / eneo", value=shop.region or "", extra='maxlength="60"')}
{field("description", "Maelezo", value=shop.description or "", extra='maxlength="300"')}
<button class="primary" type="submit">Hifadhi</button></form></div>"""
    transfer = ""
    if can["shop.ownership.transfer"]:
        others = [m for m in members if m["role"] != "OWNER"]
        if others:
            opts = "".join(f"<option value='{escape(m['user_id'])}'>{escape(m['name'])} ({ROLE_SW[m['role']]})</option>"
                           for m in others)
            mfa = (field("mfa_code", "Namba ya programu ya uthibitishaji", extra='class="code" autocomplete="one-time-code" maxlength="11" required')
                   if ctx.user.totp_enabled_at else
                   "<p class='alert err'>Kuhamisha umiliki kunahitaji MFA. <a href='/akaunti/usalama'>Washa MFA kwanza</a>.</p>")
            transfer = f"""<div class="card"><h1 class="sm">Hamisha umiliki</h1>
<p class="sub">Mmiliki mpya lazima awe tayari mwanachama wa duka. Wewe utabaki kama Meneja.</p>{err("hamisha")}
<form method="post" action="/maduka/{escape(slug)}/hamisha">{_csrf_input(request)}
<label for="new_owner">Mmiliki mpya</label><select id="new_owner" name="new_owner">{opts}</select>
{field("password", "Nenosiri lako", type_="password", extra='autocomplete="current-password" required')}{mfa}
<button class="primary" type="submit">Hamisha umiliki</button></form></div>"""
    banner = ""
    if shop.status == ShopStatus.PENDING_VERIFICATION:
        banner = alert("Duka linasubiri uthibitisho. Wateja hawataliona sokoni hadi lithibitishwe.", "ok")
    elif shop.status == ShopStatus.REJECTED and can["shop.profile.update"]:
        banner = (alert("Duka limekataliwa. Rekebisha taarifa kisha ulitume tena.") +
                  f"<form method='post' action='/maduka/{escape(slug)}/tuma-tena'>{_csrf_input(request)}"
                  f"<button class='primary' type='submit'>Tuma tena kwa uthibitisho</button></form>")
    hist = "".join(f"<li>{escape(h['at'][:16].replace('T', ' '))}: {pill(h['to'])} {escape(h['reason'] or '')}</li>"
                   for h in svc.history(shop))
    return f"""<div class="hero"><h1>{escape(shop.name)}</h1>
<p>{pill(shop.status)} · Jukumu lako: <b>{escape(ROLE_SW[me.role_code])}</b> ·
<a href="/maduka/{escape(slug)}/bidhaa">Bidhaa</a> · <a href="/duka/{escape(slug)}">Ukurasa wa wateja →</a></p></div>
{alert(notice, "ok")}{banner}
<div class="card"><h1 class="sm">Wanachama wa duka</h1>{err("wanachama")}
<table><tbody>{''.join(rows)}</tbody></table>{add_form}</div>
{profile}{transfer}
<div class="card"><h1 class="sm">Historia ya hali</h1><ul>{hist}</ul></div>"""


def _manage(request, svc, ctx, slug, **kw):
    try:
        return _html(request, "Simamia duka", _manage_body(request, svc, ctx, slug, **kw), ctx=ctx)
    except AuthError as exc:
        body = f'<div class="card"><h1>Hakipatikani</h1><p class="sub">{escape(exc.message)}</p></div>'
        return _html(request, "Hakipatikani", body, ctx=ctx, status=exc.status)


@router.get("/maduka/{slug}", response_class=HTMLResponse)
def manage(slug: str, request: Request, ujumbe: str = "", ctx: SessionContext | None = Depends(optional_session),
           svc: ShopService = Depends(get_shop_service)):
    if ctx is None:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    return _manage(request, svc, ctx, slug, notice=NOTICES.get(ujumbe))


def _post(request, csrf, ctx, svc, slug, section, action, notice):
    check_csrf(request, csrf)
    if ctx is None:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    try:
        action()
    except AuthError as exc:
        if exc.status == 404 and exc.code == "not_found":
            return _manage(request, svc, ctx, slug)
        svc.db.rollback()
        page = _manage_body(request, svc, ctx, slug, error=exc.message, section=section)
        return _html(request, "Simamia duka", page, ctx=ctx, status=exc.status)
    return _redirect(f"/maduka/{quote(slug)}?ujumbe={notice}")


@router.post("/maduka/{slug}/wanachama")
def add_member(slug: str, request: Request, csrf: str = Form(""), phone: str = Form(""), role: str = Form(""),
               ctx: SessionContext | None = Depends(optional_session), svc: ShopService = Depends(get_shop_service)):
    return _post(request, csrf, ctx, svc, slug, "ongeza", lambda: svc.add_member(ctx, slug, phone[:32], role[:16]),
                 "mwanachama-ameongezwa")


@router.post("/maduka/{slug}/wanachama/{uid}/ondoa")
def remove_member(slug: str, uid: str, request: Request, csrf: str = Form(""),
                  ctx: SessionContext | None = Depends(optional_session), svc: ShopService = Depends(get_shop_service)):
    if ctx and uid == str(ctx.user.public_id):
        check_csrf(request, csrf)
        try:
            svc.remove_member(ctx, slug, uid[:40])
        except AuthError:
            return _manage(request, svc, ctx, slug)
        return _redirect("/maduka")
    return _post(request, csrf, ctx, svc, slug, "wanachama", lambda: svc.remove_member(ctx, slug, uid[:40]),
                 "mwanachama-ameondolewa")


@router.post("/maduka/{slug}/taarifa")
def update_profile(slug: str, request: Request, csrf: str = Form(""), name: str = Form(""), region: str = Form(""),
                   description: str = Form(""), ctx: SessionContext | None = Depends(optional_session),
                   svc: ShopService = Depends(get_shop_service)):
    return _post(request, csrf, ctx, svc, slug, "profile",
                 lambda: svc.update_profile(ctx, slug, name=name[:120], description=description[:300],
                                            region=region[:60]), "imehifadhiwa")


@router.post("/maduka/{slug}/hamisha")
def transfer(slug: str, request: Request, csrf: str = Form(""), new_owner: str = Form(""), password: str = Form(""),
             mfa_code: str = Form(""), ctx: SessionContext | None = Depends(optional_session),
             svc: ShopService = Depends(get_shop_service)):
    def act():
        token = svc.step_up(ctx, StepUpAction.OWNERSHIP_TRANSFER.value, password[:1024], mfa_code[:16] or None)
        svc.transfer_ownership(ctx, slug, new_owner[:40], token)
    return _post(request, csrf, ctx, svc, slug, "hamisha", act, "umiliki-umehamishwa")


@router.post("/maduka/{slug}/tuma-tena")
def resubmit(slug: str, request: Request, csrf: str = Form(""), ctx: SessionContext | None = Depends(optional_session),
             svc: ShopService = Depends(get_shop_service)):
    return _post(request, csrf, ctx, svc, slug, "", lambda: svc.resubmit(ctx, slug), "imehifadhiwa")


# ---------------------------------------------------------------- public shop page (SHOP-007/008, BR-009)
@router.get("/duka/{slug}", response_class=HTMLResponse)
def public_shop(slug: str, request: Request, ctx: SessionContext | None = Depends(optional_session),
                svc: ShopService = Depends(get_shop_service)):
    shop = svc.shop_by_slug(slug)
    member = svc.membership(shop.id, ctx.user.id) if (shop and ctx) else None
    if shop is None or (shop.status != ShopStatus.ACTIVE and member is None):
        body = '<div class="card"><h1>Duka halipatikani</h1><p class="sub">Huenda anwani si sahihi.</p></div>'
        return _html(request, "Halipatikani", body, ctx=ctx, status=404)
    owner_bar = ""
    if member is not None:  # sellers see their own controls; customers never do (SHOP-008)
        owner_bar = (f'<div class="alert ok">Wewe ni {escape(ROLE_SW[member.role_code])} wa duka hili. '
                     f'<a href="/maduka/{escape(slug)}">Simamia Duka</a> · <a href="/soko">Bongo Markets Sokoni</a></div>')
        if shop.status != ShopStatus.ACTIVE:
            owner_bar += alert("Wateja hawaoni duka hili bado (halijathibitishwa).")
    from app.shops.catalog_hooks import render_shop_products

    products = render_shop_products(svc.db, shop)
    body = f"""<div class="hero"><h1>{escape(shop.name)}</h1>
<p>{escape(shop.region or "")}{' · ' if shop.region else ''}{escape(shop.description or "")}</p></div>
{owner_bar}{products}"""
    return _html(request, shop.name, body, ctx=ctx)


# ---------------------------------------------------------------- admin verification (SHOP-006)
@router.get("/simamizi/maduka", response_class=HTMLResponse)
def admin_pending(request: Request, ujumbe: str = "", ctx: SessionContext | None = Depends(optional_session),
                  svc: ShopService = Depends(get_shop_service)):
    if ctx is None:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    try:
        shops = svc.pending_shops(ctx)
    except AuthError as exc:
        return _html(request, "Hairuhusiwi", f'<div class="card"><h1>Hairuhusiwi</h1><p class="sub">{escape(exc.message)}</p></div>',
                     ctx=ctx, status=exc.status)
    rows = "".join(
        f"""<tr><td><b>{escape(s.name)}</b><small>/duka/{escape(s.slug)} · {escape(s.region or '')}</small></td>
<td><form method="post" action="/simamizi/maduka/{escape(s.slug)}" class="inline">{_csrf_input(request)}
<input type="hidden" name="status" value="ACTIVE"><input type="hidden" name="reason" value="Taarifa zimehakikiwa">
<button type="submit" class="linkbtn">Thibitisha</button></form> ·
<form method="post" action="/simamizi/maduka/{escape(s.slug)}" class="inline">{_csrf_input(request)}
<input type="hidden" name="status" value="REJECTED"><input type="hidden" name="reason" value="Taarifa hazijakamilika">
<button type="submit" class="linkbtn">Kataa</button></form></td></tr>""" for s in shops
    ) or "<tr><td colspan='2'>Hakuna duka linalosubiri.</td></tr>"
    body = f"""<div class="hero"><h1>Maduka yanayosubiri uthibitisho</h1></div>{alert(NOTICES.get(ujumbe), "ok")}
<table><thead><tr><th>Duka</th><th>Kitendo</th></tr></thead><tbody>{rows}</tbody></table>"""
    return _html(request, "Uthibitisho wa maduka", body, ctx=ctx)


@router.post("/simamizi/maduka/{slug}")
def admin_set_status(slug: str, request: Request, csrf: str = Form(""), status: str = Form(""),
                     reason: str = Form(""), ctx: SessionContext | None = Depends(optional_session),
                     svc: ShopService = Depends(get_shop_service)):
    check_csrf(request, csrf)
    if ctx is None:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    try:
        svc.set_status(ctx, slug, status.upper()[:24], reason[:1000])
    except AuthError as exc:
        return _html(request, "Hitilafu", f'<div class="card"><h1>Hitilafu</h1><p class="sub">{escape(exc.message)}</p></div>',
                     ctx=ctx, status=exc.status)
    return _redirect("/simamizi/maduka?ujumbe=hali-imebadilishwa")
