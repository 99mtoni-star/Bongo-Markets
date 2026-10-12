"""Seller product pages (M08)."""

from __future__ import annotations

from html import escape
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse

from app.auth.deps import check_csrf, optional_session
from app.auth.service import AuthError, SessionContext
from app.auth.web import _csrf_input, _html, _redirect
from app.catalog.api import get_catalog_service
from app.catalog.media import ImageRejected, read_limited
from app.catalog.service import UNITS, CatalogService
from app.web.layout import alert, field

router = APIRouter(include_in_schema=False)

STATUS_SW = {"DRAFT": ("Rasimu", "design"), "ACTIVE": ("Inauzwa", "built"), "SUSPENDED": ("Imesimamishwa", "todo"),
             "ARCHIVED": ("Imehifadhiwa", "todo")}
NOTICES = {"imeongezwa": "Bidhaa imeongezwa kama rasimu. Weka picha na bei, kisha ichapishe.",
           "imehifadhiwa": "Mabadiliko yamehifadhiwa.", "picha-imeongezwa": "Picha imeongezwa.",
           "picha-imeondolewa": "Picha imeondolewa."}


def money(v) -> str:
    return f"TZS {int(v):,}".replace(",", ",") if v == int(v) else f"TZS {v:,.2f}"


def _pill(status: str) -> str:
    label, cls = STATUS_SW.get(status, (status, "todo"))
    return f"<span class='pill {cls}'>{escape(label)}</span>"


def _cat_options(svc: CatalogService, selected: str = "") -> str:
    return "".join(f"<option value='{escape(c.slug)}'{' selected' if c.slug == selected else ''}>{escape(c.name)}</option>"
                   for c in svc.categories())


def _unit_options(selected: str = "kipande") -> str:
    return "".join(f"<option value='{u}'{' selected' if u == selected else ''}>{u}</option>" for u in UNITS)


def _list_body(request: Request, svc: CatalogService, ctx: SessionContext, slug: str, notice=None, error=None) -> str:
    shop = svc.shop_for(ctx, slug, "shop.products.manage")
    can_price = svc.authz.can(ctx.user.id, "shop.products.price", shop_id=shop.id)
    rows = []
    for p in svc.shop_products(shop, public=False):
        imgs = svc.images(p)
        thumb = f"<img class='thumb' src='/media/{escape(imgs[0].storage_key)}' alt=''>" if imgs else "<span class='thumb'></span>"
        rows.append(f"<tr><td class='prod'>{thumb}<span><a href='/maduka/{escape(slug)}/bidhaa/{p.public_id}'>"
                    f"<b>{escape(p.name)}</b></a><small>{escape(p.sku)}</small></span></td>"
                    f"<td>{escape(money(p.price))}</td><td>{p.stock - p.reserved} / {p.stock}</td><td>{_pill(p.status)}</td></tr>")
    table = "".join(rows) or "<tr><td colspan='4'>Bado hakuna bidhaa.</td></tr>"
    price_field = (field("price", "Bei (TZS)", extra='inputmode="decimal" placeholder="mf. 18000"') if can_price else
                   "<p class='hint'>Bei itawekwa na meneja au mmiliki.</p>")
    return f"""<div class="hero"><h1>Bidhaa za {escape(shop.name)}</h1>
<p><a href="/maduka/{escape(slug)}">← Simamia duka</a> · <a href="/duka/{escape(slug)}">Ukurasa wa wateja</a></p></div>
{alert(notice, "ok")}<table><thead><tr><th>Bidhaa</th><th>Bei</th><th>Inapatikana / Stock</th><th>Hali</th></tr></thead>
<tbody>{table}</tbody></table>
<div class="card"><h1 class="sm">Ongeza bidhaa</h1>{alert(error)}
<form method="post" action="/maduka/{escape(slug)}/bidhaa">{_csrf_input(request)}
{field("name", "Jina la bidhaa", extra='required maxlength="120" placeholder="mf. Kuku wa kienyeji (jogoo)"')}
<label for="category">Kundi</label><select id="category" name="category">{_cat_options(svc)}</select>
{price_field}
{field("stock", "Idadi iliyopo (stock)", extra='inputmode="numeric" value="0"')}
<label for="unit">Kipimo</label><select id="unit" name="unit">{_unit_options()}</select>
{field("description", "Maelezo", extra='maxlength="300"')}
<button class="primary" type="submit">Ongeza bidhaa</button></form></div>"""


def _guard(request, ctx, build):
    if ctx is None:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    try:
        return _html(request, "Bidhaa", build(), ctx=ctx)
    except AuthError as exc:
        return _html(request, "Hakipatikani", f'<div class="card"><h1>Hakipatikani</h1><p class="sub">{escape(exc.message)}</p></div>',
                     ctx=ctx, status=exc.status)


@router.get("/maduka/{slug}/bidhaa", response_class=HTMLResponse)
def product_list(slug: str, request: Request, ujumbe: str = "", ctx: SessionContext | None = Depends(optional_session),
                 svc: CatalogService = Depends(get_catalog_service)):
    return _guard(request, ctx, lambda: _list_body(request, svc, ctx, slug, NOTICES.get(ujumbe)))


@router.post("/maduka/{slug}/bidhaa")
def product_create(slug: str, request: Request, csrf: str = Form(""), name: str = Form(""), category: str = Form(""),
                   price: str = Form("0"), stock: str = Form("0"), unit: str = Form("kipande"), description: str = Form(""),
                   ctx: SessionContext | None = Depends(optional_session), svc: CatalogService = Depends(get_catalog_service)):
    check_csrf(request, csrf)
    if ctx is None:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    try:
        p = svc.create_product(ctx, slug, name=name[:200], category=category[:48], price=price[:20] or "0",
                               stock=stock[:12] or "0", unit=unit[:24], description=description[:300])
    except AuthError as exc:
        svc.db.rollback()
        msg = exc.message
        return _guard(request, ctx, lambda: _list_body(request, svc, ctx, slug, error=msg))
    return _redirect(f"/maduka/{quote(slug)}/bidhaa/{p.public_id}?ujumbe=imeongezwa")


def _edit_body(request, svc: CatalogService, ctx, slug, pid, notice=None, error=None) -> str:
    shop = svc.shop_for(ctx, slug, "shop.products.manage")
    p = svc.product_in_shop(shop, pid)
    can_price = svc.authz.can(ctx.user.id, "shop.products.price", shop_id=shop.id)
    cat = svc.product_dict(p)["category"]
    imgs = svc.images(p)
    gallery = "".join(
        f"<figure><img src='/media/{escape(i.storage_key)}' alt=''><form method='post' "
        f"action='/maduka/{escape(slug)}/bidhaa/{p.public_id}/picha/{i.public_id}/ondoa' class='inline'>"
        f"{_csrf_input(request)}<button class='linkbtn' type='submit'>Ondoa</button></form></figure>" for i in imgs)
    statuses = "".join(f"<option value='{s}'{' selected' if s == p.status else ''}>{STATUS_SW[s][0]}</option>"
                       for s in ("DRAFT", "ACTIVE", "SUSPENDED", "ARCHIVED"))
    price = (field("price", "Bei (TZS)", value=str(p.price), extra='inputmode="decimal"') if can_price else
             f"<p class='hint'>Bei: {escape(money(p.price))} (inawekwa na meneja au mmiliki)</p>")
    return f"""<div class="hero"><h1>{escape(p.name)}</h1><p>{_pill(p.status)} · SKU {escape(p.sku)} ·
<a href="/maduka/{escape(slug)}/bidhaa">← Bidhaa zote</a></p></div>{alert(notice, "ok")}{alert(error)}
<div class="card"><h1 class="sm">Picha</h1><div class="gallery">{gallery or "<p class='sub'>Bado hakuna picha.</p>"}</div>
<form method="post" action="/maduka/{escape(slug)}/bidhaa/{p.public_id}/picha" enctype="multipart/form-data">{_csrf_input(request)}
<label for="image">Ongeza picha <small>(JPEG, PNG au WebP, hadi MB 5)</small></label>
<input id="image" name="image" type="file" accept="image/jpeg,image/png,image/webp" required>
<button class="primary" type="submit">Pakia picha</button></form></div>
<div class="card"><h1 class="sm">Taarifa za bidhaa</h1>
<form method="post" action="/maduka/{escape(slug)}/bidhaa/{p.public_id}">{_csrf_input(request)}
{field("name", "Jina", value=p.name, extra='required maxlength="120"')}
<label for="category">Kundi</label><select id="category" name="category">{_cat_options(svc, cat)}</select>
{price}
{field("stock", "Stock", value=str(p.stock), extra='inputmode="numeric"')}
<p class="hint">Zimeshikiliwa kwa oda zinazoendelea: {p.reserved}</p>
<label for="unit">Kipimo</label><select id="unit" name="unit">{_unit_options(p.unit)}</select>
{field("description", "Maelezo", value=p.description or "", extra='maxlength="300"')}
<label for="status">Hali</label><select id="status" name="status">{statuses}</select>
<button class="primary" type="submit">Hifadhi</button></form></div>"""


@router.get("/maduka/{slug}/bidhaa/{pid}", response_class=HTMLResponse)
def product_edit(slug: str, pid: str, request: Request, ujumbe: str = "",
                 ctx: SessionContext | None = Depends(optional_session), svc: CatalogService = Depends(get_catalog_service)):
    return _guard(request, ctx, lambda: _edit_body(request, svc, ctx, slug, pid[:40], NOTICES.get(ujumbe)))


@router.post("/maduka/{slug}/bidhaa/{pid}")
def product_update(slug: str, pid: str, request: Request, csrf: str = Form(""), name: str = Form(""),
                   category: str = Form(""), price: str | None = Form(None), stock: str = Form("0"),
                   unit: str = Form("kipande"), description: str = Form(""), status: str = Form(""),
                   ctx: SessionContext | None = Depends(optional_session), svc: CatalogService = Depends(get_catalog_service)):
    check_csrf(request, csrf)
    if ctx is None:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    try:
        svc.update_product(ctx, slug, pid[:40], name=name[:200], category=category[:48],
                           price=price[:20] if price is not None else None, stock=stock[:12], unit=unit[:24],
                           description=description[:300], status=status[:16])
    except AuthError as exc:
        svc.db.rollback()
        msg = exc.message
        return _guard(request, ctx, lambda: _edit_body(request, svc, ctx, slug, pid[:40], error=msg))
    return _redirect(f"/maduka/{quote(slug)}/bidhaa/{quote(pid[:40])}?ujumbe=imehifadhiwa")


@router.post("/maduka/{slug}/bidhaa/{pid}/picha")
def image_upload(slug: str, pid: str, request: Request, csrf: str = Form(""), image: UploadFile = File(...),
                 ctx: SessionContext | None = Depends(optional_session), svc: CatalogService = Depends(get_catalog_service)):
    check_csrf(request, csrf)
    if ctx is None:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    try:
        svc.add_image(ctx, slug, pid[:40], read_limited(image.file))
    except (AuthError, ImageRejected) as exc:
        msg = exc.message if isinstance(exc, AuthError) else str(exc)
        return _guard(request, ctx, lambda: _edit_body(request, svc, ctx, slug, pid[:40], error=msg))
    return _redirect(f"/maduka/{quote(slug)}/bidhaa/{quote(pid[:40])}?ujumbe=picha-imeongezwa")


@router.post("/maduka/{slug}/bidhaa/{pid}/picha/{iid}/ondoa")
def image_remove(slug: str, pid: str, iid: str, request: Request, csrf: str = Form(""),
                 ctx: SessionContext | None = Depends(optional_session), svc: CatalogService = Depends(get_catalog_service)):
    check_csrf(request, csrf)
    if ctx is None:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    try:
        svc.remove_image(ctx, slug, pid[:40], iid[:40])
    except AuthError as exc:
        msg = exc.message
        return _guard(request, ctx, lambda: _edit_body(request, svc, ctx, slug, pid[:40], error=msg))
    return _redirect(f"/maduka/{quote(slug)}/bidhaa/{quote(pid[:40])}?ujumbe=picha-imeondolewa")


def product_card(p: dict) -> str:
    img = (f"<img src='{escape(p['images'][0])}' alt='{escape(p['name'])}' loading='lazy'>" if p["images"]
           else "<div class='noimg'>Hakuna picha</div>")
    stock = "" if p["available"] else "<span class='pill todo'>Imeisha</span>"
    return (f"<article class='pcard'>{img}<div class='pbody'><h3>{escape(p['name'])}</h3>"
            f"<p class='price'>{escape(money(float(p['price'])))} <small>/ {escape(p['unit'])}</small></p>{stock}</div></article>")
