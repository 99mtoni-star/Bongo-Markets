"""Bongo Markets Sokoni pages (M09): marketplace and product detail."""

from __future__ import annotations

from html import escape
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from app.auth.deps import optional_session
from app.auth.service import SessionContext
from app.auth.web import _html
from app.catalog.models import Category
from app.catalog.web import money
from app.db.session import get_db
from app.market import service as market

router = APIRouter(include_in_schema=False)


def card(p: dict) -> str:
    img = (f"<img src='{escape(p['images'][0])}' alt='{escape(p['name'])}' loading='lazy'>" if p["images"]
           else "<div class='noimg'>Hakuna picha</div>")
    out = "" if p["available"] else "<span class='pill todo'>Imeisha</span>"
    star = "<span class='pill design'>Maalum</span> " if p.get("featured") else ""
    return (f"<a class='pcard' href='/bidhaa/{escape(p['id'])}'>{img}<div class='pbody'>{star}<h3>{escape(p['name'])}</h3>"
            f"<p class='price'>{escape(money(float(p['price'])))} <small>/ {escape(p['unit'])}</small></p>"
            f"<p class='shopname'>{escape(p['shop']['name'])}{' · ' + escape(p['shop']['region']) if p['shop']['region'] else ''}</p>"
            f"{out}</div></a>")


@router.get("/soko", response_class=HTMLResponse)
def marketplace(request: Request, q: str = "", category: str = "", min_price: str = "", max_price: str = "",
                region: str = "", sort: str = "newest", cursor: str = "",
                ctx: SessionContext | None = Depends(optional_session), db=Depends(get_db)):
    f = market.Filters(q=q[:80], category=category[:48], min_price=min_price[:20], max_price=max_price[:20],
                       region=region[:60], sort=sort[:16], cursor=cursor[:200])
    items, nxt = market.search(db, f)
    filtered = any((q, category, min_price, max_price, region)) or cursor
    feat = "" if filtered else "".join(card(p) for p in market.featured(db))
    cats = db.query(Category).filter(Category.active.is_(True)).order_by(Category.sort).all()
    cat_opts = "<option value=''>Makundi yote</option>" + "".join(
        f"<option value='{escape(c.slug)}'{' selected' if c.slug == category else ''}>{escape(c.name)}</option>" for c in cats)
    sort_opts = "".join(f"<option value='{v}'{' selected' if v == f.sort else ''}>{label}</option>"
                        for v, label in (("newest", "Mpya kwanza"), ("price_asc", "Bei: chini → juu"),
                                         ("price_desc", "Bei: juu → chini")))
    params = {k: v for k, v in (("q", q), ("category", category), ("min_price", min_price), ("max_price", max_price),
                                ("region", region), ("sort", sort)) if v}
    more = (f"<a class='btn ghost' href='/soko?{escape(urlencode({**params, 'cursor': nxt}))}'>Pakia bidhaa zaidi</a>"
            if nxt else ("<p class='hint c'>Umeona bidhaa zote.</p>" if items else ""))
    grid = "".join(card(p) for p in items) or "<p class='sub'>Hakuna bidhaa zinazolingana na utafutaji wako.</p>"
    body = f"""<div class="hero"><h1>Bongo Markets Sokoni</h1><p>Bidhaa kutoka maduka mbalimbali, sehemu moja.</p></div>
<form method="get" action="/soko" class="filters">
<input name="q" value="{escape(q)}" placeholder="Tafuta: kuku, mayai, duka..." aria-label="Tafuta">
<select name="category" aria-label="Kundi">{cat_opts}</select>
<input name="region" value="{escape(region)}" placeholder="Mkoa / eneo" aria-label="Eneo">
<input name="min_price" value="{escape(min_price)}" placeholder="Bei kuanzia" inputmode="numeric" aria-label="Bei ya chini">
<input name="max_price" value="{escape(max_price)}" placeholder="Bei hadi" inputmode="numeric" aria-label="Bei ya juu">
<select name="sort" aria-label="Panga">{sort_opts}</select>
<button class="primary" type="submit">Tafuta</button></form>
{f"<h2 class='sec'>Bidhaa maalum</h2><div class='pgrid'>{feat}</div>" if feat else ""}
<h2 class="sec">{'Matokeo' if filtered else 'Bidhaa zote'}</h2><div class="pgrid">{grid}</div>
<div class="more">{more}</div>"""
    return _html(request, "Soko", body, ctx=ctx)


@router.get("/bidhaa/{product_id}", response_class=HTMLResponse)
def product_page(product_id: str, request: Request, ctx: SessionContext | None = Depends(optional_session),
                 db=Depends(get_db)):
    p = market.product_detail(db, product_id[:40])
    if p is None:
        return _html(request, "Haipatikani", '<div class="card"><h1>Bidhaa haipatikani</h1></div>', ctx=ctx, status=404)
    gallery = "".join(f"<img src='{escape(u)}' alt='{escape(p['name'])}'>" for u in p["images"]) or \
        "<div class='noimg'>Hakuna picha</div>"
    from app.market.hooks import buy_box

    body = f"""<div class="pdetail"><div class="pimages">{gallery}</div><div class="pinfo">
<p class="hint"><a href="/soko?category={escape(p['category'])}">{escape(p['category_name'])}</a></p>
<h1>{escape(p['name'])}</h1><p class="price big">{escape(money(float(p['price'])))} <small>/ {escape(p['unit'])}</small></p>
<p>{escape(p['description'] or '')}</p>
<p>Inauzwa na <a href="/duka/{escape(p['shop']['slug'])}"><b>{escape(p['shop']['name'])}</b></a>
{(' · ' + escape(p['shop']['region'])) if p['shop']['region'] else ''}</p>
{buy_box(request, ctx, p)}</div></div>"""
    return _html(request, p["name"], body, ctx=ctx)
