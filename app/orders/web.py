"""Cart, checkout and order pages (M11/M12). Plain HTML forms, no JavaScript, CSRF on every POST."""

from __future__ import annotations

import uuid
from html import escape
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.auth.deps import check_csrf, optional_session
from app.auth.service import AuthError, SessionContext
from app.auth.web import _csrf_input, _html, _redirect
from app.catalog.web import money
from app.orders import payments
from app.orders.api import get_order_service
from app.orders.cart import Address
from app.orders.service import STATUS_LABELS, OrderService
from app.web.layout import alert, field

router = APIRouter(include_in_schema=False)

STATUS_CLS = {"PENDING_PAYMENT": "design", "CONFIRMED": "built", "PROCESSING": "built", "SHIPPED": "built",
              "DELIVERED": "built", "CANCELLED": "closed", "EXPIRED": "closed"}
NOTICES = {
    "imeongezwa-kikapu": "Bidhaa imeongezwa kwenye kikapu.",
    "kikapu-kimesasishwa": "Kikapu kimesasishwa.",
    "oda-imewekwa": "Oda imewekwa! Lipa ndani ya muda ulioonyeshwa ili bidhaa zako zisiachiliwe.",
    "imelipwa": "Malipo yamethibitishwa. Duka limearifiwa kuandaa oda yako.",
    "imeghairiwa": "Oda imeghairiwa na bidhaa zimerudishwa.",
    "ombi-limetumwa": "Ombi la kughairi limetumwa kwa duka.",
    "pin-imetumwa": "PIN mpya imetumwa kwa SMS.",
    "imesasishwa": "Hali ya oda imesasishwa.",
    "imefika": "Oda imethibitishwa kufika. Asante!",
    "msafirishaji": "Msafirishaji amebadilishwa.",
}


def pill(status: str) -> str:
    return f"<span class='pill {STATUS_CLS.get(status, 'todo')}'>{escape(STATUS_LABELS.get(status, status))}</span>"


def _dev(request: Request) -> bool:
    return request.app.state.settings.environment.value in ("development", "test")


def _login():
    return _redirect("/ingia?ujumbe=ingia-kwanza")


def _notfound(request, ctx, exc: AuthError):
    body = f'<div class="card"><h1>Haipatikani</h1><p class="sub">{escape(exc.message)}</p></div>'
    return _html(request, "Haipatikani", body, ctx=ctx, status=exc.status)


# ------------------------------------------------------------------ product page buy box (M11)
def buy_box(request: Request, ctx: SessionContext | None, product: dict) -> str:
    avail = product["available_quantity"]
    if avail <= 0:
        return "<p class='alert err'>Bidhaa hii imeisha kwa sasa.</p>"
    if ctx is None:
        return (f"<p class='hint'>Zinapatikana: {avail}</p>"
                f"<a class='btn' href='/ingia?ujumbe=ingia-kwanza'>Ingia ili kununua</a>")
    return f"""<form method="post" action="/kikapu/ongeza" class="buybox">{_csrf_input(request)}
<input type="hidden" name="product_id" value="{escape(product['id'])}">
<label for="quantity">Idadi <small>(zinapatikana {avail})</small></label>
<input id="quantity" name="quantity" type="number" min="1" max="{min(avail, 999)}" value="1" inputmode="numeric">
<button class="primary" type="submit">Weka kwenye kikapu</button></form>"""


# ------------------------------------------------------------------ cart + checkout (M11)
@router.post("/kikapu/ongeza")
def add(request: Request, csrf: str = Form(""), product_id: str = Form(""), quantity: str = Form("1"),
        ctx: SessionContext | None = Depends(optional_session), svc: OrderService = Depends(get_order_service)):
    check_csrf(request, csrf)
    if ctx is None:
        return _login()
    try:
        svc.add_item(ctx, product_id[:40], int(quantity) if quantity.strip().isdigit() else 0)
    except AuthError as exc:
        return _redirect(f"/bidhaa/{quote(product_id[:40])}?kosa={quote(exc.message)}")
    return _redirect("/kikapu?ujumbe=imeongezwa-kikapu")


@router.post("/kikapu/badilisha")
def change(request: Request, csrf: str = Form(""), product_id: str = Form(""), quantity: str = Form("0"),
           ctx: SessionContext | None = Depends(optional_session), svc: OrderService = Depends(get_order_service)):
    check_csrf(request, csrf)
    if ctx is None:
        return _login()
    try:
        svc.set_quantity(ctx, product_id[:40], int(quantity) if quantity.strip().isdigit() else 0)
    except AuthError as exc:
        return _cart_page(request, ctx, svc, error=exc.message, status=exc.status)
    return _redirect("/kikapu?ujumbe=kikapu-kimesasishwa")


def _cart_page(request, ctx, svc: OrderService, *, notice: str | None = None, error: str | None = None,
               form: dict | None = None, status: int = 200):
    cart = svc.view(ctx)
    f = form or {"name": ctx.user.full_name, "phone": ctx.user.phone_e164, "region": "", "area": "", "street": "",
                 "notes": ""}
    if not cart["groups"]:
        body = f"""<div class="hero"><h1>Kikapu</h1></div>{alert(notice, "ok")}{alert(error)}
<div class="card c"><p class="sub">Kikapu chako ni tupu.</p><a class="btn" href="/soko">Nenda sokoni</a></div>"""
        return _html(request, "Kikapu", body, ctx=ctx, status=status)
    groups = []
    for g in cart["groups"]:
        rows = []
        for it in g["items"]:
            img = (f"<img class='thumb' src='{escape(it['image'])}' alt=''>" if it["image"]
                   else "<span class='thumb'></span>")
            prob = f"<small class='bad'>{escape(it['problem'])}</small>" if it["problem"] else ""
            rows.append(f"""<tr><td class="prod">{img}<span><a href="/bidhaa/{escape(it['product_id'])}">{escape(it['name'])}</a>
<small>{escape(money(float(it['unit_price'])))} / {escape(it['unit'])}</small>{prob}</span></td>
<td><form method="post" action="/kikapu/badilisha" class="qty">{_csrf_input(request)}
<input type="hidden" name="product_id" value="{escape(it['product_id'])}">
<input name="quantity" type="number" min="0" max="999" value="{it['quantity']}" aria-label="Idadi ya {escape(it['name'])}">
<button type="submit" class="linkbtn">Sasisha</button></form></td>
<td class="num">{escape(money(float(it['line_total'])))}</td>
<td><form method="post" action="/kikapu/badilisha" class="inline">{_csrf_input(request)}
<input type="hidden" name="product_id" value="{escape(it['product_id'])}"><input type="hidden" name="quantity" value="0">
<button type="submit" class="linkbtn">Ondoa</button></form></td></tr>""")
        groups.append(f"""<h2 class="sec">{escape(g['shop']['name'])}</h2>
<table class="cart"><thead><tr><th>Bidhaa</th><th>Idadi</th><th>Jumla</th><th></th></tr></thead>
<tbody>{''.join(rows)}</tbody><tfoot><tr><td colspan="2">Jumla ndogo ya duka hili</td>
<td class="num"><b>{escape(money(float(g['subtotal'])))}</b></td><td></td></tr></tfoot></table>""")
    key = uuid.uuid4().hex  # one checkout attempt; a double submit replays the same result (ORD-001)
    body = f"""<div class="hero"><h1>Kikapu</h1>
<p>Kila duka hupokea oda yake. Bei hukaguliwa upya wakati wa kuweka oda.</p></div>
{alert(notice, "ok")}{alert(error)}{''.join(groups)}
<div class="checkout"><div class="card wide"><h1 class="sm">Weka oda</h1>
<form method="post" action="/kikapu/lipa">{_csrf_input(request)}
<input type="hidden" name="idempotency_key" value="{key}">
<input type="hidden" name="expected_total" value="{escape(cart['total'])}">
{field("name", "Jina la mpokeaji", value=f['name'], extra='required maxlength="120" autocomplete="name"')}
{field("phone", "Simu ya mpokeaji", type_="tel", value=f['phone'], extra='required inputmode="tel" autocomplete="tel"')}
{field("region", "Mkoa", value=f['region'], hint="mf. Dar es Salaam", extra='required maxlength="60"')}
{field("area", "Wilaya / eneo", value=f['area'], extra='maxlength="80"')}
{field("street", "Mtaa / alama ya karibu", value=f['street'], extra='maxlength="160"')}
{field("notes", "Maelekezo ya ziada", value=f['notes'], extra='maxlength="300"')}
<fieldset class="pay"><legend>Njia ya malipo</legend>
<label class="radio"><input type="radio" name="payment_method" value="ONLINE" checked> Lipa mtandaoni (M-Pesa, Tigo Pesa, Airtel Money, kadi)</label>
<label class="radio muted"><input type="radio" name="payment_method" value="COD" disabled> Lipa mzigo ukifika <small>(inakuja: Module 14)</small></label>
</fieldset>
<p class="total">Jumla ya kulipa: <b>{escape(money(float(cart['total'])))}</b></p>
<button class="primary" type="submit">Weka oda</button></form></div></div>"""
    return _html(request, "Kikapu", body, ctx=ctx, status=status)


@router.get("/kikapu", response_class=HTMLResponse)
def cart_page(request: Request, ujumbe: str = "", ctx: SessionContext | None = Depends(optional_session),
              svc: OrderService = Depends(get_order_service)):
    if ctx is None:
        return _login()
    return _cart_page(request, ctx, svc, notice=NOTICES.get(ujumbe))


@router.post("/kikapu/lipa")
def place_order(request: Request, csrf: str = Form(""), idempotency_key: str = Form(""),
                expected_total: str = Form(""), name: str = Form(""), phone: str = Form(""), region: str = Form(""),
                area: str = Form(""), street: str = Form(""), notes: str = Form(""),
                payment_method: str = Form("ONLINE"), ctx: SessionContext | None = Depends(optional_session),
                svc: OrderService = Depends(get_order_service)):
    check_csrf(request, csrf)
    if ctx is None:
        return _login()
    form = {"name": name[:120], "phone": phone[:32], "region": region[:60], "area": area[:80], "street": street[:160],
            "notes": notes[:300]}
    try:
        result = svc.checkout(ctx, Address(**form), payment_method[:12], idempotency_key[:80], expected_total[:24])
    except AuthError as exc:
        return _cart_page(request, ctx, svc, error=exc.message, form=form, status=exc.status)
    orders = result["orders"]
    target = f"/oda/{quote(orders[0]['number'])}" if len(orders) == 1 else "/oda"
    return _redirect(f"{target}?ujumbe=oda-imewekwa")


# ------------------------------------------------------------------ buyer orders (M12)
@router.get("/oda", response_class=HTMLResponse)
def my_orders(request: Request, ujumbe: str = "", ctx: SessionContext | None = Depends(optional_session),
              svc: OrderService = Depends(get_order_service)):
    if ctx is None:
        return _login()
    rows = "".join(f"""<tr><td><a href="/oda/{escape(o['number'])}"><b>{escape(o['number'])}</b></a>
<small>{escape(o['created_at'][:16].replace('T', ' '))}</small></td><td>{escape(o['shop']['name'])}</td>
<td>{pill(o['status'])}</td><td class="num">{escape(money(float(o['total'])))}</td></tr>""" for o in svc.my_orders(ctx))
    body = f"""<div class="hero"><h1>Oda zangu</h1><p>Unaona oda zako tu.</p></div>{alert(NOTICES.get(ujumbe), "ok")}
{f'<table><thead><tr><th>Oda</th><th>Duka</th><th>Hali</th><th>Jumla</th></tr></thead><tbody>{rows}</tbody></table>'
 if rows else '<div class="card c"><p class="sub">Bado hujaweka oda.</p><a class="btn" href="/soko">Nenda sokoni</a></div>'}"""
    return _html(request, "Oda zangu", body, ctx=ctx)


def _order_common(o: dict) -> str:
    items = "".join(f"""<tr><td class="prod">{f"<img class='thumb' src='{escape(i['image'])}' alt=''>" if i['image']
                                              else "<span class='thumb'></span>"}<span>{escape(i['name'])}
<small>{escape(money(float(i['unit_price'])))} / {escape(i['unit'])} · SKU {escape(i['sku'])}</small></span></td>
<td class="num">{i['quantity']}</td><td class="num">{escape(money(float(i['line_total'])))}</td></tr>""" for i in o["items"])
    d = o["delivery"]
    addr = ", ".join(escape(x) for x in (d["street"], d["area"], d["region"]) if x)
    timeline = "".join(f"<li><b>{escape(STATUS_LABELS.get(h['to'], h['to']))}</b> "
                       f"<small>{escape(h['at'][:16].replace('T', ' '))} · {escape(h['actor'])}"
                       f"{(' · ' + escape(h['note'])) if h['note'] else ''}</small></li>" for h in o["history"])
    courier = (f"<dt>Msafirishaji</dt><dd>{escape(o['courier']['name'])} · {escape(o['courier']['phone'])}</dd>"
               if o["courier"] else "")
    flags = ""
    if o["cancel_requested"]:
        flags += alert(f"Mnunuzi ameomba kughairi: {o['cancel_reason'] or ''}")
    if o["refund_required"]:
        flags += alert("Marejesho ya fedha yanahitajika (yatashughulikiwa na Fedha).", "ok")
    return f"""{flags}<div class="ogrid"><div>
<table><thead><tr><th>Bidhaa</th><th>Idadi</th><th>Jumla</th></tr></thead><tbody>{items}</tbody>
<tfoot><tr><td colspan="2">Jumla</td><td class="num"><b>{escape(money(float(o['total'])))}</b></td></tr></tfoot></table>
<div class="tile"><h3>Kupelekwa kwa</h3><dl><dt>Mpokeaji</dt><dd>{escape(d['name'])} · {escape(d['phone'])}</dd>
<dt>Anwani</dt><dd>{addr}</dd>{f"<dt>Maelekezo</dt><dd>{escape(d['notes'])}</dd>" if d['notes'] else ''}{courier}</dl></div>
</div><div class="tile"><h3>Historia ya oda</h3><ol class="timeline">{timeline}</ol></div></div>"""


@router.get("/oda/{number}", response_class=HTMLResponse)
def my_order(number: str, request: Request, ujumbe: str = "", kosa: str = "",
             ctx: SessionContext | None = Depends(optional_session), svc: OrderService = Depends(get_order_service)):
    if ctx is None:
        return _login()
    try:
        o = svc.order_dict(svc.buyer_order(ctx, number[:24]))
    except AuthError as exc:
        return _notfound(request, ctx, exc)
    n = escape(o["number"])
    acts = []
    if o["status"] == "PENDING_PAYMENT":
        exp = (o["expires_at"] or "")[11:16]
        acts.append(f"<p>Lipa kabla ya saa <b>{escape(exp)}</b> (UTC). Usipolipa, oda itaisha na bidhaa zitaachiliwa.</p>")
        if _dev(request):
            acts.append(f"""<form method="post" action="/dev/lipa/{n}" class="inline">{_csrf_input(request)}
<button class="primary" type="submit">Lipa sasa (malipo ya majaribio)</button></form>
<p class="hint">Mazingira ya majaribio: kitufe hiki kinaiga uthibitisho wa mtoa huduma wa malipo. Malipo halisi yanakuja Module 13.</p>""")
    if "cancel" in o["actions"]:
        acts.append(f"""<form method="post" action="/oda/{n}/ghairi">{_csrf_input(request)}
<input type="hidden" name="reason" value=""><button type="submit" class="btn ghost wide">Ghairi oda</button></form>""")
    if "request_cancel" in o["actions"]:
        acts.append(f"""<form method="post" action="/oda/{n}/ghairi">{_csrf_input(request)}
{field("reason", "Unataka kughairi? Eleza sababu", extra='maxlength="300" required')}
<button type="submit" class="btn ghost wide">Omba kughairi</button></form>""")
    if "resend_pin" in o["actions"]:
        acts.append(f"""<p>Oda iko njiani. Mpe msafirishaji <b>PIN uliyotumiwa kwa SMS</b> pale tu utakapopokea mzigo.</p>
<form method="post" action="/oda/{n}/pin">{_csrf_input(request)}
<button type="submit" class="linkbtn">Tuma PIN mpya</button></form>""")
    if o["status"] == "DELIVERED":
        acts.append("<p>Oda imefika. Sasa unaweza kutoa maoni kwa bidhaa ulizonunua (Module 18).</p>")
    body = f"""<div class="hero"><h1>Oda {n}</h1><p>{pill(o['status'])} · Duka:
<a href="/duka/{escape(o['shop']['slug'])}">{escape(o['shop']['name'])}</a> · Malipo: {escape(o['payment_status'])}</p></div>
{alert(NOTICES.get(ujumbe), "ok")}{alert(kosa[:200] or None)}
{f"<div class='tile actions'>{''.join(acts)}</div>" if acts else ""}{_order_common(o)}"""
    return _html(request, f"Oda {o['number']}", body, ctx=ctx)


@router.post("/oda/{number}/ghairi")
def buyer_cancel(number: str, request: Request, csrf: str = Form(""), reason: str = Form(""),
                 ctx: SessionContext | None = Depends(optional_session),
                 svc: OrderService = Depends(get_order_service)):
    check_csrf(request, csrf)
    if ctx is None:
        return _login()
    try:
        order = svc.buyer_cancel(ctx, number[:24], reason[:300])
    except AuthError as exc:
        return _redirect(f"/oda/{quote(number[:24])}?kosa={quote(exc.message)}")
    return _redirect(f"/oda/{quote(order.number)}?ujumbe="
                     f"{'imeghairiwa' if order.status == 'CANCELLED' else 'ombi-limetumwa'}")


@router.post("/oda/{number}/pin")
def buyer_pin(number: str, request: Request, csrf: str = Form(""),
              ctx: SessionContext | None = Depends(optional_session), svc: OrderService = Depends(get_order_service)):
    check_csrf(request, csrf)
    if ctx is None:
        return _login()
    try:
        svc.resend_pin(ctx, number[:24])
    except AuthError as exc:
        return _redirect(f"/oda/{quote(number[:24])}?kosa={quote(exc.message)}")
    return _redirect(f"/oda/{quote(number[:24])}?ujumbe=pin-imetumwa")


@router.post("/dev/lipa/{number}")
def dev_pay(number: str, request: Request, csrf: str = Form(""),
            ctx: SessionContext | None = Depends(optional_session), svc: OrderService = Depends(get_order_service)):
    """Development/test only: simulate a verified provider callback. 404 in staging/production."""
    if not _dev(request):
        raise HTTPException(status_code=404)
    check_csrf(request, csrf)
    if ctx is None:
        return _login()
    try:
        order = svc.buyer_order(ctx, number[:24])
    except AuthError as exc:
        return _notfound(request, ctx, exc)
    status = payments.confirm_payment(svc.db, order.number, f"DEV-{uuid.uuid4().hex[:12]}")
    return _redirect(f"/oda/{quote(order.number)}?ujumbe={'imelipwa' if status == 'CONFIRMED' else 'imesasishwa'}")


# ------------------------------------------------------------------ seller orders (M12)
@router.get("/maduka/{slug}/oda", response_class=HTMLResponse)
def shop_orders(slug: str, request: Request, hali: str = "", ctx: SessionContext | None = Depends(optional_session),
                svc: OrderService = Depends(get_order_service)):
    if ctx is None:
        return _login()
    try:
        orders = svc.shop_orders(ctx, slug, hali[:20] or None)
        shop = svc.shop_by_slug(slug)
    except AuthError as exc:
        return _notfound(request, ctx, exc)
    counts = svc.shop_order_counts(shop.id)
    tabs = [("", "Zote", sum(counts.values()))] + [(s, STATUS_LABELS[s], counts.get(s, 0)) for s in
                                                  ("CONFIRMED", "PROCESSING", "SHIPPED", "DELIVERED", "PENDING_PAYMENT",
                                                   "CANCELLED")]
    tab_html = "".join(f"<a href='/maduka/{escape(slug)}/oda{('?hali=' + s) if s else ''}'"
                       f"{' aria-current=page' if s == hali.upper() else ''}>{escape(label)} ({c})</a>"
                       for s, label, c in tabs)
    rows = "".join(f"""<tr><td><a href="/maduka/{escape(slug)}/oda/{escape(o['number'])}"><b>{escape(o['number'])}</b></a>
<small>{escape(o['created_at'][:16].replace('T', ' '))}</small></td><td>{escape(o['customer'])}</td>
<td>{pill(o['status'])}{" <span class='pill todo'>Ombi la kughairi</span>" if o['cancel_requested'] else ''}</td>
<td class="num">{escape(money(float(o['total'])))}</td></tr>""" for o in orders)
    body = f"""<div class="hero"><h1>Oda za {escape(shop.name)}</h1>
<p><a href="/maduka/{escape(slug)}">← Dashibodi ya duka</a></p></div><nav class="tabs">{tab_html}</nav>
{f'<table><thead><tr><th>Oda</th><th>Mteja</th><th>Hali</th><th>Jumla</th></tr></thead><tbody>{rows}</tbody></table>'
 if rows else '<p class="sub">Hakuna oda katika kundi hili.</p>'}"""
    return _html(request, "Oda za duka", body, ctx=ctx)


@router.get("/maduka/{slug}/oda/{number}", response_class=HTMLResponse)
def shop_order(slug: str, number: str, request: Request, ujumbe: str = "", kosa: str = "",
               ctx: SessionContext | None = Depends(optional_session), svc: OrderService = Depends(get_order_service)):
    if ctx is None:
        return _login()
    try:
        shop, order = svc.shop_order(ctx, slug, number[:24], "shop.orders.view")
    except AuthError as exc:
        return _notfound(request, ctx, exc)
    o = svc.order_dict(order, seller=True)
    can_fulfil = svc.authz.can(ctx.user.id, "shop.orders.fulfil", shop_id=shop.id)
    base = f"/maduka/{escape(slug)}/oda/{escape(o['number'])}"
    acts = []
    if can_fulfil:
        if "process" in o["actions"]:
            acts.append(f"""<form method="post" action="{base}/hali">{_csrf_input(request)}
<input type="hidden" name="status" value="PROCESSING"><button class="primary" type="submit">Anza kuandaa oda</button></form>""")
        if "ship" in o["actions"]:
            acts.append(f"""<form method="post" action="{base}/hali">{_csrf_input(request)}
<input type="hidden" name="status" value="SHIPPED">
{field("courier_name", "Jina la msafirishaji", extra='required maxlength="120"')}
{field("courier_phone", "Simu ya msafirishaji", type_="tel", extra='required inputmode="tel"')}
<button class="primary" type="submit">Safirisha (mnunuzi atapata PIN kwa SMS)</button></form>""")
        if "deliver" in o["actions"]:
            locked = "<p class='alert err'>PIN imefungwa. Mnunuzi aombe PIN mpya.</p>" if o["pin_locked"] else ""
            acts.append(f"""<form method="post" action="{base}/fika">{_csrf_input(request)}{locked}
{field("pin", "PIN ya mnunuzi (tarakimu 6)", extra='class="code" inputmode="numeric" maxlength="6" required autocomplete="off"')}
<button class="primary" type="submit">Thibitisha kufika</button></form>
<details><summary>Badilisha msafirishaji</summary><form method="post" action="{base}/msafirishaji">{_csrf_input(request)}
{field("courier_name", "Jina", extra='required maxlength="120"')}{field("courier_phone", "Simu", type_="tel", extra='required')}
<button class="primary" type="submit">Hifadhi</button></form></details>""")
        if "cancel" in o["actions"]:
            acts.append(f"""<details{' open' if o['cancel_requested'] else ''}><summary>Ghairi oda</summary>
<form method="post" action="{base}/ghairi">{_csrf_input(request)}
{field("reason", "Sababu (itaonekana kwa mnunuzi)", value=o['cancel_reason'] or '', extra='required maxlength="300"')}
<button class="primary danger" type="submit">Ghairi na rudisha stock</button></form></details>""")
    body = f"""<div class="hero"><h1>Oda {escape(o['number'])}</h1><p>{pill(o['status'])} · Malipo: {escape(o['payment_status'])} ·
<a href="/maduka/{escape(slug)}/oda">← Oda zote</a></p></div>{alert(NOTICES.get(ujumbe), "ok")}{alert(kosa[:200] or None)}
{f"<div class='tile actions'>{''.join(acts)}</div>" if acts else ""}{_order_common(o)}"""
    return _html(request, f"Oda {o['number']}", body, ctx=ctx)


def _seller_post(request, csrf, ctx, slug, number, action, notice):
    check_csrf(request, csrf)
    if ctx is None:
        return _login()
    try:
        action()
    except AuthError as exc:
        if exc.status == 404:
            return _notfound(request, ctx, exc)
        return _redirect(f"/maduka/{quote(slug)}/oda/{quote(number[:24])}?kosa={quote(exc.message)}")
    return _redirect(f"/maduka/{quote(slug)}/oda/{quote(number[:24])}?ujumbe={notice}")


@router.post("/maduka/{slug}/oda/{number}/hali")
def seller_advance(slug: str, number: str, request: Request, csrf: str = Form(""), status: str = Form(""),
                   courier_name: str = Form(""), courier_phone: str = Form(""),
                   ctx: SessionContext | None = Depends(optional_session),
                   svc: OrderService = Depends(get_order_service)):
    return _seller_post(request, csrf, ctx, slug, number, lambda: svc.advance(
        ctx, slug, number[:24], status[:20], courier_name=courier_name[:120], courier_phone=courier_phone[:32]),
        "imesasishwa")


@router.post("/maduka/{slug}/oda/{number}/msafirishaji")
def seller_courier(slug: str, number: str, request: Request, csrf: str = Form(""), courier_name: str = Form(""),
                   courier_phone: str = Form(""), ctx: SessionContext | None = Depends(optional_session),
                   svc: OrderService = Depends(get_order_service)):
    return _seller_post(request, csrf, ctx, slug, number, lambda: svc.assign_courier(
        ctx, slug, number[:24], courier_name[:120], courier_phone[:32]), "msafirishaji")


@router.post("/maduka/{slug}/oda/{number}/fika")
def seller_deliver(slug: str, number: str, request: Request, csrf: str = Form(""), pin: str = Form(""),
                   ctx: SessionContext | None = Depends(optional_session),
                   svc: OrderService = Depends(get_order_service)):
    return _seller_post(request, csrf, ctx, slug, number,
                        lambda: svc.confirm_delivery(ctx, slug, number[:24], pin[:12]), "imefika")


@router.post("/maduka/{slug}/oda/{number}/ghairi")
def seller_cancel(slug: str, number: str, request: Request, csrf: str = Form(""), reason: str = Form(""),
                  ctx: SessionContext | None = Depends(optional_session),
                  svc: OrderService = Depends(get_order_service)):
    return _seller_post(request, csrf, ctx, slug, number,
                        lambda: svc.seller_cancel(ctx, slug, number[:24], reason[:300]), "imeghairiwa")
