"""Shop page product section (M07 hook, filled by M08).

BR-009: only this shop's products. BR-010: category headings come from this shop's own active
products, so categories unrelated to the shop never appear.
"""

from __future__ import annotations

from collections import OrderedDict
from html import escape


def render_shop_products(db, shop) -> str:
    from app.catalog.service import CatalogService
    from app.catalog.web import product_card

    svc = CatalogService.__new__(CatalogService)
    svc.db = db
    products = svc.shop_products(shop, public=True)
    if not products:
        return '<div class="card"><p class="sub">Duka hili bado halina bidhaa zinazouzwa.</p></div>'
    groups: OrderedDict[str, list[str]] = OrderedDict()
    for p in sorted(products, key=lambda p: p.name):
        d = svc.product_dict(p)
        groups.setdefault(d["category_name"], []).append(product_card(d))
    return "".join(f"<h2 class='sec'>{escape(name)}</h2><div class='pgrid'>{''.join(cards)}</div>"
                   for name, cards in groups.items())
