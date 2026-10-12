"""Additional dashboard sections contributed by later modules (orders in M12)."""

from __future__ import annotations


def extra_sections(db, shop, perms: set[str]) -> dict:
    """Order counters for members allowed to see the shop's orders (M12, ORD-005)."""
    if "shop.orders.view" not in perms:
        return {}
    from sqlalchemy import text

    counts = dict(db.execute(text("SELECT status, count(*) FROM bm.orders WHERE shop_id = :s GROUP BY status"),
                             {"s": shop.id}).all())
    revenue = db.execute(text("SELECT coalesce(sum(total), 0) FROM bm.orders WHERE shop_id = :s "
                              "AND status = 'DELIVERED'"), {"s": shop.id}).scalar_one()
    return {"orders": {k: int(v) for k, v in counts.items()},
            "cards": [{"value": counts.get("CONFIRMED", 0), "label": "Oda mpya (zimelipwa)"},
                      {"value": counts.get("PROCESSING", 0) + counts.get("SHIPPED", 0),
                       "label": "Oda zinazoshughulikiwa"},
                      {"value": f"TZS {int(revenue):,}", "label": "Mauzo yaliyofika"}]}
