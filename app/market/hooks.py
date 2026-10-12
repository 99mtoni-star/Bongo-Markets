"""Purchase box on the product page (M11 cart form)."""

from __future__ import annotations


def buy_box(request, ctx, product: dict) -> str:
    from app.orders.web import buy_box as cart_buy_box  # M11 add-to-cart form

    return cart_buy_box(request, ctx, product)
