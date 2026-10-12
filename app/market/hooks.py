"""Purchase box on the product page (filled in by M11 cart)."""

from __future__ import annotations


def buy_box(request, ctx, product: dict) -> str:
    if product["available_quantity"] <= 0:
        return "<p class='alert err'>Bidhaa hii imeisha kwa sasa.</p>"
    return f"<p class='hint'>Zinapatikana: {product['available_quantity']}</p>"
