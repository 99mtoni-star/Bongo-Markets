"""Shared page shell: header, navigation, footer (M06).

- No JavaScript and no inline styles: the CSP allows only same-origin stylesheets (SEC-007).
- Every dynamic value is escaped here or by the caller.
- Responsive: desktop navigation bar; on phones a <details> menu (works without JavaScript) (NFR-004).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from dataclasses import field as dc_field
from html import escape
from pathlib import Path

STATIC_DIR = Path(__file__).resolve().parent / "static"
CSS_VERSION = hashlib.sha256((STATIC_DIR / "app.css").read_bytes()).hexdigest()[:10]


@dataclass
class Nav:
    user_name: str | None = None
    csrf: str = ""
    is_admin: bool = False
    has_shops: bool = False
    cart_count: int = 0
    current: str = ""
    links: list[tuple[str, str]] = dc_field(default_factory=list)


def _links(nav: Nav) -> list[tuple[str, str]]:
    links = [("/soko", "Soko")]
    if nav.user_name:
        links.append(("/kikapu", f"Kikapu ({nav.cart_count})" if nav.cart_count else "Kikapu"))
        links.append(("/oda", "Oda zangu"))
        links.append(("/maduka", "Maduka yangu" if nav.has_shops else "Fungua duka"))
        links.append(("/akaunti", "Akaunti"))
        if nav.is_admin:
            links.append(("/simamizi/majukumu", "Usimamizi"))
    return links


def _nav_html(nav: Nav, cls: str) -> str:
    items = []
    for href, label in _links(nav):
        cur = ' aria-current="page"' if nav.current and nav.current.startswith(href) else ""
        items.append(f'<a href="{href}"{cur}>{escape(label)}</a>')
    if nav.user_name:
        items.append(f'<form method="post" action="/toka" class="inline"><input type="hidden" name="csrf" '
                     f'value="{escape(nav.csrf)}"><button type="submit">Toka ({escape(nav.user_name.split()[0])})'
                     f'</button></form>')
    else:
        items.append('<a href="/ingia">Ingia</a><a href="/jisajili">Jisajili</a>')
    return f'<nav class="{cls}" aria-label="Menyu kuu">{"".join(items)}</nav>'


def page(title: str, body: str, *, user_name: str | None = None, csrf: str = "", nav: Nav | None = None) -> str:
    """Wrap ``body`` (already-escaped HTML) in the site shell."""
    nav = nav or Nav(user_name=user_name, csrf=csrf)
    return f"""<!doctype html><html lang="sw"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{escape(title)} – Bongo Markets</title>
<link rel="stylesheet" href="/static/app.css?v={CSS_VERSION}"></head><body>
<a class="skip" href="#yaliyomo">Ruka hadi maudhui</a>
<header class="top"><div class="wrap topbar"><a class="brand" href="/">Bongo Markets</a>
{_nav_html(nav, "main")}
<details class="menu"><summary aria-label="Fungua menyu">☰ Menyu</summary>{_nav_html(nav, "")}</details>
</div></header>
<main class="wrap" id="yaliyomo">{body}</main>
<footer class="site"><div class="wrap"><span>© Bongo Markets · Soko la maduka mengi, Tanzania</span>
<span><a href="/faragha">Faragha</a> · <a href="/masharti">Masharti</a> · <a href="/hali">Hali ya mfumo</a></span>
</div></footer></body></html>"""


def alert(message: str | None, kind: str = "err") -> str:
    return f'<div class="alert {kind}" role="alert">{escape(message)}</div>' if message else ""


def field(name: str, label: str, *, type_: str = "text", value: str = "", hint: str = "", extra: str = "") -> str:
    hint_html = f" <small>{escape(hint)}</small>" if hint else ""
    return (f'<label for="{name}">{escape(label)}{hint_html}</label>'
            f'<input id="{name}" name="{name}" type="{type_}" value="{escape(value)}" {extra}>')
