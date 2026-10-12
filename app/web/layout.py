"""Shared page shell (minimal; the full header/navigation system arrives in M06).

No JavaScript. Every dynamic value must be passed through ``escape`` by the caller
or by the helpers below.
"""

from __future__ import annotations

from html import escape

CSS = """
:root{--bg:#f6f4ef;--card:#fff;--ink:#1d2a24;--muted:#5d6b64;--line:#e3ded3;--brand:#1f6f4a;--brand-ink:#fff;
--todo:#9aa39e;--design:#b7791f;--built:#1f6f4a;--closed:#2b4c7e;--err:#b42318;--err-bg:#fdecea;--ok-bg:#e8f5ee}
@media (prefers-color-scheme:dark){:root{--bg:#121714;--card:#1a211d;--ink:#e8efe9;--muted:#9fb0a6;
--line:#2a342e;--brand:#4fbf86;--brand-ink:#0d1a13;--built:#4fbf86;--err:#ff8a80;--err-bg:#3a1714;--ok-bg:#16301f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--brand)}
header.top{background:var(--brand);color:var(--brand-ink);padding:14px 16px}
header.top .wrap{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
header.top a{color:var(--brand-ink);text-decoration:none}
header.top .brand{font-weight:700;font-size:22px}
header.top nav{display:flex;gap:16px;align-items:center;font-size:15px}
header.top nav form{margin:0}
header.top nav button{background:transparent;border:1px solid var(--brand-ink);color:var(--brand-ink);
border-radius:8px;padding:4px 10px;font:inherit;cursor:pointer}
.wrap{max-width:980px;margin:0 auto;padding:0 16px}
.hero{padding:22px 0 4px}.hero h1{margin:0;font-size:26px}.hero p{margin:4px 0 0;color:var(--muted)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:20px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.stat b{display:block;font-size:26px}.stat span{color:var(--muted);font-size:14px}
.bar{height:10px;background:var(--line);border-radius:6px;overflow:hidden;margin-top:8px}
.bar i{display:block;height:100%;background:var(--brand)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);font-size:15px}
th{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
td small{display:block;color:var(--muted)}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:13px;color:#fff;white-space:nowrap}
.todo{background:var(--todo)}.design{background:var(--design)}.built{background:var(--built)}.closed{background:var(--closed)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:22px;max-width:440px;margin:28px auto}
.card h1{margin:0 0 6px;font-size:24px}.card p.sub{margin:0 0 18px;color:var(--muted)}
label{display:block;font-weight:600;font-size:14px;margin:14px 0 6px}
label small{font-weight:400;color:var(--muted)}
input{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:8px;font:inherit;
background:var(--bg);color:var(--ink)}
input:focus{outline:2px solid var(--brand);outline-offset:1px}
input.code{letter-spacing:.4em;font-size:22px;text-align:center}
button.primary{width:100%;margin-top:20px;padding:12px;border:0;border-radius:8px;background:var(--brand);
color:var(--brand-ink);font:inherit;font-weight:700;cursor:pointer}
.links{margin-top:16px;font-size:14px;display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap}
.alert{padding:10px 12px;border-radius:8px;margin:0 0 14px;font-size:15px}
.alert.err{background:var(--err-bg);color:var(--err)}.alert.ok{background:var(--ok-bg)}
dl{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;margin:0}dt{color:var(--muted)}dd{margin:0}
.dev{border-style:dashed}
footer{color:var(--muted);font-size:13px;padding:20px 0 40px}
@media (max-width:600px){.hide-sm{display:none}.pill{white-space:normal;border-radius:10px}th,td{padding:10px 8px}
.card{margin:16px 0;padding:18px}}
"""


def page(title: str, body: str, *, user_name: str | None = None, csrf: str = "") -> str:
    """Wrap ``body`` (already-escaped HTML) in the site shell."""
    if user_name:
        nav = (f'<a href="/akaunti">{escape(user_name.split()[0])}</a>'
               f'<form method="post" action="/toka"><input type="hidden" name="csrf" value="{escape(csrf)}">'
               f'<button type="submit">Toka</button></form>')
    else:
        nav = '<a href="/ingia">Ingia</a><a href="/jisajili">Jisajili</a>'
    return f"""<!doctype html><html lang="sw"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} – Bongo Markets</title><style>{CSS}</style></head><body>
<header class="top"><div class="wrap"><a class="brand" href="/">Bongo Markets</a><nav>{nav}</nav></div></header>
<main class="wrap">{body}</main></body></html>"""


def alert(message: str | None, kind: str = "err") -> str:
    return f'<div class="alert {kind}" role="alert">{escape(message)}</div>' if message else ""


def field(name: str, label: str, *, type_: str = "text", value: str = "", hint: str = "", extra: str = "") -> str:
    hint_html = f" <small>{escape(hint)}</small>" if hint else ""
    return (f'<label for="{name}">{escape(label)}{hint_html}</label>'
            f'<input id="{name}" name="{name}" type="{type_}" value="{escape(value)}" {extra}>')
