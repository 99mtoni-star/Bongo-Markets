"""Read-only RBAC matrix page for administrators (M05)."""

from __future__ import annotations

from html import escape

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from app.auth.deps import optional_session
from app.auth.service import AuthError, SessionContext
from app.auth.web import _html, _redirect
from app.authz.api import get_rbac_service
from app.authz.service import RBACService

router = APIRouter(include_in_schema=False)


@router.get("/simamizi/majukumu", response_class=HTMLResponse)
def rbac_matrix(request: Request, ctx: SessionContext | None = Depends(optional_session),
                svc: RBACService = Depends(get_rbac_service)):
    if ctx is None:
        return _redirect("/ingia?ujumbe=ingia-kwanza")
    try:
        cat = svc.catalogue(ctx)
    except AuthError as exc:
        body = f'<div class="card"><h1>Hairuhusiwi</h1><p class="sub">{escape(exc.message)}</p></div>'
        return _html(request, "Hairuhusiwi", body, ctx=ctx, status=exc.status)

    def matrix(scope: str, roles: dict[str, list[str]]) -> str:
        names = sorted(roles, key=lambda r: -len(roles[r]))
        head = "".join(f"<th>{escape(r)}</th>" for r in names)
        rows = []
        for p in (p for p in cat["permissions"] if p["scope"] == scope):
            cells = "".join(f"<td class='c'>{'✓' if p['code'] in roles[r] else ''}</td>"
                            for r in names)
            risk = " <span class='pill design'>hatari</span>" if p["high_risk"] else ""
            rows.append(f"<tr><td><code>{escape(p['code'])}</code>{risk}"
                        f"<small>{escape(p['description'])}</small></td>{cells}</tr>")
        return f"<table><thead><tr><th>Ruhusa</th>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table>"

    body = f"""<div class="hero"><h1>Majukumu na ruhusa</h1>
<p>Toleo la sera: <b>{cat['policy_version']}</b> · Kila ombi linakaguliwa na server; kisichoruhusiwa wazi
kimekatazwa.</p></div>
<h2 class="sec">Majukumu ya jukwaa (platform)</h2>{matrix("PLATFORM", cat["platform_roles"])}
<h2 class="sec">Majukumu ya duka (shop)</h2>{matrix("SHOP", cat["shop_roles"])}
<footer>Mabadiliko hufanywa kupitia API yenye MFA, step-up, CSRF na If-Match (docs/api/rbac.md).</footer>"""
    return _html(request, "Majukumu", body, ctx=ctx)
