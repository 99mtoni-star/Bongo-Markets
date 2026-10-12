# M06 — Shared UI, Header na Navigation: Design

| Req | Control |
|---|---|
| NFR-004 | Shared shell (`app/web/layout.py`): header with Soko / Maduka yangu / Akaunti / Usimamizi (admins only) / Toka; a `<details>` phone menu that needs no JavaScript; footer links; skip link |
| NFR-M07 | Plain HTML/CSS using widely supported features; automated Chromium check at 390/1280 px; manual cross-browser check per release (`docs/operations/browser-support.md`) |
| NFR-M09 | Logrotate: 90-day retention for app logs (`deploy/logrotate/bongo-markets`); audit records follow their own schedule (M05) |
| SEC-007 | Central escaping, CSP with no `unsafe-inline` (scripts **and** styles), `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`; all styles in a versioned static file |
| SEC-008, SEC-WEB-004, SEC-INV-003 | Two independent controls on every state-changing request: (1) Origin/Referer allow-list in middleware, (2) CSRF double-submit token (form field or `X-CSRF-Token`). Webhooks (M13) are exempt and use signatures + replay guard instead |
| SEC-COM-005 | `docs/compliance/breach-response.md` |
| SEC-COM-007 | `docs/compliance/cross-border-transfers.md` (processor register, approval rule, M20 gate) + privacy page statement |
| SEC-SDLC-002 | `scripts/scan_secrets.py` in the gate and CI; `pip-audit` in CI |
| CAP-CHAT-001 | Gated: contract requirements recorded in `docs/compliance/feature-contracts.md`; no chat code |

Pages: `/` (home), `/hali` (system status, moved from `/`), `/faragha`, `/masharti`, `/soko` (placeholder until M09).

Design Ready: YES — Claude (developer), 2026-10-12 UTC
