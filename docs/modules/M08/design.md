# M08 — Categories, Products, Images na Stock: Design

## Data (migration 0006)

- `categories`: a seeded, read-only catalogue (Kuku na ndege, Mayai, ...).
- `products`: `shop_id` (BR-007), `category_id` (PRD-002), `UNIQUE(shop_id, sku)` (PRD-003), `price NUMERIC(18,2) ≥ 0`, `stock ≥ 0`, `0 ≤ reserved ≤ stock` (PRD-004, enforced by the DB), status DRAFT/ACTIVE/SUSPENDED/ARCHIVED (ACTIVE requires price > 0).
- `product_images`: metadata of re-encoded images (type, size, dimensions, SHA-256, uploader).
- `stock_reservations` + the `stock_reservation_minutes` setting (default 15).
- No hard deletes by the app; column-level UPDATE only.

## Rules

| Req | Control |
|---|---|
| PRD-001 | `shop.products.manage` to create, edit, suspend or archive; price changes need `shop.products.price` (owner/manager) |
| PRD-005, V13-SEC-004 | Magic-byte sniffing (client type ignored), 5 MB cap while streaming, full decode with a pixel-bomb limit, 100–6000 px, **re-encode to WebP** (removes EXIF/GPS and any payload). Rejections are audited. Served with `nosniff` and a sandbox CSP |
| V13-REQ-005 | `Storage` interface (local now; object storage + CDN in M20); random 192-bit keys |
| BR-011 | Publicly visible ⇔ product ACTIVE ∧ marketplace ∧ shop ACTIVE |
| BR-009/010 | Shop page and API list only the shop's own active products; category headings come from those products |
| STK-001/003/004 | `catalog/stock.py`: row-locked reserve/commit/release/expire; the DB invariant prevents oversell; the 10-thread last-unit race test passes |
| STK-002 | `PUT /admin/settings/stock-reservation-minutes` (permission + SETTINGS_CHANGE step-up, 5–60 min, audited) |
| SEC-SDLC-005 | `docs/operations/patch-management.md` |
| V13-REQ-008 | **Deferred**: service-job material lists need the service-provider module (not yet allocated) |
| CAP-VID-001 | **Deferred** (no requirement yet) |

Operations: run `scripts/expire_reservations.py` every minute.

Design Ready: YES — Claude (developer), 2026-10-12 UTC
