# M07 — Shops, Ownership na Staff: Design

## Data (migration 0005, sensitive review)

- `shops` (slug, name, region, owner_user_id, status)
- `shop_users` (OWNER/MANAGER/STAFF; soft-removal). Partial unique indexes: one active membership per user per shop, and **one active OWNER per shop**.
- `shop_status_history` (append-only for the app)
- A deferred constraint trigger checks at COMMIT that the active OWNER equals `shops.owner_user_id` (BR-003/004/005).
- The app has no DELETE on any of these tables and only column-level UPDATE.

## Rules

| Req | Control |
|---|---|
| SHOP-001/002, BR-001/002 | Any active user may open up to 10 shops (rate limited). Buyer and seller on one account |
| SHOP-003, BR-003/004 | The creator becomes OWNER in `shop_users`; the DB invariant enforces it |
| SHOP-004 | Owner adds managers and staff; managers add staff; staff add no one |
| BR-005, SHOP-002 (v1.12.2) | Ownership transfer: `shop.ownership.transfer` + OWNERSHIP_TRANSFER step-up (TOTP), target must be a member, single transaction, audited; the old owner becomes MANAGER |
| BR-006 | OWNER can never be assigned through membership APIs |
| BR-007 | Products reference exactly one shop (FK, M08) |
| BR-008, SEC-004 | Every shop action uses `Authorizer` over `shop_users`; non-members get a generic 404 |
| BR-009/010 | Shop page shows only that shop's products and categories. The hook is in place; tests are in M08 |
| BR-013/015 | Strict request models; an OpenAPI guard ensures no request schema carries payment, ownership or total state |
| SHOP-006 | PENDING→ACTIVE/REJECTED, ACTIVE↔SUSPENDED, →CLOSED; status history + audit + SMS to the owner |
| SHOP-007/008 | `/duka/{slug}`: members see "Simamia Duka" and "Bongo Markets Sokoni" links; customers see no admin controls, and unverified shops are invisible to them |
| CAP-VER-001 | Verification activates the SELLER capability only; it never grants platform permissions |
| SEC-IR-003 (from M04) | Shop suspension is now available to responders (PLATFORM_ADMIN holds `platform.shops.verify`) |

Design Ready: YES — Claude (developer), 2026-10-12 UTC
