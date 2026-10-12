# M11 — Cart, Checkout na Stock Reservation: Design

## Data (migration 0008, shared with M12)

- `carts`: one row per cart; partial unique index `uq_carts_one_active (user_id) WHERE status='ACTIVE'`.
- `cart_items`: `UNIQUE(cart_id, product_id)`, quantity 1–999. **No price column**: the cart stores quantities only.
- `checkouts`: one row per checkout attempt, `UNIQUE(user_id, idempotency_key)`, `request_hash` (address + payment method), server total.
- The app role may only change `carts.status`, `cart_items.quantity` (column grants); `checkouts` is insert-only.

## Rules

| Req | Control |
|---|---|
| BR-018, CART-001 | One ACTIVE cart per user, enforced by the partial unique index. A race on the first add is resolved by a savepoint + re-read under `FOR UPDATE` (test: 5 concurrent first-adds → 1 cart, quantity 5) |
| CART-002 | Adding the same product again increments the existing row; the DB unique constraint is the backstop |
| CART-003, CART-001 (v1.12), BR-014 | Checkout locks the cart, then each product row (`FOR UPDATE`, ascending id — no deadlocks), re-checks visibility (BR-011) and recomputes every line from `products.price`. The client may send `expected_total` only as a confirmation; if it differs the request stops with `409 price_changed` and returns the new cart total. Request bodies are strict: `price`/`total` fields are rejected |
| ORD-LC-005, ORD-LC-008 | Reservation happens inside the checkout transaction through `catalog/stock.reserve` (row lock, `0 ≤ reserved ≤ stock` DB invariant). Six concurrent checkouts of the last unit → exactly one order |
| ORD-006 | Orders, items, reservations, history, audit and the cart status are written in one transaction; any `StockError` rolls everything back (the cart is left intact so the buyer can fix it) |
| ORD-001 (v1.12) | `Idempotency-Key` header (8–80 chars) is mandatory. A retry with the same key and same body returns the original result (`200`, `replayed: true`); same key with a different body → `409 idempotency_conflict`. The web form embeds a fresh key per page view, so a double click cannot create two orders |
| Multi-shop carts | One order per shop (`BM{yymm}-{seq}`), so each seller only ever sees its own order (ORD-005) |
| COD | Disabled until M14 (`422 cod_unavailable`); only ONLINE is accepted |

## UX

- Product page: quantity + "Weka kwenye kikapu" (POST form with CSRF, no JavaScript). Guests see "Ingia ili kununua".
- `/kikapu`: grouped by shop, quantity update/remove, delivery address, payment method, total from the server.
- Header shows `Kikapu (n)`.

Design Ready: YES — Claude (developer), 2026-10-12 UTC
