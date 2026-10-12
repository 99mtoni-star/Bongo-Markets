# M12 — Orders, Fulfilment na Delivery PIN: Design

## Data (migration 0008)

- `orders`: number, buyer, shop, status, payment_status, payment_method, subtotal = total (`CHECK`), delivery-address
  snapshot, courier, `delivery_pin_hash`, `pin_attempts`, cancel request, `refund_required`, timestamps.
- `order_items`: product snapshot (SKU, name, image key, unit, unit price, quantity, `line_total = unit_price × quantity` CHECK) + reservation link.
- `order_status_history`: append-only for the app role.
- Column grants: the app role cannot change totals, address, items or history.
- Trigger `bm.guard_new_order_payment`: new orders must be `UNPAID`.
- Trigger `bm.guard_payment_status`: `payment_status` changes only inside a transaction that set
  `SET LOCAL bm.payment_context = 'provider-verified'` (only `orders/payments.confirm_payment` does this, after the
  provider verification that M13 implements). This is a defence-in-depth guard against accidental code paths
  (seller UI, admin tools, bugs); it is not a boundary against a fully compromised application process.

## Lifecycle

```
PENDING_PAYMENT ──verified payment──▶ CONFIRMED ──▶ PROCESSING ──(courier)──▶ SHIPPED ──(buyer PIN)──▶ DELIVERED
      │                                   │              │
 buyer cancel / expiry               seller cancel (stock returned, refund_required)
      ▼                                   ▼
CANCELLED / EXPIRED                   CANCELLED
```

## Rules

| Req | Control |
|---|---|
| BR-014 | Totals are computed at checkout from DB prices and frozen; app role has no UPDATE grant on totals |
| ORD-001 | Orders are created only from the cart via checkout (M11) |
| ORD-002, ORD-002 (v1.12) | Delivery address copied into the order |
| ORD-003 | Item name/SKU/image/unit/price copied into `order_items`; later product edits do not change history |
| ORD-004 | Buyer endpoints filter by `buyer_user_id`; any other order → generic 404 |
| ORD-005 | Shop endpoints require `shop.orders.view` in that shop and match `order.shop_id`; non-members get 404 |
| ORD-006 | Each transition locks the order row, checks the state, writes history + audit, commits once |
| ORD-LC-001 | Buyer may cancel while `PENDING_PAYMENT` (reservations released). After confirmation the buyer can only *request* cancellation with a reason; the seller decides |
| ORD-LC-002 | `shop.orders.fulfil`: CONFIRMED→PROCESSING→SHIPPED only, no skipping |
| ORD-LC-004 | No customer endpoint sets a fulfilment or payment state; strict bodies reject `status` |
| ORD-LC-005/008 | Reservation inside checkout (M11); verified payment commits reservations (`stock -= q`, `reserved -= q`) |
| ORD-LC-006 | Expiry sweep `expire_unpaid` (cron, every minute via `scripts/expire_reservations.py`) releases stock of unpaid orders; seller cancellation of a paid order returns sold units to stock and sets `refund_required`. A payment arriving after expiry never takes stock: the order stays EXPIRED with `refund_required` |
| DEL-001 | Courier name + phone are required to ship; reassignment allowed while SHIPPED; both audited with before/after |
| DEL-002 (Design Ready decision) | **Delivery PIN** chosen for v1 (works on any phone, no camera, no data). QR confirmation is deferred until the courier app exists |
| V13-TRUST-002 | 6-digit PIN from `secrets`, sent by SMS to the buyer only when the order ships. Stored as `HMAC-SHA256(key, order_public_id ‖ pin)` → bound to that order, useless elsewhere. Single use (hash cleared on DELIVERED; replay → 409). 5 wrong attempts lock it (`423`); only the buyer can issue a new PIN. Failed attempts are audited |
| BR-017 | `can_review(user, order_item)` true only for the buyer's own item in a DELIVERED order (`/api/v1/order-items/{id}/review-eligibility`), used by M18 (reviews) |
| CAP-DEL-ADV-001 | **Deferred** (design now, implement later): core delivery works; courier matching, route consolidation and live tracking are out of scope until a logistics module is allocated |

## Payment boundary

M13 owns provider integration, signatures, webhooks, reconciliation and refunds. Until then `/dev/lipa/{number}`
simulates a verified provider event in development/test only (404 in staging/production, test M12-T012).

Design Ready: YES — Claude (developer), 2026-10-12 UTC
