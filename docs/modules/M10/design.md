# M10 — Shop Page na Shop Admin: Design

| Req | Control |
|---|---|
| SHOP-005 | `/maduka` and `GET /api/v1/shops/mine` list only shops with an active `shop_users` row for the caller. `/maduka/{slug}` and `GET /api/v1/shops/{slug}/dashboard` return a generic 404 to non-members. The dashboard shows only sections the caller's shop permissions allow (counts, low stock, team; order counts are added by M12). Every operation is checked per request by the Authorizer (role matrix test M10-T003) |

The customer-facing shop page (`/duka/{slug}`) was delivered in M07/M08/M09 and is reused here.

Design Ready: YES — Claude (developer), 2026-10-12 UTC
