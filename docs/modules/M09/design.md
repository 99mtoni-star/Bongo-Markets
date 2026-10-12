# M09 — Bongo Markets Sokoni, Search na Filtering: Design

| Req | Control |
|---|---|
| MKT-001 | `/soko` and `GET /api/v1/marketplace/products`: ACTIVE + marketplace products of ACTIVE shops, across all shops |
| MKT-002 | Search over product name, description and shop name (case-insensitive, wildcards escaped); filters for category, price range and shop |
| MKT-001 (v1.12.2) | Location discovery: `region` filter on the shop's area (e.g. "Arusha", "Kariakoo"). Street-level discovery waits on approved location data (see below) |
| MKT-003 | Keyset (cursor) batches of 24 (maximum 48) until exhausted. Stable when products are added while paging; sorts: newest, price ascending/descending |
| MKT-004/005 | Shop page and `?shop=` filter scoped to one shop; category headings derived from that shop's active products (M07/M08 hook) |
| MKT-006 | `featured` only adds a product to the "Bidhaa maalum" section. Set by moderators (`platform.content.moderate`), audited; sellers cannot self-feature |
| V13-REQ-004 | **Deferred**: dedicated search index (OpenSearch/Meilisearch) for multi-million catalogues. `app/market/service.py` is the seam to replace; trigram GIN indexes and keyset indexes serve the current scale |

Indexes (migration 0007): `pg_trgm` GIN on `lower(products.name)` and `lower(shops.name)`; partial keyset indexes for newest and price.

## Deferred or gated capabilities (recorded, not built)

| ID | Status | Note |
|---|---|---|
| CAP-B2C-001 | Deferred | B2C/B2B operating model not yet decided |
| CAP-MOQ-001 | Deferred | Minimum order quantity and bulk pricing depend on CAP-B2C-001 |
| CAP-RFQ-001 | Deferred | "Natafuta Bidhaa" (request for quote) |
| CAP-BRD-001 | Design now, implement later | Broadcast offers need opt-in, rate limits and SMS cost controls (reuse ID-011 limits). Contract required before coding |
| CAP-SPON-001 | Deferred | Sponsored listings need commercial validation. `featured` is editorial, not paid |
| CAP-UX-001 | Deferred | B2C/B2B UI split waits for the operating model |
| MKT-001 (location streets) | Partial | Region/area filter now. Street-level Kariakoo discovery needs an approved list of streets and areas |

Design Ready: YES — Claude (developer), 2026-10-12 UTC
