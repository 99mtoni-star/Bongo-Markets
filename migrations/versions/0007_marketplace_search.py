"""M09 marketplace search: trigram indexes for product/shop search

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-12

Sensitive-Review: not-applicable (indexes and a search extension only; no personal or financial data).
"""

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # pg_trgm is a trusted extension; installed into the bm schema so search_path stays minimal.
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA bm")
    op.execute("CREATE INDEX ix_products_name_trgm ON bm.products USING gin (lower(name) bm.gin_trgm_ops)")
    op.execute("CREATE INDEX ix_shops_name_trgm ON bm.shops USING gin (lower(name) bm.gin_trgm_ops)")
    # Keyset pagination indexes for the marketplace listing (MKT-003).
    op.execute("CREATE INDEX ix_products_market_newest ON bm.products (created_at DESC, id DESC) "
               "WHERE status = 'ACTIVE' AND marketplace")
    op.execute("CREATE INDEX ix_products_market_price ON bm.products (price, id) "
               "WHERE status = 'ACTIVE' AND marketplace")


def downgrade() -> None:
    for ix in ("ix_products_market_price", "ix_products_market_newest", "ix_shops_name_trgm",
               "ix_products_name_trgm"):
        op.execute(f"DROP INDEX IF EXISTS bm.{ix}")
    op.execute("DROP EXTENSION IF EXISTS pg_trgm")
