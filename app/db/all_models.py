"""Import every model module so Base.metadata is complete (Alembic, drift tests)."""

from app.auth import models as auth_models  # noqa: F401
from app.authz import models as authz_models  # noqa: F401
from app.catalog import models as catalog_models  # noqa: F401
from app.db import models as core_models  # noqa: F401
from app.orders import models as order_models  # noqa: F401
from app.shops import models as shop_models  # noqa: F401
