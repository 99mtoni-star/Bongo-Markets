"""Import every model module so Base.metadata is complete (Alembic, drift tests)."""

from app.auth import models as auth_models  # noqa: F401
from app.db import models as core_models  # noqa: F401
