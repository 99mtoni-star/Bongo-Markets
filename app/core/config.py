"""Central configuration (M01).

All configuration comes from environment variables (prefix ``BM_``) or a local
``.env`` file. Secrets are never hard-coded (NFR-005). Production refuses to
start with unsafe settings.
"""

from __future__ import annotations

import os
from enum import StrEnum
from functools import lru_cache

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_SECRETS = {"", "change-me", "changeme", "secret", "dev", "development", "password"}
MIN_SECRET_LENGTH = 32
POSTGRES_SCHEMES = ("postgresql://", "postgresql+psycopg://")


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # Production secrets are mounted as files by the secret manager (SEC-KEY-002),
        # e.g. /run/secrets/bm_database_url. Each file name is the lower-case field name.
        secrets_dir=os.environ.get("BM_SECRETS_DIR") or None,
    )

    app_name: str = "Bongo Markets"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    version: str = "0.1.0"

    # Secrets
    secret_key: SecretStr = Field(default=SecretStr("change-me"))

    # Database: PostgreSQL in every environment. The app connects as the least-privilege
    # application role (SEC-005); migrations use a separate owner connection.
    database_url: SecretStr = Field(
        default=SecretStr("postgresql+psycopg://bm_app:bm_app_dev_pw@127.0.0.1:5432/bongomarkets")
    )
    db_pool_size: int = 10
    db_statement_timeout_ms: int = 15000

    # HTTP
    allowed_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1", "testserver"])
    cors_origins: list[str] = Field(default_factory=list)

    # Logging
    log_level: str = "INFO"
    log_json: bool = True

    # Authentication (M03). Cookies are always HttpOnly; Secure is mandatory outside dev/test.
    cookie_secure: bool = True
    session_ttl_hours: int = 24 * 7          # absolute lifetime
    session_idle_hours: int = 48             # idle timeout
    login_max_failures: int = 5              # AUTH-007
    lockout_minutes: int = 15
    otp_ttl_minutes: int = 10
    reset_ttl_minutes: int = 15
    otp_max_attempts: int = 5
    default_phone_region: str = "TZ"         # mobile-number-first identity (ID-002)
    dormant_account_days: int = 180          # ID-009: SMS-only reset refused after long inactivity
    closed_account_retention_days: int = 365  # SEC-COM-004
    media_dir: str = "./media"                # product images (object storage + CDN in M20)
    notifier: str = "dev"                    # "dev" keeps SMS/email in memory; production needs a provider

    @property
    def is_production_like(self) -> bool:
        return self.environment in (Environment.STAGING, Environment.PRODUCTION)

    @model_validator(mode="after")
    def _enforce_safe_production(self) -> Settings:
        db = self.database_url.get_secret_value()
        if not db.startswith(POSTGRES_SCHEMES):
            raise ValueError("BM_DATABASE_URL must point to PostgreSQL")
        if "*" in self.cors_origins:
            raise ValueError("BM_CORS_ORIGINS must list approved origins; '*' is not allowed (SEC-WEB-003)")
        if not self.is_production_like:
            return self
        problems: list[str] = []
        secret = self.secret_key.get_secret_value()
        if secret.lower() in INSECURE_SECRETS or len(secret) < MIN_SECRET_LENGTH:
            problems.append(f"BM_SECRET_KEY must be a random value of at least {MIN_SECRET_LENGTH} characters")
        if self.debug:
            problems.append("BM_DEBUG must be false")
        if "*" in self.allowed_hosts:
            problems.append("BM_ALLOWED_HOSTS must not contain '*'")
        if not self.cookie_secure:
            problems.append("BM_COOKIE_SECURE must be true")
        if self.notifier == "dev":
            problems.append("BM_NOTIFIER must name a real SMS/email provider, not 'dev'")
        if problems:
            raise ValueError("Unsafe configuration for {}: {}".format(self.environment.value, "; ".join(problems)))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
