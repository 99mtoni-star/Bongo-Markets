"""Central configuration (M01).

All configuration comes from environment variables (prefix ``KAR_``) or a local
``.env`` file. Secrets are never hard-coded (NFR-005). Production refuses to
start with unsafe settings.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_SECRETS = {"", "change-me", "changeme", "secret", "dev", "development", "password"}
MIN_SECRET_LENGTH = 32


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="KAR_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Kariakoo"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    version: str = "0.1.0"

    # Secrets
    secret_key: SecretStr = Field(default=SecretStr("change-me"))

    # Database (MariaDB in staging/production; SQLite allowed only for dev/test)
    database_url: SecretStr = Field(default=SecretStr("sqlite:///./kariakoo-dev.db"))

    # HTTP
    allowed_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1", "testserver"])
    cors_origins: list[str] = Field(default_factory=list)

    # Logging
    log_level: str = "INFO"
    log_json: bool = True

    @property
    def is_production_like(self) -> bool:
        return self.environment in (Environment.STAGING, Environment.PRODUCTION)

    @model_validator(mode="after")
    def _enforce_safe_production(self) -> Settings:
        if not self.is_production_like:
            return self
        problems: list[str] = []
        secret = self.secret_key.get_secret_value()
        if secret.lower() in INSECURE_SECRETS or len(secret) < MIN_SECRET_LENGTH:
            problems.append(f"KAR_SECRET_KEY must be a random value of at least {MIN_SECRET_LENGTH} characters")
        if self.debug:
            problems.append("KAR_DEBUG must be false")
        db = self.database_url.get_secret_value()
        if not db.startswith(("mysql+pymysql://", "mariadb+pymysql://", "mariadb+mariadbconnector://")):
            problems.append("KAR_DATABASE_URL must point to MariaDB")
        if "*" in self.allowed_hosts:
            problems.append("KAR_ALLOWED_HOSTS must not contain '*'")
        if problems:
            raise ValueError("Unsafe configuration for {}: {}".format(self.environment.value, "; ".join(problems)))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
