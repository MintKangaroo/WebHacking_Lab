"""Validated application configuration."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from WEBHACKING_ environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="WEBHACKING_",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "WebHacking Lab"
    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"  # noqa: S104 - container bind address
    api_port: int = 8000
    database_url: str = "sqlite+aiosqlite:///./data/webhacking_lab.db"
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://localhost:8080"]
    )

    analysis_only: bool = True
    network_execution_enabled: bool = False
    allow_insecure_tls: bool = False
    global_requests_per_minute: int = Field(default=30, ge=1, le=120)
    default_target_concurrency: int = Field(default=2, ge=1, le=5)
    request_timeout_seconds: float = Field(default=10.0, gt=0, le=30)
    max_request_bytes: int = Field(default=1024 * 1024, ge=1024, le=5 * 1024 * 1024)
    max_response_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=10 * 1024 * 1024)
    max_har_bytes: int = Field(default=10 * 1024 * 1024, ge=1024, le=50 * 1024 * 1024)
    max_har_entries: int = Field(default=100, ge=1, le=500)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide immutable settings instance."""

    return Settings()
