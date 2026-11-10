"""Runtime configuration.

All settings are read from environment variables prefixed with ``CONTEXTOS_`` (or a ``.env`` file).
Production refuses to start with insecure defaults — see ``Settings.validate_for_production``.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_DEV_SECRET = "contextos-dev-insecure-secret-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CONTEXTOS_", env_file=".env", extra="ignore")

    env: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./data/contextos.db"

    # Server-side secret. Used for: HMAC secret fingerprints, context-receipt signatures and the
    # keyed audit hash chain. Rotating it invalidates existing fingerprints/receipts/chain anchors.
    secret_key: str = INSECURE_DEV_SECRET

    session_ttl_hours: int = 12
    session_cookie_name: str = "contextos_session"
    cookie_secure: bool = False
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"])

    log_level: str = "INFO"
    log_json: bool = False

    # Content inspection. Raw context content is NEVER persisted; only a redacted, truncated preview
    # and a SHA-256 content hash are stored.
    preview_chars: int = 600
    max_event_bytes: int = 512_000
    max_content_chars: int = 200_000

    retention_days: int = 90
    approval_default_timeout_s: int = 600

    # Repository root used by the Engineering Workspace context-pack builder to verify file references.
    workspace_root: str | None = None

    # Serve the built frontend (frontend/dist) from the API process when present.
    serve_frontend: bool = True
    frontend_dist: str | None = None

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    def validate_for_production(self) -> None:
        if self.env != "production":
            return
        problems: list[str] = []
        if self.secret_key == INSECURE_DEV_SECRET or len(self.secret_key) < 32:
            problems.append("CONTEXTOS_SECRET_KEY must be set to a random value of at least 32 characters")
        if not self.cookie_secure:
            problems.append("CONTEXTOS_COOKIE_SECURE must be true in production")
        if problems:
            raise RuntimeError("Refusing to start in production: " + "; ".join(problems))


@lru_cache
def get_settings() -> Settings:
    return Settings()
