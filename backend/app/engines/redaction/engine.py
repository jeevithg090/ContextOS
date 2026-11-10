"""STUB — to be implemented by the redaction work package. Keep these signatures."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.domain.enums import Sensitivity


@dataclass(frozen=True)
class SecretMatch:
    secret_type: str  # e.g. "aws_access_key", "github_token", "private_key", "generic_password"
    start: int
    end: int
    fingerprint: str  # fingerprint_secret(raw_value)
    confidence: float  # 0..1


@dataclass
class RedactionResult:
    text: str
    matches: list[SecretMatch] = field(default_factory=list)

    @property
    def contains_secrets(self) -> bool:
        return bool(self.matches)


def detect_secrets(text: str) -> list[SecretMatch]:
    raise NotImplementedError


def redact_text(text: str) -> RedactionResult:
    raise NotImplementedError


def redact_value(value: Any) -> tuple[Any, list[SecretMatch]]:
    raise NotImplementedError


def fingerprint_secret(raw: str) -> str:
    raise NotImplementedError


def classify_sensitivity(text: str, matches: list[SecretMatch], identifier: str | None = None) -> Sensitivity:
    raise NotImplementedError


def is_sensitive_path(path: str) -> tuple[bool, str | None]:
    raise NotImplementedError
