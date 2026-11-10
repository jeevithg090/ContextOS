"""Shared API schema primitives.

Conventions (all routes):
- Response models are Pydantic ``*Out`` classes with ``model_config = ORM`` so they can be built
  from SQLAlchemy rows via ``Model.model_validate(row)``.
- Lists return ``Page[T]``: ``{"items": [...], "total": int, "limit": int, "offset": int}``.
- Timestamps are ISO-8601 UTC. IDs are prefixed strings.
- Errors use the envelope in ``app.core.errors``.
"""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")

ORM = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class PageParams(BaseModel):
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class Message(BaseModel):
    message: str
