"""Small, safe text helpers shared by the workspace generators.

Every piece of record-derived text that ends up in a generated prompt passes through
:func:`clean` (redaction + length cap). Free text written by users or captured from agent
sessions is rendered as quoted or fenced *data* so that it cannot masquerade as prompt structure.
"""

from __future__ import annotations

import math
import re
from typing import Any

from app.engines.redaction import redact_text

_BACKTICK_RUN = re.compile(r"`+")
_WS = re.compile(r"\s+")


def estimate_tokens(text: str | None) -> int:
    """Rough token estimate (~4 characters per token). Good enough for budgeting, not billing."""
    if not text:
        return 0
    return math.ceil(len(text) / 4)


def clean(value: Any, limit: int = 4000) -> str:
    """Redact secrets, strip, and cap ``value`` at ``limit`` characters (with an ellipsis marker)."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = redact_text(text).text.strip()
    if len(text) > limit:
        text = text[: max(0, limit - 1)].rstrip() + "…"
    return text


def inline(value: Any, limit: int = 300) -> str:
    """Single-line, redacted, capped text suitable for list items and table cells."""
    return _WS.sub(" ", clean(value, limit=limit * 2)).strip()[:limit]


def code(value: str) -> str:
    """Inline code span that survives backticks inside ``value``."""
    text = inline(value, limit=500)
    longest = max((len(m.group(0)) for m in _BACKTICK_RUN.finditer(text)), default=0)
    ticks = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{ticks}{pad}{text}{pad}{ticks}"


def fence(text: str, lang: str = "") -> str:
    """Fenced code block whose fence is longer than any backtick run inside ``text``."""
    longest = max((len(m.group(0)) for m in _BACKTICK_RUN.finditer(text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{lang}\n{text.rstrip()}\n{ticks}"


def quote(text: str) -> str:
    """Markdown blockquote; keeps user-written text visibly separate from prompt structure."""
    lines = text.splitlines() or [""]
    return "\n".join(f"> {line}" if line.strip() else ">" for line in lines)


def bullets(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items if item)


def numbered(items: list[str]) -> str:
    return "\n".join(f"{i}. {item}" for i, item in enumerate((x for x in items if x), start=1))


def truncate_lines(text: str, max_tokens: int) -> tuple[str, bool]:
    """Truncate ``text`` to roughly ``max_tokens`` at a line boundary. Returns ``(text, truncated)``."""
    budget_chars = max(0, max_tokens) * 4
    if len(text) <= budget_chars:
        return text, False
    lines = text.splitlines(keepends=True)
    kept: list[str] = []
    used = 0
    for line in lines:
        if used + len(line) > budget_chars:
            break
        kept.append(line)
        used += len(line)
    if not kept and lines:
        kept = [lines[0][:budget_chars]]
    remaining = len(lines) - len(kept)
    body = "".join(kept).rstrip("\n")
    marker = f"\n… [truncated: {remaining} more line{'s' if remaining != 1 else ''} not included]"
    return body + marker, True
