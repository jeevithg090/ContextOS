"""What a Codex tool returned, reduced to the text the model reads.

``PostToolUse.tool_response`` shapes (Codex ``core/src/tools/context.rs`` and handlers at
``rust-v0.158.0-alpha.2.1``):

- ``Bash`` (``exec_command``; also the final ``write_stdin`` poll of a long-running command): a
  string, the command output exactly as Codex hands it to the model (already token-truncated).
- ``apply_patch``: a string (Codex's summary of the applied patch).
- ``mcp__<server>__<tool>``: the MCP ``CallToolResult`` as JSON — ``{"content": [{"type": "text",
  "text": ...}, ...], "structuredContent": ..., "isError": ...}``.
- other function tools: the function-call output body Codex sends to the model, a string or a list
  of content items (``{"type": "input_text", "text": ...}``, ``{"type": "input_image", ...}``).

Known shapes become their text (images become a marker); anything else is sent as JSON with long
base64 payloads replaced by a size marker; the result is cut at ``max_chars`` with a visible
marker. Secrets are NOT masked here: the server redacts before storing and needs the raw value
once to fingerprint it (that is how it later recognises the same credential in an outbound call).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from contextos._args import to_jsonable, truncate_result
from contextos.integrations.claude_code.results import bounded_arguments

_BINARY_KEYS = frozenset({"base64", "data", "image", "image_url", "bytes_base64", "blob"})
_MEDIA_TYPES = frozenset({"image", "audio", "resource_link", "input_image", "input_audio"})


def _texts_of_blocks(blocks: Any) -> str | None:
    """Join MCP content blocks or Codex content items into the text the model reads."""
    if not isinstance(blocks, list):
        return None
    parts: list[str] = []
    for block in blocks:
        if isinstance(block, Mapping):
            if isinstance(block.get("text"), str):
                parts.append(block["text"])
            elif block.get("type") in _MEDIA_TYPES:
                parts.append(f"[{block.get('type')} content omitted]")
            elif block.get("type") == "resource" and isinstance(block.get("resource"), Mapping):
                text = block["resource"].get("text")
                if isinstance(text, str):
                    parts.append(text)
        elif isinstance(block, str):
            parts.append(block)
    return "\n".join(parts) if parts else None


def _strip_binary(value: Any, depth: int = 0) -> Any:
    if depth > 10:
        return "[nested too deeply]"
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if str(key) in _BINARY_KEYS and isinstance(item, str) and len(item) > 256:
                out[str(key)] = f"[binary content omitted: {len(item)} characters]"
            else:
                out[str(key)] = _strip_binary(item, depth + 1)
        return out
    if isinstance(value, list):
        return [_strip_binary(item, depth + 1) for item in value]
    return value


def _text_of(tool_name: str, response: Any) -> str | None:
    if isinstance(response, str):
        return response
    if isinstance(response, list):
        return _texts_of_blocks(response)
    if isinstance(response, Mapping):
        text = _texts_of_blocks(response.get("content"))
        if text is not None:
            return text
        if tool_name.startswith("mcp__") and response.get("structuredContent") is not None:
            return None  # structured-only MCP result: sent as JSON below
    return None


def extract_result(tool_name: str, response: Any, max_chars: int) -> str | dict[str, Any] | list[Any] | None:
    """JSON-safe, size-bounded tool result for a ``tool.completed`` event."""
    if response is None:
        return None
    text = _text_of(tool_name, response)
    if text is not None:
        return truncate_result(text, max_chars)
    return truncate_result(_strip_binary(to_jsonable(response)), max_chars)


__all__ = ["bounded_arguments", "extract_result"]
