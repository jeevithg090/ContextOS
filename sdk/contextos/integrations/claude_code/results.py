"""What a Claude Code tool returned, reduced to the text the model actually reads.

``PostToolUse`` delivers ``tool_response`` in a per-tool shape (for example ``Read`` nests the file
text under ``file.content``; ``Bash`` has ``stdout``/``stderr``). ContextOS runs trust
classification and prompt-injection detection on the result, so sending the readable text gives
the detectors the same content the model sees instead of JSON-escaped text.

Rules:
- Known shapes are reduced to their text (``Read``, ``Bash``, ``WebFetch``, ``Grep``, ``Glob``,
  ``Agent``/``Task``, MCP content blocks).
- File-writing tools return a confirmation, not new context: only small descriptive fields are
  kept (Edit's ``originalFile`` — the whole previous file — is dropped).
- A background ``Agent`` launch returns only its status and ``agentId`` (the task prompt it echoes
  was already reported as the delegation).
- Binary payloads (base64 images, PDFs) are replaced by a size marker.
- Everything else is sent as structured JSON.
- The result is cut at ``max_chars`` with a visible marker.

Secrets in results are NOT masked here: the server redacts them before storing anything, and it
needs the raw value once to fingerprint it (that is how it later recognises the same credential in
an outbound request).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from contextos._args import to_jsonable, truncate_result

WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit", "TodoWrite"})
SHELL_TOOLS = frozenset({"Bash", "PowerShell", "BashOutput"})
DELEGATION_TOOLS = frozenset({"Agent", "Task"})
_BINARY_KEYS = frozenset({"base64", "data", "image", "bytes_base64"})
_WRITE_KEEP = ("type", "filePath", "file_path", "notebook_path", "replaceAll", "userModified", "edit_mode")
_LAUNCH_KEEP = ("status", "isAsync", "agentId", "description", "resolvedModel")
_MAX_SMALL = 2_000


def _texts_of_blocks(blocks: Any) -> str | None:
    """Join ``[{"type": "text", "text": ...}]`` content blocks (MCP results, Agent results)."""
    if not isinstance(blocks, list):
        return None
    parts: list[str] = []
    for block in blocks:
        if isinstance(block, Mapping):
            if isinstance(block.get("text"), str):
                parts.append(block["text"])
            elif block.get("type") in ("image", "audio", "resource_link"):
                parts.append(f"[{block.get('type')} content omitted]")
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


def _shell_text(response: Mapping[str, Any]) -> str | None:
    stdout = response.get("stdout")
    stderr = response.get("stderr")
    if not isinstance(stdout, str) and not isinstance(stderr, str):
        return None
    parts = [stdout] if isinstance(stdout, str) and stdout else []
    if isinstance(stderr, str) and stderr.strip():
        parts.append(f"[stderr]\n{stderr}")
    if response.get("interrupted"):
        parts.append("[interrupted]")
    return "\n".join(parts)


def _text_of(tool_name: str, response: Any) -> str | None:
    if isinstance(response, str):
        return response
    if tool_name.startswith("mcp__"):
        if isinstance(response, list):
            return _texts_of_blocks(response)
        if isinstance(response, Mapping):
            return _texts_of_blocks(response.get("content"))
        return None
    if not isinstance(response, Mapping):
        return None
    if tool_name == "Read":
        file = response.get("file")
        if response.get("type") in (None, "text") and isinstance(file, Mapping) and isinstance(file.get("content"), str):
            return file["content"]
        return None
    if tool_name in SHELL_TOOLS:
        return _shell_text(response)
    if tool_name == "WebFetch" and isinstance(response.get("result"), str):
        return response["result"]
    if tool_name == "Grep":
        if isinstance(response.get("content"), str):
            return response["content"]
        names = response.get("filenames")
        return "\n".join(str(n) for n in names) if isinstance(names, list) else None
    if tool_name == "Glob":
        names = response.get("filenames")
        return "\n".join(str(n) for n in names) if isinstance(names, list) else None
    if tool_name in DELEGATION_TOOLS:
        return _texts_of_blocks(response.get("content")) or (
            response["result"] if isinstance(response.get("result"), str) else None)
    return None


def _write_summary(response: Any) -> dict[str, Any] | str | None:
    if not isinstance(response, Mapping):
        return None if response is None else str(response)[:_MAX_SMALL]
    kept = {k: response[k] for k in _WRITE_KEEP if k in response and isinstance(response[k], (str, bool, int))}
    return kept or {"keys": sorted(str(k) for k in response)[:20]}


def extract_result(tool_name: str, response: Any, max_chars: int) -> str | dict[str, Any] | list[Any] | None:
    """JSON-safe, size-bounded tool result for a ``tool.completed`` event."""
    if response is None:
        return None
    if tool_name in WRITE_TOOLS:
        return _write_summary(response)
    if tool_name in DELEGATION_TOOLS and isinstance(response, Mapping) and (
            response.get("isAsync") is True or response.get("status") == "async_launched"):
        # A background subagent was launched; its result arrives later as a <task-notification>.
        return {k: response[k] for k in _LAUNCH_KEEP if isinstance(response.get(k), (str, bool))}
    text = _text_of(tool_name, response)
    if text is not None:
        return truncate_result(text, max_chars)
    return truncate_result(_strip_binary(to_jsonable(response)), max_chars)


def bounded_arguments(arguments: Mapping[str, Any], max_string: int = 20_000, _depth: int = 0) -> dict[str, Any]:
    """Copy of tool arguments for an *observation* event with long strings cut (marker appended).

    Only used where the server merely records the call (``tool.completed``); decision requests
    always carry the full arguments so nothing can hide past a cut.
    """
    def cut(value: Any, depth: int) -> Any:
        if isinstance(value, str):
            return value if len(value) <= max_string else value[:max_string] + f"[TRUNCATED: {len(value) - max_string} more characters]"
        if depth > 10:
            return "[nested too deeply]"
        if isinstance(value, Mapping):
            return {str(k): cut(v, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [cut(v, depth + 1) for v in value[:500]]
        return value

    return {str(k): cut(v, _depth + 1) for k, v in to_jsonable(dict(arguments)).items()}


__all__ = ["DELEGATION_TOOLS", "SHELL_TOOLS", "WRITE_TOOLS", "bounded_arguments", "extract_result"]
