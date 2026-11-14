"""Resources touched by a tool call, and the outbound destination it names (pure).

``extract_resources`` walks the (already redacted) argument object by key name — never by
guessing at free text — and returns ``[{"kind", "id", "sensitive", "reason"}]`` where ``kind`` is
one of ``file | glob | pattern | url | host | email | channel | command | table | agent``.
Identifiers are paths, hosts and sanitised URLs; secret-looking values are masked (see
``sanitize``). Path sensitivity always comes from ``app.engines.redaction.is_sensitive_path``.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

from app.domain.enums import ToolCategory
from app.engines.redaction import is_sensitive_path
from app.engines.risk import sanitize as san
from app.engines.risk.shell import ShellAnalysis, analyze_code, analyze_command

MAX_RESOURCES = 100
# Sensitive resources are kept beyond the cap so padding a call with benign paths cannot hide one.
MAX_SENSITIVE_EXTRA = 50
MAX_LIST_ITEMS = 2000
MAX_DEPTH = 4

FILE_KEYS = {
    "file_path",
    "path",
    "notebook_path",
    "filename",
    "file",
    "filepath",
    "file_name",
    "source_path",
    "target_path",
    "directory",
    "dir",
    "folder",
    "local_path",
}
LIST_FILE_KEYS = {"paths", "files", "file_paths", "attachments", "attachment", "filenames"}
MOVE_KEYS = {"source", "destination", "target", "src", "dest"}
URL_KEYS = {
    "url",
    "uri",
    "endpoint",
    "href",
    "link",
    "webhook",
    "webhook_url",
    "base_url",
    "target_url",
    "page_url",
    "image_url",
    "callback_url",
    "redirect_uri",
    "download_url",
    "upload_url",
    "repo_url",
    "remote_url",
    "website",
    "urls",
}
HOST_KEYS = {"host", "hostname", "domain", "ip", "ip_address", "server_address"}
RECIPIENT_KEYS = {
    "to",
    "cc",
    "bcc",
    "recipient",
    "recipients",
    "to_email",
    "to_address",
    "reply_to",
    "emails",
}
CHANNEL_KEYS = {"channel", "channel_id", "channel_name", "chat_id", "conversation_id", "room", "room_id"}
COMMAND_KEYS = {"command", "cmd", "script", "shell_command", "command_line", "commandline"}
CODE_KEYS = {"code", "source_code", "snippet", "program"}
SQL_KEYS = {"query", "sql", "statement", "sql_query"}
PATTERN_KEYS = {"pattern", "glob", "include", "regex", "search_pattern", "file_pattern"}
AGENT_KEYS = {"subagent_type", "agent", "agent_name", "agent_id"}
# Free-form payloads: their contents are data being sent/written, not resources being accessed.
TEXT_KEYS = {
    "content",
    "new_string",
    "old_string",
    "new_source",
    "prompt",
    "description",
    "body",
    "text",
    "message",
    "html",
    "subject",
    "todos",
    "messages",
    "data",
    "json",
    "payload",
    "form",
    "headers",
    "params",
    "allowed_domains",
    "blocked_domains",
    "plan",
    "instructions",
}

_FILE_CATEGORIES = {ToolCategory.FILE_READ, ToolCategory.FILE_WRITE}
_COMMAND_CATEGORIES = {
    ToolCategory.SHELL,
    ToolCategory.INFRASTRUCTURE,
    ToolCategory.CODE_EXECUTION,
    ToolCategory.MCP,
    ToolCategory.OTHER,
}
_HTTPISH = {ToolCategory.HTTP, ToolCategory.BROWSER}
_SQL_TABLE = re.compile(r"\b(?:from|join|into|update|table)\s+([`\"\[]?[\w.$]+[`\"\]]?)", re.IGNORECASE)
_SQL_KEYWORDS = {"select", "where", "set", "values", "lateral", "unnest", "exists", "only"}
_SENSITIVE_TABLE = re.compile(
    r"(passw|credential|secret|token|api_?key|session|auth|payment|card|ssn|salary|private|oauth)",
    re.IGNORECASE,
)
_CREDENTIAL_PATTERN = re.compile(
    r"(passw|secret|token|api[_\-\s]?key|private[_\-\s]?key|BEGIN [A-Z ]*PRIVATE|aws_access|credential|bearer)",
    re.IGNORECASE,
)
_ROLE_NOTES = {
    "upload": "sent over the network",
    "key": "used as a private key or certificate",
    "write": "written",
    "read": None,
    "arg": None,
}
_OBJECT_STORAGE_SCHEMES = {"s3", "gs", "az", "abfs", "abfss", "wasb", "wasbs", "r2"}


def path_sensitivity(path: str) -> tuple[bool, str | None]:
    """Sensitivity of a path or glob, via the redaction engine's ``is_sensitive_path``."""
    variants = [path]
    if any(c in path for c in "*?["):
        variants += [path.replace("**/", "").replace("*", "").replace("?", ""), re.sub(r"[*?]", "x", path)]
    for variant in variants:
        if not variant:
            continue
        sensitive, reason = is_sensitive_path(variant)
        if sensitive:
            return True, reason
    return False, None


class _Collector:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}

    def add(
        self, kind: str, ident: str | None, *, sensitive: bool = False, reason: str | None = None
    ) -> None:
        if not ident:
            return
        ident = san.truncate(ident)
        existing = self.items.get((kind, ident))
        if existing is not None:
            if sensitive and not existing["sensitive"]:
                existing["sensitive"], existing["reason"] = True, reason
            elif reason and not existing["reason"]:
                existing["reason"] = reason
            return
        limit = MAX_RESOURCES + (MAX_SENSITIVE_EXTRA if sensitive else 0)
        if len(self.items) < limit:
            self.items[(kind, ident)] = {"kind": kind, "id": ident, "sensitive": sensitive, "reason": reason}

    def file(self, raw: str, role: str | None = None) -> None:
        if not isinstance(raw, str) or not raw.strip() or san.REDACTION_MARKER in raw:
            return
        raw = raw.strip()
        if "://" in raw:
            self.url(raw)
            return
        path = san.mask_path_segments(raw, min_length=24, min_entropy=4.0)
        if not path.replace(san.MASK, "").strip("/"):
            return
        sensitive, reason = path_sensitivity(raw)
        if re.match(r"^/proc/(?:\d+|self|\*)/environ$", raw):
            sensitive, reason = True, reason or "process environment (often holds credentials)"
        note = _ROLE_NOTES.get(role or "", None)
        if role == "key":
            sensitive = True
            reason = reason or note
        elif note:
            reason = f"{reason}; {note}" if reason else note
        self.add("file", path, sensitive=sensitive, reason=reason)

    def glob(self, pattern: str) -> None:
        sensitive, reason = path_sensitivity(pattern)
        self.add("glob", _mask_token(pattern), sensitive=sensitive, reason=reason)

    def pattern(self, pattern: str) -> None:
        cred = _CREDENTIAL_PATTERN.search(pattern)
        self.add(
            "pattern",
            _mask_token(pattern),
            sensitive=bool(cred),
            reason="search pattern targets credential material" if cred else None,
        )

    def url(self, raw: str) -> None:
        url = san.sanitize_url(raw)
        if not url:
            return
        scheme = url.split("://", 1)[0]
        host = san.url_host(url)
        sensitive, reason = False, None
        if scheme == "file":
            sensitive, reason = path_sensitivity(san.url_path(url))
        elif host and san.is_metadata_host(host):
            sensitive, reason = True, "cloud instance-metadata endpoint (serves credentials)"
        self.add("url", url, sensitive=sensitive, reason=reason)
        if host and scheme not in {"file", *_OBJECT_STORAGE_SCHEMES}:
            self.host(host)

    def host(self, raw: str, *, single_label: bool = False) -> None:
        host = san.normalize_host(raw, allow_single_label=single_label)
        if host:
            metadata = san.is_metadata_host(host)
            self.add(
                "host",
                host,
                sensitive=metadata,
                reason="cloud instance-metadata endpoint (serves credentials)" if metadata else None,
            )

    def emails(self, raw: Any) -> None:
        values = raw if isinstance(raw, list) else [raw]
        for value in values:
            if isinstance(value, dict):
                value = value.get("email") or value.get("address") or ""
            if isinstance(value, str):
                for part in re.split(r"[,;\s]+", value):
                    email = san.normalize_email(part)
                    if email:
                        self.add("email", email)

    def shell(self, analysis: ShellAnalysis) -> None:
        for prog in analysis.programs:
            self.add("command", prog)
        for prog, reason in zip(analysis.network_programs, analysis.outbound_reasons, strict=False):
            self.add("command", prog.split(" ")[0], reason=reason)
        for dump in analysis.env_dumps:
            if dump.startswith("/proc/"):
                self.file(dump, "read")
            else:
                self.add(
                    "command",
                    dump,
                    sensitive=True,
                    reason="dumps environment variables, which often hold credentials",
                )
        for item in analysis.files:
            self.file(item.path, item.role)
        for word in analysis.bare_words:
            sensitive, _ = path_sensitivity(word)
            if sensitive:
                self.file(word, "read")
        for url in analysis.urls:
            self.url(url)
        for host in analysis.hosts:
            self.host(host, single_label=True)
        for email in analysis.emails:
            self.add("email", email)

    def result(self) -> list[dict[str, Any]]:
        return list(self.items.values())


def _mask_token(value: str) -> str:
    value = san.truncate(value, 300)
    return san.MASK if san.looks_secret(value) else value


def _looks_glob(pattern: str) -> bool:
    return any(c in pattern for c in "*?{") and not any(c in pattern for c in "|\\^$()+")


def _tables(sql: str, out: _Collector) -> None:
    for match in _SQL_TABLE.finditer(sql):
        name = match.group(1).strip('`"[]')
        if not name or name.lower() in _SQL_KEYWORDS or san.REDACTION_MARKER in name:
            continue
        sensitive = bool(_SENSITIVE_TABLE.search(name))
        out.add(
            "table",
            name,
            sensitive=sensitive,
            reason="table name suggests credentials or personal data" if sensitive else None,
        )


def command_text(arguments: dict[str, Any], *, include_script: bool = True) -> str | None:
    """The shell command line in a tool's arguments (``command`` plus an ``args`` list if given)."""
    keys = ["command", "cmd", "shell_command", "command_line", "commandline"]
    for key in keys + (["script"] if include_script else []):
        value = arguments.get(key)
        if isinstance(value, list) and all(isinstance(v, str) for v in value):
            value = shlex.join(value)
        if isinstance(value, str) and value.strip():
            extra = arguments.get("args") or arguments.get("argv")
            if isinstance(extra, list) and all(isinstance(v, str) for v in extra):
                value = f"{value} {shlex.join(extra)}"
            return value
    return None


def _walk(category: str, obj: dict[str, Any], out: _Collector, depth: int) -> None:
    if depth > MAX_DEPTH:
        return
    if category in _COMMAND_CATEGORIES:
        cmd = command_text(obj, include_script=category != ToolCategory.CODE_EXECUTION)
        if cmd:
            out.shell(analyze_command(cmd))
    for raw_key, value in obj.items():
        key = str(raw_key).lower()
        if key in TEXT_KEYS:
            continue
        if isinstance(value, str):
            _string_value(category, key, value, obj, out)
        elif isinstance(value, list):
            if key in LIST_FILE_KEYS or (key in FILE_KEYS and category not in _HTTPISH):
                for v in value[:MAX_LIST_ITEMS]:
                    if isinstance(v, str):
                        out.file(v, "upload" if key.startswith("attachment") else None)
                    elif isinstance(v, dict):
                        _walk(category, v, out, depth + 1)
            elif key in URL_KEYS:
                for v in value[:MAX_LIST_ITEMS]:
                    if isinstance(v, str):
                        out.url(v)
            elif key in RECIPIENT_KEYS:
                out.emails(value[:MAX_LIST_ITEMS])
            else:
                for v in value[:MAX_LIST_ITEMS]:
                    if isinstance(v, dict):
                        _walk(category, v, out, depth + 1)
        elif isinstance(value, dict):
            if key in RECIPIENT_KEYS:
                out.emails([value])
            else:
                _walk(category, value, out, depth + 1)


def _string_value(category: str, key: str, value: str, obj: dict[str, Any], out: _Collector) -> None:
    value = value.strip()
    if not value:
        return
    if key in CODE_KEYS or (key == "script" and category == ToolCategory.CODE_EXECUTION):
        language = obj.get("language") if isinstance(obj.get("language"), str) else "code"
        out.shell(analyze_code(value, language))
    elif key in COMMAND_KEYS:
        return  # handled once per object by command_text()
    elif key in FILE_KEYS and not (category in _HTTPISH and key == "path"):
        out.file(value, "upload" if key.startswith("attachment") else None)
    elif key in MOVE_KEYS and category in _FILE_CATEGORIES:
        out.file(value)
    elif key in URL_KEYS:
        if "://" in value:
            out.url(value)
        else:
            out.host(value)
    elif key in HOST_KEYS:
        out.host(value, single_label=True)
    elif key in RECIPIENT_KEYS:
        out.emails(value)
    elif key in CHANNEL_KEYS and category == ToolCategory.MESSAGING:
        out.add("channel", _mask_token(value))
    elif key in SQL_KEYS and category == ToolCategory.DATABASE:
        _tables(value, out)
    elif key in PATTERN_KEYS and category != ToolCategory.DATABASE:
        if key in {"glob", "include", "file_pattern"} or _looks_glob(value):
            out.glob(value)
        else:
            out.pattern(value)
    elif key in AGENT_KEYS and category == ToolCategory.AGENT_DELEGATION:
        out.add("agent", _mask_token(value))
    elif re.match(r"^https?://\S+$", value):
        out.url(value)


# Files named in an apply_patch-style patch ("*** Update File: <path>", Codex's patch grammar).
_PATCH_FILE = re.compile(
    r"^[ \t]*\*\*\*[ \t]*(?:Add File|Delete File|Update File|Move to):[ \t]*(\S.*?)[ \t]*$", re.MULTILINE
)
_PATCH_START = "*** Begin Patch"


def _patch_files(category: str, arguments: dict[str, Any], out: _Collector) -> None:
    if category != ToolCategory.FILE_WRITE:
        return
    for key in ("command", "patch", "input"):
        value = arguments.get(key)
        if isinstance(value, str) and _PATCH_START in value:
            for match in _PATCH_FILE.finditer(value):
                out.file(match.group(1))
            return


def extract_resources(category: str, arguments: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(arguments, dict) or not arguments:
        return []
    out = _Collector()
    _patch_files(category, arguments, out)
    _walk(category, arguments, out, 0)
    return out.result()


def _host_destination(host: str) -> dict[str, str]:
    if san.is_ip(host):
        return {"kind": "ip", "identifier": host}
    return {"kind": "domain" if san.looks_like_domain(host) else "unknown", "identifier": host}


_DESTINATION_CATEGORIES = {
    ToolCategory.HTTP,
    ToolCategory.BROWSER,
    ToolCategory.EMAIL,
    ToolCategory.MESSAGING,
    ToolCategory.CODE_EXECUTION,
    ToolCategory.INFRASTRUCTURE,
    ToolCategory.MCP,
}


def extract_destination(
    category: str, arguments: dict[str, Any], resources: list[dict[str, Any]]
) -> dict[str, str] | None:
    """First outbound target of the call, or None when nothing leaves the environment."""
    args = arguments if isinstance(arguments, dict) else {}
    if category == ToolCategory.SHELL:
        cmd = command_text(args)
        analysis = analyze_command(cmd) if cmd else None
        if analysis is None or not analysis.outbound:
            return None
        if analysis.remote_targets:
            return _host_destination(analysis.remote_targets[0])
        if analysis.emails:
            return {"kind": "email", "identifier": analysis.emails[0]}
        if analysis.services:
            kind, ident = analysis.services[0]
            return {"kind": kind, "identifier": ident}
        return None  # outbound-capable, but the target is not statically known
    if category not in _DESTINATION_CATEGORIES:
        return None
    if category == ToolCategory.EMAIL:
        for res in resources:
            if res.get("kind") == "email":
                return {"kind": "email", "identifier": res["id"]}
    for res in resources:
        res_kind, ident = res.get("kind"), res.get("id") or ""
        if res_kind == "url":
            scheme = ident.split("://", 1)[0]
            if scheme in _OBJECT_STORAGE_SCHEMES:
                return {"kind": "service", "identifier": "/".join(ident.split("/")[:3])}
            host = san.url_host(ident)
            if scheme != "file" and host and not san.is_loopback(host):
                return _host_destination(host)
        elif res_kind == "host" and not san.is_loopback(ident):
            return _host_destination(ident)
        elif res_kind == "email":
            return {"kind": "email", "identifier": ident}
    if category == ToolCategory.MESSAGING:
        for res in resources:
            if res.get("kind") == "channel":
                return {"kind": "service", "identifier": f"channel:{res['id']}"}
    return None
