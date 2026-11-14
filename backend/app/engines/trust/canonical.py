"""Canonical identifiers for context sources.

One real-world source should map to one identifier no matter how an integration spelled it:
``https://Docs.Example.com:443/a/./b/?utm_source=x#top`` and ``https://docs.example.com/a/b`` are
the same page. Credentials embedded in identifiers (URL user-info, token/signature query
parameters) are removed or replaced with ``REDACTED`` so a canonical identifier is safe to persist.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

from app.engines.trust.domains import HostInfo, canonical_host, registrable_domain, split_host_port

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}
WEB_SCHEMES = frozenset({"http", "https", "ws", "wss"})

_TRACKING_PARAMS = frozenset(
    {
        "fbclid",
        "gclid",
        "dclid",
        "gbraid",
        "wbraid",
        "msclkid",
        "yclid",
        "mc_cid",
        "mc_eid",
        "_ga",
        "_gl",
        "igshid",
    }
)
_CREDENTIAL_PARAMS = frozenset(
    {
        "token",
        "access_token",
        "id_token",
        "refresh_token",
        "auth",
        "authorization",
        "api_key",
        "apikey",
        "api-key",
        "key",
        "secret",
        "client_secret",
        "password",
        "passwd",
        "pwd",
        "sig",
        "signature",
        "code",
        "session",
        "sessionid",
        "session_id",
        "jwt",
        "private_token",
        "sas",
        "sv",
        "se",
        "sp",
    }
)
_CREDENTIAL_PREFIXES = ("x-amz-", "x-goog-")
REDACTED = "REDACTED"

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://")
_SCP_GIT_RE = re.compile(r"^[\w.\-]+@([\w.\-]+):(?!//)(.+)$")
_OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,38})/[A-Za-z0-9._\-]+$")
_EMAIL_RE = re.compile(r"^[^@\s<>()]+@[^@\s<>()]+$")
_ANGLE_EMAIL_RE = re.compile(r"<([^<>\s]+@[^<>\s]+)>")
_DRIVE_RE = re.compile(r"^([a-zA-Z]):(/|$)")
_CASE_INSENSITIVE_GIT_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})


@dataclass(frozen=True)
class Canonical:
    identifier: str
    host: HostInfo | None = None
    path: str = ""  # URL path (used for service detection only; may contain tokens, never persist)

    @property
    def domain(self) -> str | None:
        return registrable_domain(self.host.host) if self.host else None


def has_scheme(text: str) -> bool:
    return bool(_SCHEME_RE.match(text))


def strip_web_scheme(text: str) -> str:
    lowered = text.lower()
    for prefix in ("https://", "http://", "wss://", "ws://"):
        if lowered.startswith(prefix):
            return text[len(prefix) :]
    return text


def web_url_text(text: str) -> str:
    """Browsers treat ``\\`` as ``/`` in http(s) URLs. Do the same so that
    ``https://evil.com\\@good.com`` is read as host ``evil.com`` (as a browser would), not ``good.com``.
    """

    return text.replace("\\", "/")


def is_path_like(text: str) -> bool:
    return (
        text.startswith(("/", "./", "../", "~/", "~\\", ".\\", "..\\"))
        or text in (".", "..", "~")
        or bool(_DRIVE_RE.match(text.replace("\\", "/")))
        or text.lower().startswith("file:")
        or ("\\" in text and "://" not in text)
    )


def looks_like_email(text: str) -> bool:
    text = text.strip()
    if text.lower().startswith("mailto:") or _ANGLE_EMAIL_RE.search(text):
        return True
    return bool(_EMAIL_RE.match(text)) and "/" not in text and "." in text.rpartition("@")[2]


# --------------------------------------------------------------------------------------- pieces


def _norm_url_path(path: str) -> str:
    if not path:
        return ""
    normalised = posixpath.normpath(path)
    if normalised in (".", "/", "//"):
        return ""
    normalised = "/" + normalised.lstrip("/")
    return normalised


def _clean_query(query: str) -> str:
    if not query:
        return ""
    kept: list[tuple[str, str]] = []
    for name, value in parse_qsl(query, keep_blank_values=True):
        lowered = name.lower()
        if lowered.startswith("utm_") or lowered in _TRACKING_PARAMS:
            continue
        if lowered in _CREDENTIAL_PARAMS or lowered.startswith(_CREDENTIAL_PREFIXES):
            value = REDACTED
        kept.append((name, value))
    return urlencode(kept, quote_via=quote, safe="/:,@")


def _netloc(host: HostInfo, port: int | None, scheme: str) -> str:
    rendered = f"[{host.host}]" if host.ip is not None and host.ip.version == 6 else host.host
    if port is not None and DEFAULT_PORTS.get(scheme) != port:
        rendered = f"{rendered}:{port}"
    return rendered


def _git_host_form(host: str, path: str, *, repository: bool) -> str | None:
    """github.com/owner/repo[/path] style identifiers for GitHub/GitLab (and any host for repos)."""

    segments = [s for s in path.split("/") if s]
    if host in ("www.github.com", "github.com"):
        host = "github.com"
    elif host == "raw.githubusercontent.com" and len(segments) >= 3:
        # raw.githubusercontent.com/<owner>/<repo>/<ref>/<path> is content of github.com/<owner>/<repo>
        host, segments = "github.com", [*segments[:2], "blob", *segments[2:]]
    elif host == "api.github.com" and len(segments) >= 3 and segments[0] == "repos":
        host, segments = "github.com", segments[1:]
    elif host in ("www.gitlab.com", "gitlab.com"):
        host = "gitlab.com"
    elif not repository:
        return None
    if host in _CASE_INSENSITIVE_GIT_HOSTS:
        if host == "gitlab.com":
            # Namespace segments come before GitLab's "/-/" separator and are case-insensitive.
            stop = segments.index("-") if "-" in segments else len(segments)
            segments = [s.lower() for s in segments[:stop]] + segments[stop:]
        else:
            segments = [s.lower() for s in segments[:2]] + segments[2:]
    if len(segments) >= 2 and segments[1].lower().endswith(".git"):
        segments[1] = segments[1][:-4]
    if repository and segments and segments[-1].lower().endswith(".git"):
        segments[-1] = segments[-1][:-4]
    normalised = _norm_url_path("/" + "/".join(segments))
    return f"{host}{normalised}"


# ---------------------------------------------------------------------------------- canonicals


def canonical_url(raw: str, *, repository: bool = False) -> Canonical | None:
    """Canonicalise ``scheme://...`` identifiers. Returns None when ``raw`` is not such a URL."""

    match = _SCHEME_RE.match(raw)
    if not match:
        return None
    scheme = match.group(1).lower()
    if scheme == "file":
        return canonical_path(raw)
    if scheme in WEB_SCHEMES:
        raw = web_url_text(raw)
    parts = urlsplit(raw)
    netloc = parts.netloc.rpartition("@")[2]  # drop user-info (may carry credentials)
    host_text, port = split_host_port(netloc)
    host = canonical_host(host_text)
    path = _norm_url_path(parts.path)
    query = f"?{q}" if (q := _clean_query(parts.query)) else ""
    if host is None:
        return Canonical(identifier=f"{scheme}://{netloc.lower()}{path}{query}")
    is_git = repository or scheme in ("ssh", "git", "git+ssh")
    if scheme in WEB_SCHEMES or is_git:
        git_form = _git_host_form(host.host, parts.path, repository=is_git)
        if git_form is not None:
            return Canonical(identifier=git_form, host=_git_host_info(git_form, host), path=parts.path)
    identifier = f"{scheme}://{_netloc(host, port, scheme)}{path}{query}"
    # Single-label names in non-web URIs (s3://bucket, postgres://db) are not internet domains.
    named_domain = host.ip is not None or "." in host.host or host.host == "localhost"
    if scheme not in WEB_SCHEMES and not named_domain:
        return Canonical(identifier=identifier, path=parts.path)
    return Canonical(identifier=identifier, host=host, path=parts.path)


def _git_host_info(git_form: str, fallback: HostInfo) -> HostInfo:
    host = git_form.split("/", 1)[0]
    return fallback if fallback.host == host else HostInfo(host=host, original=fallback.original)


def canonical_bare_host(raw: str, *, repository: bool = False) -> Canonical | None:
    """``example.com/docs?x=1`` (no scheme). Returns None when the first segment is not a host."""

    raw = web_url_text(raw)
    first = re.split(r"[/?#]", raw, maxsplit=1)[0]
    if "@" in first:
        return None
    host_text, port = split_host_port(first)
    host = canonical_host(host_text)
    if host is None:
        return None
    # Require something that is plausibly an internet host: an IP, localhost or a dotted name
    # ending in an alphabetic top-level label (so "notes.v2" or "1.2.3-beta" are not hosts).
    if host.ip is None and not re.search(r"\.[a-z][a-z0-9\-]*$|^localhost$", host.host):
        return None
    parts = urlsplit("//" + raw)
    git_form = _git_host_form(host.host, parts.path, repository=repository)
    if git_form is not None:
        return Canonical(identifier=git_form, host=_git_host_info(git_form, host), path=parts.path)
    identifier = f"{_netloc(host, port, '')}{_norm_url_path(parts.path)}"
    query = _clean_query(parts.query)
    if query:
        identifier = f"{identifier}?{query}"
    return Canonical(identifier=identifier, host=host, path=parts.path)


def canonical_path(raw: str) -> Canonical:
    text = raw.strip()
    if text.lower().startswith("file:"):
        parts = urlsplit(text)
        path = unquote(parts.path)
        netloc = parts.netloc.lower()
        text = f"//{parts.netloc}{path}" if netloc and netloc != "localhost" else path
    text = text.replace("\\", "/")
    drive = _DRIVE_RE.match(text)
    if drive:
        text = drive.group(1).upper() + text[1:]
    normalised = posixpath.normpath(text) if text else "."
    if normalised.startswith("//") and not text.startswith("//"):
        normalised = "/" + normalised.lstrip("/")
    return Canonical(identifier=normalised)


def canonical_email(raw: str) -> Canonical:
    text = raw.strip()
    angle = _ANGLE_EMAIL_RE.search(text)
    if angle:
        text = angle.group(1)
    if text.lower().startswith("mailto:"):
        text = text[7:].split("?", 1)[0]
    text = unquote(text).strip().lower()
    local, sep, domain = text.rpartition("@")
    if not sep or not local:
        return Canonical(identifier=text)
    host = canonical_host(domain)
    if host is None:
        return Canonical(identifier=text)
    rendered = f"[{host.host}]" if host.ip is not None else host.host
    return Canonical(identifier=f"{local}@{rendered}", host=host)


def canonical_mcp(raw: str) -> Canonical:
    """MCP servers/tools → lower-case ``server`` or ``server/tool`` (accepts ``mcp__server__tool``)."""

    text = raw.strip().lower()
    if text.startswith("mcp__"):
        server, _, tool = text[5:].partition("__")
    elif "/" in text:
        server, _, tool = text.partition("/")
    elif ":" in text:
        server, _, tool = text.partition(":")
    else:
        server, tool = text, ""
    server, tool = server.strip(), tool.strip()
    return Canonical(identifier=f"{server}/{tool}" if tool else server)


def canonical_repository(raw: str) -> Canonical:
    text = raw.strip()
    scp = _SCP_GIT_RE.match(text)
    if scp and not has_scheme(text):
        host = canonical_host(scp.group(1))
        if host is not None:
            git_form = _git_host_form(host.host, "/" + scp.group(2), repository=True)
            if git_form is not None:
                return Canonical(identifier=git_form, host=_git_host_info(git_form, host))
    if has_scheme(text):
        url = canonical_url(text, repository=True)
        if url is not None:
            return url
    if is_path_like(text):
        return canonical_path(text)
    if _OWNER_REPO_RE.match(text.rstrip("/")):
        owner, repo = text.rstrip("/").split("/")
        if repo.lower().endswith(".git"):
            repo = repo[:-4]
        return Canonical(
            identifier=f"github.com/{owner.lower()}/{repo.lower()}", host=HostInfo(host="github.com")
        )
    bare = canonical_bare_host(text, repository=True)
    if bare is not None:
        return bare
    return canonical_path(text)


# ----------------------------------------------------------------------------------- dispatch

_PATH_TYPES = frozenset({"file", "user_upload"})
_MCP_TYPES = frozenset({"mcp_server", "mcp_tool"})
_PLAIN_TYPES = frozenset({"user_prompt", "system"})
_PRODUCED_TYPES = frozenset({"tool_output", "agent_output"})


def canonicalize(source_type: str, identifier: str) -> Canonical:
    """Canonical form of a source identifier for its type (see ``canonicalize_source``)."""

    raw = (identifier or "").strip()
    st = (source_type or "other").strip().lower()
    if not raw:
        return Canonical(identifier="")
    if st == "repository":
        return canonical_repository(raw)
    if st in _PLAIN_TYPES:
        return Canonical(identifier=raw)
    if st in _PATH_TYPES:
        if has_scheme(raw) and not raw.lower().startswith("file:"):
            url = canonical_url(raw)
            if url is not None:
                return url
        return canonical_path(raw)
    if st == "email":
        if has_scheme(raw):
            url = canonical_url(raw)
            if url is not None:
                return url
        return canonical_email(raw)
    if st in _MCP_TYPES:
        return (canonical_url(raw) if has_scheme(raw) else None) or canonical_mcp(raw)
    if has_scheme(raw):
        url = canonical_url(raw)
        if url is not None:
            return url
    if st in _PRODUCED_TYPES or st == "database":
        return Canonical(identifier=raw)
    if raw.lower().startswith("file:") or (st in ("document", "other") and is_path_like(raw)):
        return canonical_path(raw)
    if st == "other" and looks_like_email(raw):
        return canonical_email(raw)
    bare = canonical_bare_host(raw)
    if bare is not None:
        return bare
    return Canonical(identifier=raw)
