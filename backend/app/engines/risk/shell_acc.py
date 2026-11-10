"""Accumulator and result types for the shell analyser (pure)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.engines.risk import sanitize as san

URL_IN_TEXT = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://[^\s'\"<>()\[\]{}`|;]+")
DEV_NET = re.compile(r"/dev/(?:tcp|udp)/([^/\s'\"]+)/\d+")
_PROC_ENVIRON = re.compile(r"^/proc/(?:\d+|self|\$\$|\*)/environ$")
_FILE_NAME = re.compile(r"^[\w\-*?\[\]]*(?:\.[\w\-*?\[\]]+)+$")
_BARE_WORD = re.compile(r"^[\w\-]{2,64}$")
_ROLE_RANK = {"upload": 4, "key": 3, "write": 2, "read": 1, "arg": 0}


@dataclass(frozen=True)
class ShellFile:
    path: str
    role: str  # read | write | upload | key | arg


@dataclass(frozen=True)
class ShellAnalysis:
    programs: tuple[str, ...] = ()
    network_programs: tuple[str, ...] = ()
    outbound_reasons: tuple[str, ...] = ()
    files: tuple[ShellFile, ...] = ()
    bare_words: tuple[str, ...] = ()  # positional words that might be file names (checked by caller)
    urls: tuple[str, ...] = ()  # sanitised
    hosts: tuple[str, ...] = ()  # every host seen
    targets: tuple[str, ...] = ()  # hosts contacted by network programs
    emails: tuple[str, ...] = ()
    services: tuple[tuple[str, str], ...] = ()  # (kind, identifier) for CLIs with a known remote API
    env_dumps: tuple[str, ...] = ()
    destructive: tuple[str, ...] = ()
    exec_on_connect: bool = False
    warnings: tuple[str, ...] = ()

    @property
    def remote_targets(self) -> tuple[str, ...]:
        return tuple(h for h in self.targets if not san.is_loopback(h))

    @property
    def outbound(self) -> bool:
        """True when a network-capable program runs and not every target is loopback."""
        if not self.network_programs:
            return False
        if self.services or not self.targets:
            return True  # a remote API, or the target is not statically known (e.g. a variable)
        return bool(self.remote_targets)


@dataclass
class Acc:
    """Mutable accumulator shared by the shell and network-program analysers."""

    programs: list[str] = field(default_factory=list)
    network_programs: list[str] = field(default_factory=list)
    outbound_reasons: list[str] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    bare_words: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    services: list[tuple[str, str]] = field(default_factory=list)
    env_dumps: list[str] = field(default_factory=list)
    destructive: list[str] = field(default_factory=list)
    exec_on_connect: bool = False
    warnings: list[str] = field(default_factory=list)

    def add_url(self, raw: str, *, target: bool = False) -> str | None:
        url = san.sanitize_url(raw)
        if not url:
            return None
        self.urls.append(url)
        host = san.url_host(url)
        if host:
            self.hosts.append(host)
            if target:
                self.targets.append(host)
        return url

    def add_host(self, raw: str, *, target: bool = True, single_label: bool = False) -> str | None:
        host = san.normalize_host(raw, allow_single_label=single_label)
        if host:
            self.hosts.append(host)
            if target:
                self.targets.append(host)
        return host

    def add_email(self, raw: str) -> None:
        for part in re.split(r"[,;\s]+", raw):
            email = san.normalize_email(part)
            if email:
                self.emails.append(email)

    def add_file(self, raw: str, role: str) -> None:
        if not raw:
            return
        dev = DEV_NET.search(raw)
        if dev:
            self.add_host(dev.group(1), single_label=True)
            self.network("/dev/tcp", "redirects data to a network socket via /dev/tcp (a common reverse-shell "
                                     "and exfiltration technique)")
            return
        if _PROC_ENVIRON.match(raw):
            self.env_dumps.append(raw)
        candidate = path_candidate(raw)
        if candidate is None:
            if _BARE_WORD.match(raw):
                self.bare_words.append(raw)
            return
        masked = san.truncate(san.mask_path_segments(candidate, min_length=24, min_entropy=4.0))
        if not masked.strip("/").replace(san.MASK, "").strip("/"):
            return
        if _ROLE_RANK.get(role, 0) >= _ROLE_RANK.get(self.files.get(masked, "arg"), 0):
            self.files[masked] = role

    def network(self, program: str, reason: str) -> None:
        self.network_programs.append(program)
        self.outbound_reasons.append(reason)

    def freeze(self) -> ShellAnalysis:
        return ShellAnalysis(
            programs=_uniq(self.programs),
            network_programs=_uniq(self.network_programs),
            outbound_reasons=_uniq(self.outbound_reasons),
            files=tuple(ShellFile(p, r) for p, r in self.files.items()),
            bare_words=_uniq(self.bare_words),
            urls=_uniq(self.urls),
            hosts=_uniq(self.hosts),
            targets=_uniq(self.targets),
            emails=_uniq(self.emails),
            services=_uniq(self.services),
            env_dumps=_uniq(self.env_dumps),
            destructive=_uniq(self.destructive),
            exec_on_connect=self.exec_on_connect,
            warnings=_uniq(self.warnings),
        )


def _uniq(items: list) -> tuple:
    return tuple(dict.fromkeys(items))


def path_candidate(tok: str) -> str | None:
    """Return ``tok`` when it plausibly names a file or directory."""
    if not tok or len(tok) > 4096 or san.REDACTION_MARKER in tok or tok.startswith("-") or "://" in tok:
        return None
    if tok in {"/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr", "-", ".", ".."}:
        return None
    if tok.startswith("$") and "/" not in tok:
        return None
    if any(c.isspace() for c in tok):
        return tok if tok.startswith(("/", "~", "./")) else None
    if tok.startswith(("/", "~", "./", "../")) or "/" in tok or _FILE_NAME.match(tok):
        return tok
    return None
