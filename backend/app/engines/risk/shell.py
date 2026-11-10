"""Best-effort static analysis of shell command lines and inline code (pure).

This never executes anything. It tokenises with :mod:`shlex` (tolerating unbalanced quotes),
splits pipelines/lists, unwraps ``sudo``/``env``/``xargs``/``bash -c``/``eval`` and reports which
programs run, which of them can transmit data, the remote targets they name, the local files they
read/write/upload, environment dumps and destructive operations.

Static analysis can be evaded (variables, aliases, encoded payloads); results describe what the
command line *visibly* does and say "target not statically known" rather than guessing.
"""

from __future__ import annotations

import re
import shlex
from functools import lru_cache

from app.engines.risk import sanitize as san
from app.engines.risk.shell_acc import DEV_NET, URL_IN_TEXT, Acc, ShellAnalysis, ShellFile, path_candidate
from app.engines.risk.shell_net import analyze_network_program
from app.engines.risk.shell_specs import (
    DESTRUCTIVE_RM_TARGETS,
    ENV_DUMP_PROGRAMS,
    INTERPRETERS,
    NETWORK_SPECS,
    PUBLISHERS,
    SERVICE_CLIS,
    SHELLS,
    WRAPPERS,
    XARGS_VALUE_OPTS,
)

MAX_DEPTH = 3
MAX_COMMAND_LENGTH = 20_000

_PUNCT = set(";&|()<>`")
_OPERATORS = ("<<<", "&&", "||", "|&", ">>", "<<", ">&", "<&", "&>", ">|", ";;", "|", "&", ";", "(", ")", "`",
              "<", ">")
_REDIRECT_OPS = {">", ">>", "<", "<&", ">&", "&>", ">|", "<<", "<<<"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_NETWORK_CODE = re.compile(
    r"(requests\.(?:get|post|put|patch|request|Session)|urllib|http\.client|httpx|aiohttp|socket\.|"
    r"\bfetch\s*\(|axios|XMLHttpRequest|net/http|Net::HTTP|LWP::|IO::Socket|curl_exec|Invoke-WebRequest|"
    r"Invoke-RestMethod|WebClient|smtplib|ftplib|paramiko|open-uri|Net::SMTP|https?\.request)",
    re.IGNORECASE,
)
_QUOTED_PATH = re.compile(r"""['"]((?:~|/|\.{1,2}/)[^'"\s]{1,300}|[^'"\s/]*\.env(?:\.[\w-]+)?)['"]""")
_PRIVILEGE_WRAPPERS = {"sudo", "doas", "su"}
_TEXT_PROGRAMS = {"echo", "printf", "test", "[", "true", "false", "sleep", "exit", "return"}
# Programs whose file arguments are read (their content may end up on stdout / in a pipeline).
_READ_PROGRAMS = {"cat", "head", "tail", "less", "more", "base64", "xxd", "od", "hexdump", "strings", "grep",
                  "egrep", "fgrep", "rg", "ag", "awk", "sed", "cut", "sort", "uniq", "tac", "nl", "jq", "yq",
                  "tar", "zip", "gzip", "bzip2", "xz", "7z", "source", ".", "diff", "cmp", "md5sum", "sha256sum",
                  "gpg", "openssl", "security"}


def program_name(word: str) -> str:
    name = word.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _prescan(command: str) -> str:
    """Turn unquoted newlines into ``;``, join line continuations and drop ``#`` comments."""
    out: list[str] = []
    quote: str | None = None
    i, n = 0, len(command)
    while i < n:
        ch = command[i]
        if ch == "\\" and quote != "'":
            if i + 1 < n and command[i + 1] == "\n":
                i += 2
                continue
            out.append(command[i : i + 2])
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = None
            out.append(ch)
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        elif ch == "\n":
            out.append(" ; ")
        elif ch == "#" and (not out or out[-1][-1:].isspace() or out[-1][-1:] in _PUNCT):
            while i < n and command[i] != "\n":
                i += 1
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _lex(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>`")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _flat_split(command: str) -> list[str]:
    flat = command.replace('"', " ").replace("'", " ")
    return re.findall(r"[^\s;&|()<>`]+|[;&|()<>`]+", flat)


def tokenize(command: str) -> tuple[list[list[str]], list[str]]:
    """Token streams plus warnings. Never raises on malformed input.

    With unbalanced quotes the shell would refuse to run the line, but an attacker-controlled
    string may still be completed later, so both readings are returned: the quote-closed lexing
    and a quote-blind split. Analysing both can only add findings, never hide one.
    """
    try:
        return [_lex(command)], []
    except ValueError:
        pass
    for closer in ('"', "'"):
        try:
            return [_lex(command + closer), _flat_split(command)], ["unbalanced quotes; parsed best-effort"]
        except ValueError:
            continue
    return [_flat_split(command)], ["could not tokenise; split on whitespace"]


def _split_ops(run: str) -> list[str]:
    ops, i = [], 0
    while i < len(run):
        for op in _OPERATORS:
            if run.startswith(op, i):
                ops.append(op)
                i += len(op)
                break
        else:  # pragma: no cover - every punctuation char is a single-char operator
            i += 1
    return ops


def _segments(tokens: list[str]) -> list[tuple[list[str], list[tuple[str, str]]]]:
    segments: list[tuple[list[str], list[tuple[str, str]]]] = []
    words: list[str] = []
    redirects: list[tuple[str, str]] = []
    pending: str | None = None
    for tok in tokens:
        if tok and all(c in _PUNCT for c in tok):
            for op in _split_ops(tok):
                if op in _REDIRECT_OPS:
                    pending = op
                else:
                    pending = None
                    if words or redirects:
                        segments.append((words, redirects))
                        words, redirects = [], []
            continue
        if pending:
            op, pending = pending, None
            if op in {"<<", "<<<"} or (op in {">&", "<&"} and (tok.isdigit() or tok == "-")):
                continue
            redirects.append((op, tok))
            continue
        if tok != "$":
            words.append(tok)
    if words or redirects:
        segments.append((words, redirects))
    return segments


def _flag_value(args: list[str], flags: set[str], *, case_insensitive: bool = False) -> str | None:
    """Value following one of ``flags`` (exact match)."""
    for i, arg in enumerate(args):
        if (arg.lower() if case_insensitive else arg) in flags:
            return args[i + 1] if i + 1 < len(args) else None
    return None


def _shell_code(args: list[str]) -> str | None:
    """``bash -c CODE`` including combined short flags such as ``-lc`` / ``-ec``."""
    for i, arg in enumerate(args):
        if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            return args[i + 1] if i + 1 < len(args) else None
        if not arg.startswith("-"):
            return None  # a script path comes first: no inline code
    return None


def _generic_args(args: list[str], acc: Acc, role: str = "arg") -> None:
    for arg in args:
        value = arg.split("=", 1)[1] if arg.startswith("--") and "=" in arg else arg
        if value.startswith("-"):
            continue
        if "://" in value:
            acc.add_url(value)
        elif "=" in value and not value.startswith(("/", "~", ".")):
            rhs = value.partition("=")[2]  # dd if=/path, KEY=/path
            if rhs.startswith(("/", "~", "./")):
                acc.add_file(rhs, "write" if value.startswith("of=") else role)
        else:
            acc.add_file(value, role)


def _destructive(prog: str, args: list[str], acc: Acc) -> None:
    if prog == "rm":
        short = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
        recursive = "r" in short.lower() or "--recursive" in args
        targets = [a for a in args if not a.startswith("-")]
        hit = [t for t in targets if t in DESTRUCTIVE_RM_TARGETS]
        if (recursive and hit) or "--no-preserve-root" in args:
            acc.destructive.append(f"rm -r on {', '.join(hit) or '/'} deletes broad parts of the filesystem")
    elif prog.startswith("mkfs") or prog in {"wipefs", "shred"}:
        acc.destructive.append(f"{prog} irreversibly destroys data")
    elif prog == "dd" and any(a.startswith("of=/dev/") for a in args):
        acc.destructive.append("dd writes directly to a block device")
    elif prog in {"chmod", "chown"} and "-R" in args and "/" in args:
        acc.destructive.append(f"{prog} -R on / changes permissions of the whole filesystem")


def _publisher(prog: str, args: list[str], acc: Acc) -> bool:
    positional = [a for a in args if not a.startswith("-")]
    if not positional or (prog, positional[0]) not in PUBLISHERS:
        return False
    sub = positional[0]
    kind, ident = PUBLISHERS[(prog, sub)]
    custom = None
    for i, arg in enumerate(args):
        if arg in {"--registry", "--repository-url", "--index", "--repository"} and i + 1 < len(args):
            custom = args[i + 1]
        elif arg.startswith(("--registry=", "--repository-url=", "--index=")):
            custom = arg.split("=", 1)[1]
    if custom and "://" in custom:
        acc.add_url(custom, target=True)
    elif prog in {"docker", "podman"} and len(positional) > 1:
        first = positional[1].split("/", 1)[0]
        if "/" in positional[1] and ("." in first or ":" in first or first == "localhost"):
            acc.add_host(first, single_label=True)
        else:
            acc.services.append((kind, ident))
    else:
        acc.services.append((kind, ident))
    acc.network(f"{prog} {sub}", f"{prog} {sub} uploads local content to a registry")
    return True


def _git(args: list[str], acc: Acc) -> None:
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in {"-C", "-c", "--git-dir", "--work-tree", "--namespace"} else 1
    if i >= len(args):
        return
    sub, rest = args[i], args[i + 1 :]
    positional = [a for a in rest if not a.startswith("-")]
    if sub == "push":
        remote = positional[0] if positional else None
        if remote and "://" in remote:
            acc.add_url(remote, target=True)
        elif remote and re.match(r"^[^@\s]+@[^:\s]+:", remote):
            acc.add_host(remote.split("@", 1)[1].split(":", 1)[0], single_label=True)
        else:
            acc.services.append(("service", f"git-remote:{remote or 'default'}"))
        acc.network("git push", "git push uploads commits to a remote repository")
    elif sub == "send-email":
        for arg in rest:
            if arg.startswith(("--to=", "--cc=", "--bcc=")):
                acc.add_email(arg.split("=", 1)[1])
        for p in positional:
            if "@" in p:
                acc.add_email(p)
            else:
                acc.add_file(p, "upload")
        acc.network("git send-email", "git send-email mails patches to recipients")
    else:
        for p in positional:
            if "://" in p:
                acc.add_url(p)


def scan_code(code: str, acc: Acc, origin: str) -> None:
    """Inline interpreter code: URLs, quoted paths and networking APIs."""
    urls = [acc.add_url(m.group(0)) for m in URL_IN_TEXT.finditer(code)]
    for m in _QUOTED_PATH.finditer(code):
        acc.add_file(m.group(1), "read")
    for m in DEV_NET.finditer(code):
        acc.add_file(m.group(0), "write")
    net = _NETWORK_CODE.search(code)
    if net:
        for url in urls:
            host = san.url_host(url) if url else None
            if host:
                acc.targets.append(host)
        acc.network(f"{origin} code", f"inline {origin} code uses networking ({net.group(0).strip()})")


def _analyze_words(words: list[str], redirects: list[tuple[str, str]], acc: Acc, depth: int) -> None:
    for op, target in redirects:
        acc.add_file(target, "read" if op.startswith("<") else "write")
        if op.startswith(">") and re.match(r"^/dev/(sd|nvme|hd|disk)", target):
            acc.destructive.append(f"redirect overwrites block device {target}")
    i, n = 0, len(words)
    while i < n:
        word = words[i]
        if _ASSIGNMENT.match(word):
            i += 1
            continue
        prog = program_name(word)
        if prog in WRAPPERS:
            opts = WRAPPERS[prog]
            if prog in _PRIVILEGE_WRAPPERS:
                acc.programs.append(prog)
            i += 1
            while i < n and words[i].startswith("-"):
                i += 2 if words[i] in opts else 1
            if prog == "timeout" and i < n:
                i += 1
            continue
        if prog == "env":
            i += 1
            while i < n and (words[i].startswith("-") or _ASSIGNMENT.match(words[i])):
                i += 2 if words[i] in {"-u", "--unset", "-C", "--chdir"} else 1
            if i >= n:
                acc.programs.append("env")
                acc.env_dumps.append("env")
                return
            continue
        break
    if i >= n:
        return
    prog, args = program_name(words[i]), words[i + 1 :]
    acc.programs.append(prog)
    _dispatch(prog, args, acc, depth)


def _dispatch(prog: str, args: list[str], acc: Acc, depth: int) -> None:
    if prog in SHELLS:
        code = _shell_code(args)
        if code is not None:
            _analyze(code, acc, depth + 1)
        else:
            _generic_args(args[:1], acc)
        return
    if prog == "eval":
        _analyze(" ".join(args), acc, depth + 1)
        return
    if prog == "xargs":
        j = 0
        while j < len(args) and args[j].startswith("-"):
            j += 2 if args[j] in XARGS_VALUE_OPTS else 1
        _analyze_words(args[j:], [], acc, depth + 1)
        return
    if prog in ENV_DUMP_PROGRAMS or (prog in {"set", "export", "declare", "typeset"} and
                                     all(a in {"-p", "-x", "-px", "-xp"} for a in args)):
        acc.env_dumps.append(prog)
        return
    if prog in INTERPRETERS:
        code = _flag_value(args, INTERPRETERS[prog], case_insensitive=prog in {"powershell", "pwsh"})
        if code is not None:
            scan_code(code, acc, prog)
        else:
            _generic_args([a for a in args if not a.startswith("-")][:1], acc)
        return
    if prog == "git":
        _git(args, acc)
        return
    if _publisher(prog, args, acc):
        return
    if prog in SERVICE_CLIS:
        kind, ident = SERVICE_CLIS[prog]
        acc.services.append((kind, ident))
        acc.network(prog, f"{prog} sends requests to the {ident} API")
        positional = [a for a in args if not a.startswith("-")]
        remote_last = bool(positional) and "://" in positional[-1]
        for p in positional:
            if "://" in p:
                acc.add_url(p, target=True)
            else:
                acc.add_file(p, "upload" if remote_last else "arg")
        return
    spec = NETWORK_SPECS.get(prog)
    if spec is not None:
        analyze_network_program(prog, args, spec, acc)
        return
    _destructive(prog, args, acc)
    if prog not in _TEXT_PROGRAMS:
        _generic_args(args, acc, "read" if prog in _READ_PROGRAMS else "arg")


def _analyze(command: str, acc: Acc, depth: int) -> None:
    if depth > MAX_DEPTH:
        acc.warnings.append("nested shell invocations beyond depth 3 were not analysed")
        return
    if ":(){" in command.replace(" ", ""):
        acc.destructive.append("fork bomb pattern exhausts system resources")
    streams, warnings = tokenize(_prescan(command))
    acc.warnings.extend(warnings)
    for tokens in streams:
        for words, redirects in _segments(tokens):
            _analyze_words(words, redirects, acc, depth)


@lru_cache(maxsize=512)
def analyze_command(command: str) -> ShellAnalysis:
    acc = Acc()
    if len(command) > MAX_COMMAND_LENGTH:
        acc.warnings.append(f"command longer than {MAX_COMMAND_LENGTH} characters; only the start was analysed")
        command = command[:MAX_COMMAND_LENGTH]
    _analyze(command, acc, 0)
    return acc.freeze()


@lru_cache(maxsize=256)
def analyze_code(code: str, language: str = "code") -> ShellAnalysis:
    acc = Acc()
    scan_code(code[:MAX_COMMAND_LENGTH], acc, language)
    return acc.freeze()


__all__ = ["Acc", "ShellAnalysis", "ShellFile", "analyze_code", "analyze_command", "path_candidate", "program_name"]
