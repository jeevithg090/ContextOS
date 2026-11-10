"""Argument analysis for network-capable shell programs (curl, wget, ssh, scp, nc, dig, mail...).

Driven by the declarative specs in ``shell_specs.NETWORK_SPECS``. Determines the remote targets,
the local files a program uploads / writes / uses as keys, and whether the program is actually
used for network transfer (``scp a b`` between two local paths is not).
"""

from __future__ import annotations

import re
from typing import Any

from app.engines.risk import sanitize as san
from app.engines.risk.shell_acc import URL_IN_TEXT, Acc
from app.engines.risk.shell_specs import HTTP_METHODS, SOCAT_CONNECT_TYPES, SOCAT_FILE_TYPES

_SCP_REMOTE = re.compile(r"^(?:[^@/\s:]+@)?([^:/\s@]+):(.*)$")
_DATA_FILE = re.compile(r"(?:^|=)[@<]([^;@<]+)")
_HTTPIE_FILE = re.compile(r"^[^=:@]+(?:=|:=)?@(.+)$")


def _lower_spec(spec: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = dict(spec)
    for name in ("value", "data", "url", "host", "email", "exec"):
        out[name] = {k.lower() for k in spec.get(name, ())}
    out["file"] = {k.lower(): v for k, v in spec.get("file", {}).items()}
    return out


def _option_keys(spec: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for name in ("value", "data", "url", "host", "email", "exec"):
        keys |= set(spec.get(name, ()))
    keys |= set(spec.get("file", {}))
    return keys


def _option_value(prog: str, key: str, value: str, spec: dict[str, Any], acc: Acc) -> bool:
    """Record what an option's value names. Returns True when it named a remote host."""
    if key in spec.get("file", {}):
        acc.add_file(value[1:] if value.startswith("@") else value, spec["file"][key])
    elif key in spec.get("data", ()):
        if value.startswith("@") and value not in {"@-", "@"}:
            acc.add_file(value[1:], "upload")
        else:
            for m in _DATA_FILE.finditer(value):
                if m.group(1) != "-":
                    acc.add_file(m.group(1), "upload")
    elif key in spec.get("url", ()):
        return bool(acc.add_url(value, target=True)) if "://" in value else bool(acc.add_host(value))
    elif key in spec.get("host", ()):
        if "://" in value:
            return bool(acc.add_url(value, target=True))
        return bool(acc.add_host(value, single_label=True))
    elif key in spec.get("email", ()):
        acc.add_email(value)
    elif key in spec.get("exec", ()):
        acc.exec_on_connect = True
        acc.network(prog, f"{prog} runs '{san.truncate(value, 60)}' for whoever connects (reverse/bind shell pattern)")
    return False


def _remote_or_file(prog: str, positional: list[str], acc: Acc) -> bool:
    remote_idx: list[int] = []
    for idx, p in enumerate(positional):
        if "://" in p:
            acc.add_url(p, target=True)
            remote_idx.append(idx)
            continue
        m = _SCP_REMOTE.match(p)
        if m and len(m.group(1)) > 1:  # "C:\path" is a Windows drive, not a host
            acc.add_host(m.group(1), single_label=True)
            remote_idx.append(idx)
    if not remote_idx:
        for p in positional:
            acc.add_file(p, "read")
        return False
    uploading = (len(positional) - 1) in remote_idx
    for idx, p in enumerate(positional):
        if idx not in remote_idx:
            acc.add_file(p, "upload" if uploading else "write")
    return True


def _url_like(prog: str, positional: list[str], acc: Acc) -> None:
    for p in positional:
        if p.upper() in HTTP_METHODS:
            continue
        if "://" in p:
            acc.add_url(p, target=True)
        elif "/" in p or "?" in p:
            if acc.add_url(f"http://{p}", target=True) is None:
                acc.add_file(p, "arg")
        else:
            acc.add_host(p)


def _httpie(positional: list[str], acc: Acc) -> None:
    items = list(positional)
    if items and items[0].upper() in HTTP_METHODS:
        items = items[1:]
    if not items:
        return
    target, rest = items[0], items[1:]
    if target.startswith(":"):
        acc.add_host("localhost")
    elif "://" in target:
        acc.add_url(target, target=True)
    else:
        acc.add_url(f"http://{target}", target=True)
    for item in rest:
        m = _HTTPIE_FILE.match(item)
        if m:
            acc.add_file(m.group(1), "upload")


def _socat(prog: str, positional: list[str], acc: Acc) -> bool:
    networked = False
    for addr in positional:
        parts = addr.split(":")
        kind = parts[0].lower().split(",")[0]
        if kind in SOCAT_CONNECT_TYPES and len(parts) >= 2:
            acc.add_host(parts[1], single_label=True)
            networked = True
        elif kind.endswith("listen"):
            networked = True
        elif kind in SOCAT_FILE_TYPES and len(parts) >= 2:
            acc.add_file(parts[1].split(",")[0], "read")
        elif kind in {"exec", "system"}:
            acc.exec_on_connect = True
    return networked


def analyze_network_program(prog: str, args: list[str], spec: dict[str, Any], acc: Acc) -> None:
    ci = bool(spec.get("case_insensitive"))
    if ci:
        spec = _lower_spec(spec)
    keys = _option_keys(spec)
    positional: list[str] = []
    host_from_option = False
    targets_before = len(acc.targets)
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            positional.extend(args[i + 1 :])
            break
        if arg.startswith("-") and len(arg) > 1:
            key, eq, inline = arg.partition("=") if arg.startswith("--") else (arg, "", "")
            key = key.lower() if ci else key
            if not eq and not arg.startswith("--") and len(arg) > 2 and key not in keys and arg[:2] in keys:
                key, inline, eq = arg[:2], arg[2:], "="  # "-d@file", "-ofile"
            if key in keys:
                if not eq:
                    i += 1
                    inline = args[i] if i < len(args) else ""
                host_from_option |= _option_value(prog, key, inline, spec, acc)
            i += 1
            continue
        positional.append(arg)
        i += 1

    style = spec.get("positional", "none")
    networked = True
    if style == "url":
        _url_like(prog, positional, acc)
    elif style == "ssh":
        if positional:
            dest = positional[0]
            if "://" in dest:
                acc.add_url(dest, target=True)
            else:
                acc.add_host(dest, single_label=True)
            for m in URL_IN_TEXT.finditer(" ".join(positional[1:])):
                acc.add_url(m.group(0))
    elif style == "remote_or_file":
        networked = _remote_or_file(prog, positional, acc) or host_from_option
    elif style in {"host_port", "host_or_url"}:
        if positional:
            first = positional[0]
            if "://" in first:
                acc.add_url(first, target=True)
            else:
                acc.add_host(first, single_label=True)
    elif style == "socat":
        networked = _socat(prog, positional, acc)
    elif style == "dns":
        for p in positional:
            if p.startswith("@"):
                acc.add_host(p[1:], single_label=True)
            elif not p.startswith(("+", "-")):
                acc.add_host(p)
    elif style == "emails":
        for p in positional:
            acc.add_email(p)
    elif style == "httpie":
        _httpie(positional, acc)
    if spec.get("only_with_host") and not host_from_option:
        networked = False
    if networked:
        targets = acc.targets[targets_before:]
        detail = f" (targets: {', '.join(dict.fromkeys(targets[-3:]))})" if targets else " (target not statically known)"
        acc.network(prog, f"{prog} can transmit data off this machine{detail}")
