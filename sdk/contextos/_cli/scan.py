"""``contextos scan``: run ContextOS detection on files or stdin without storing anything.

Files at sensitive paths (``.env``, SSH keys, cloud credentials, ...) are NOT uploaded unless
``--force`` is given. Binary and oversized files are skipped. Exit codes: 0 nothing found,
3 something was detected (unless ``--no-fail``), 1 an error stopped the scan.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.table import Table

from contextos._cli.common import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    cli_errors,
    err,
    get_client,
    get_config,
    items_of,
    out,
    pick,
    print_json,
    severity,
    text,
)
from contextos.redact import sensitive_path_reason

SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
                       ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".contextos", ".next", "target"})


@dataclass
class ScanTarget:
    label: str
    path: Path | None  # None = stdin


@dataclass
class ScanReport:
    scanned: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)


def _collect(paths: list[str], max_files: int, report: ScanReport) -> list[ScanTarget]:
    targets: list[ScanTarget] = []
    for raw in paths:
        if raw == "-":
            targets.append(ScanTarget("<stdin>", None))
            continue
        path = Path(raw)
        if path.is_dir():
            for root, dirs, files in os.walk(path):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                targets.extend(ScanTarget(str(Path(root) / name), Path(root) / name) for name in sorted(files))
        elif path.is_file():
            targets.append(ScanTarget(str(path), path))
        else:
            report.skipped.append((raw, "not found"))
    if len(targets) > max_files:
        for extra in targets[max_files:]:
            report.skipped.append((extra.label, f"over the --max-files limit ({max_files})"))
        targets = targets[:max_files]
    return targets


def _read(target: ScanTarget, max_bytes: int, force: bool) -> tuple[str | None, str | None]:
    """``(content, skip_reason)``."""
    if target.path is None:
        data = sys.stdin.buffer.read(max_bytes + 1)
    else:
        reason = sensitive_path_reason(str(target.path)) or sensitive_path_reason(os.path.realpath(target.path))
        if reason and not force:
            return None, f"sensitive path, not uploaded ({reason}); use --force to scan it"
        try:
            if target.path.stat().st_size > max_bytes:
                return None, f"larger than {max_bytes} bytes"
            data = target.path.read_bytes()
        except OSError as exc:
            return None, f"unreadable ({exc.strerror})"
    if len(data) > max_bytes:
        return None, f"larger than {max_bytes} bytes"
    if b"\x00" in data[:8192]:
        return None, "binary file"
    return data.decode("utf-8", errors="replace"), None


def _hits(result: dict[str, Any]) -> list[dict[str, Any]]:
    return [h for h in items_of(result, "hits", "detections", "findings") if isinstance(h, dict)]


def _secrets(result: dict[str, Any]) -> list[Any]:
    value = result.get("secrets") or result.get("secret_matches") or []
    return value if isinstance(value, list) else []


def _print_result(label: str, result: dict[str, Any]) -> None:
    console = out()
    hits, secrets = _hits(result), _secrets(result)
    if not hits and not secrets:
        console.print(f"[green]✓[/green] {text(label)} — nothing detected")
        return
    console.print(f"[red]✗[/red] [bold]{text(label)}[/bold] — {len(hits)} detection(s), {len(secrets)} secret(s)")
    for hit in hits:
        technique = pick(hit, "technique")
        revealed = f" (revealed by {text(technique)} decoding)" if technique and technique != "plain" else ""
        console.print(f"    {severity(pick(hit, 'severity'))} [bold]{text(pick(hit, 'title', 'rule_id'))}[/bold] "
                      f"[dim]{text(pick(hit, 'rule_id'), '')}{revealed}[/dim]")
        if pick(hit, "explanation"):
            console.print(f"      {text(pick(hit, 'explanation'))}")
        if pick(hit, "excerpt"):
            console.print(f"      [dim]excerpt (redacted): {text(pick(hit, 'excerpt'))}[/dim]")
    for secret in secrets:
        kind = pick(secret, "type", "secret_type", default=secret) if isinstance(secret, dict) else secret
        console.print(f"    [red]secret[/red] {text(kind)} [dim](value never shown or stored)[/dim]")


def scan(
    paths: list[str] = typer.Argument(..., help="Files or directories to scan; '-' reads stdin."),
    source_type: str | None = typer.Option(None, "--source-type", help="How ContextOS should treat the content (default: file, or other for stdin)."),
    force: bool = typer.Option(False, "--force", help="Also upload files at sensitive paths (.env, keys, credentials)."),
    max_bytes: int = typer.Option(1_000_000, "--max-bytes", min=1, help="Skip files larger than this."),
    max_files: int = typer.Option(200, "--max-files", min=1, help="Scan at most this many files."),
    fail: bool = typer.Option(True, "--fail/--no-fail", help="Exit with code 3 when anything is detected."),
    as_json: bool = typer.Option(False, "--json", help="Print raw scan results as JSON."),
) -> None:
    """Detect prompt injection, credential-seeking instructions and secrets in files (nothing is stored)."""
    cfg = get_config()
    client = get_client(cfg)
    report = ScanReport()
    targets = _collect(paths, max_files, report)
    with cli_errors(cfg.url):
        for target in targets:
            content, skip = _read(target, max_bytes, force)
            if skip:
                report.skipped.append((target.label, skip))
                continue
            if not content or not content.strip():
                report.skipped.append((target.label, "empty"))
                continue
            kind = source_type or ("other" if target.path is None else "file")
            result = client.scan(content, kind)
            report.scanned.append((target.label, result if isinstance(result, dict) else {}))
    flagged = [label for label, result in report.scanned if _hits(result) or _secrets(result)]
    if as_json:
        print_json({"results": [{"target": label, **result} for label, result in report.scanned],
                    "skipped": [{"target": label, "reason": reason} for label, reason in report.skipped]})
    else:
        for label, result in report.scanned:
            _print_result(label, result)
        if report.skipped:
            table = Table(title="Skipped", title_justify="left")
            table.add_column("Target")
            table.add_column("Reason")
            for label, reason in report.skipped:
                table.add_row(text(label), text(reason))
            out().print(table)
        out().print(f"Scanned {len(report.scanned)} target(s): {len(flagged)} with detections, {len(report.skipped)} skipped.")
    if not report.scanned and not report.skipped:
        err().print("Nothing to scan.")
        raise typer.Exit(EXIT_ERROR)
    if flagged and fail:
        raise typer.Exit(EXIT_FINDINGS)
