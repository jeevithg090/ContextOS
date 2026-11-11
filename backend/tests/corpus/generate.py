"""Deterministic generator for the detection evaluation corpus.

    cd backend && .venv/bin/python -m tests.corpus.generate          # rewrite the committed files
    cd backend && .venv/bin/python -m tests.corpus.generate --check  # exit 1 if they are stale

Content samples (``corpus.jsonl``) combine ``INSTRUCTION_SEEDS`` / ``BENIGN_SEEDS`` with carriers
(``carriers.py``) and obfuscation transforms (``transforms.py``):

* every malicious seed x every applicable transform, in the ``plain`` carrier;
* every malicious seed x every other carrier, untransformed;
* ``CROSS_PER_SEED`` further (carrier, transform) pairs per malicious seed, drawn with a RNG seeded
  from the seed id, so obfuscation is also measured inside realistic documents;
* every benign seed x every carrier, untransformed (the obfuscation-looking hard negatives live in
  ``BENIGN_SEEDS`` with a ``lookalike_*`` kind).

Tool-request samples (``tool_requests.jsonl``) put each ``TOOL_REQUEST_SEEDS`` entry into the
argument shapes the integrations report: Claude Code (``Bash {command}``), a generic MCP server
(``mcp__terminal__run_command {cmd}``) and, for shell commands, a nested SDK payload.

The dev/test split is decided per *seed* (never per sample) by hashing the seed id, stratified by
family, so no seed contributes to both splits. Output is byte-for-byte reproducible.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from tests.corpus.carriers import CARRIERS
from tests.corpus.seeds import BENIGN_SEEDS, INSTRUCTION_SEEDS, TOOL_REQUEST_SEEDS
from tests.corpus.transforms import TRANSFORMS

CORPUS_DIR = Path(__file__).resolve().parent
CORPUS_PATH = CORPUS_DIR / "corpus.jsonl"
TOOL_CORPUS_PATH = CORPUS_DIR / "tool_requests.jsonl"

RNG_SEED = "contextos-detection-corpus-v1"
CROSS_PER_SEED = 4
SPLITS = ("dev", "test")

# Language of benign seeds that predate the optional "lang" key.
_BENIGN_LANG = {"ben-10": "de"}

# Destructive commands are reported as suspicious_tool_use by the TOOL-DESTRUCTIVE-* rules (their own
# semantics, matched by the "Deny destructive shell commands" policy), not as permission_escalation,
# which is reserved for widening the agent's own capabilities (config tampering, persistence,
# reverse shells). The seed file predates that split, so the expected category is set here.
_DESTRUCTIVE_PREFIX = "tr-destr-"
_DESTRUCTIVE_CATEGORY = "suspicious_tool_use"

_TOOL_CATEGORY = {"Bash": "shell", "Read": "file_read", "Write": "file_write", "WebFetch": "http"}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def assign_splits(groups: dict[str, list[str]]) -> dict[str, str]:
    """Seed id -> split. Within each group the seeds are ordered by hash and alternate dev/test,
    starting from a hash-chosen side, so every group is balanced and assignment is reproducible."""
    out: dict[str, str] = {}
    for group, ids in sorted(groups.items()):
        start = int(_digest(f"{RNG_SEED}|group|{group}"), 16) % 2
        for i, seed_id in enumerate(sorted(ids, key=lambda s: _digest(f"{RNG_SEED}|{s}"))):
            out[seed_id] = SPLITS[(start + i) % 2]
    return out


def _benign_group(seed: dict[str, str]) -> str:
    return "benign/lookalike" if seed["kind"].startswith("lookalike") else "benign/plain"


def content_splits() -> dict[str, str]:
    groups: dict[str, list[str]] = defaultdict(list)
    for s in INSTRUCTION_SEEDS:
        groups[s["family"]].append(s["id"])
    for s in BENIGN_SEEDS:
        groups[_benign_group(s)].append(s["id"])
    return assign_splits(groups)


def _sample(seed_id: str, text: str, *, label: str, family: str, category: str | None, carrier: str,
            technique: str, lang: str, split: str) -> dict[str, Any]:
    return {
        "id": f"{seed_id}|{carrier}|{technique}",
        "seed_id": seed_id,
        "text": text,
        "label": label,
        "family": family,
        "expected_category": category,
        "carrier": carrier,
        "technique": technique,
        "lang": lang,
        "split": split,
    }


def _malicious_samples(seed: dict[str, str], split: str) -> list[dict[str, Any]]:
    text, lang = seed["text"], seed["lang"]
    transformed = {name: fn(text, lang) for name, fn in TRANSFORMS.items()}
    applicable = [name for name, value in transformed.items() if value is not None]
    pairs: list[tuple[str, str]] = [("plain", t) for t in applicable]
    pairs += [(c, "none") for c in CARRIERS if c != "plain"]
    cross = [(c, t) for c in CARRIERS if c != "plain" for t in applicable if t != "none"]
    rng = random.Random(f"{RNG_SEED}|{seed['id']}")
    pairs += rng.sample(cross, min(CROSS_PER_SEED, len(cross)))
    out = []
    for carrier, technique in pairs:
        payload = transformed[technique]
        assert payload is not None
        out.append(_sample(seed["id"], CARRIERS[carrier](payload), label="malicious", family=seed["family"],
                           category=seed["category"], carrier=carrier, technique=technique, lang=lang,
                           split=split))
    return out


def build_content_corpus() -> list[dict[str, Any]]:
    splits = content_splits()
    samples: list[dict[str, Any]] = []
    for seed in INSTRUCTION_SEEDS:
        samples += _malicious_samples(seed, splits[seed["id"]])
    for seed in BENIGN_SEEDS:
        lang = seed.get("lang") or _BENIGN_LANG.get(seed["id"], "en")
        for carrier, wrap in CARRIERS.items():
            samples.append(_sample(seed["id"], wrap(seed["text"]), label="benign", family=f"benign/{seed['kind']}",
                                   category=None, carrier=carrier, technique="none", lang=lang,
                                   split=splits[seed["id"]]))
    return samples


# --------------------------------------------------------------------------- tool requests


def _tool_shapes(tool: str, arguments: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """(shape, tool name, arguments) variants of one request as different integrations report it."""
    shapes: list[tuple[str, str, dict[str, Any]]] = [("claude_code", tool, dict(arguments))]
    if tool == "Bash":
        cmd = arguments["command"]
        shapes.append(("mcp", "mcp__terminal__run_command", {"cmd": cmd}))
        shapes.append(("sdk_nested", "run_shell", {"request": {"script": cmd, "timeout_s": 60}}))
    elif tool == "Read":
        shapes.append(("mcp", "mcp__filesystem__read_file", {"path": arguments["file_path"]}))
    elif tool == "Write":
        shapes.append(("mcp", "mcp__filesystem__write_file",
                       {"path": arguments["file_path"], "content": arguments["content"]}))
    elif tool == "WebFetch":
        shapes.append(("mcp", "mcp__fetch__fetch", {"url": arguments["url"], "max_length": 5000}))
    return shapes


def _tool_expected_category(seed: dict[str, Any]) -> str | None:
    if not seed["malicious"]:
        return None
    if str(seed["id"]).startswith(_DESTRUCTIVE_PREFIX):
        return _DESTRUCTIVE_CATEGORY
    return str(seed["category"])


def build_tool_corpus() -> list[dict[str, Any]]:
    groups: dict[str, list[str]] = defaultdict(list)
    for seed in TOOL_REQUEST_SEEDS:
        groups[_tool_expected_category(seed) or "benign"].append(str(seed["id"]))
    splits = assign_splits(groups)
    samples: list[dict[str, Any]] = []
    for seed in TOOL_REQUEST_SEEDS:
        seed_id, tool = str(seed["id"]), str(seed["tool"])
        expected = _tool_expected_category(seed)
        for shape, name, args in _tool_shapes(tool, dict(seed["arguments"])):  # type: ignore[arg-type]
            samples.append({
                "id": f"{seed_id}|{shape}",
                "seed_id": seed_id,
                "tool": name,
                "category": _TOOL_CATEGORY[tool],
                "arguments": args,
                "label": "malicious" if seed["malicious"] else "benign",
                "family": expected or "benign",
                "expected_category": expected,
                "shape": shape,
                "split": splits[seed_id],
            })
    return samples


# --------------------------------------------------------------------------- serialisation


def to_jsonl(samples: list[dict[str, Any]]) -> str:
    # ensure_ascii keeps invisible / tag / homoglyph characters visible as escapes in the file.
    return "".join(json.dumps(s, ensure_ascii=True, sort_keys=True) + "\n" for s in samples)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def rendered() -> dict[Path, str]:
    return {CORPUS_PATH: to_jsonl(build_content_corpus()), TOOL_CORPUS_PATH: to_jsonl(build_tool_corpus())}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the detection evaluation corpus.")
    parser.add_argument("--check", action="store_true", help="exit 1 if the committed files are out of date")
    args = parser.parse_args(argv)
    stale = []
    for path, content in rendered().items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == content:
            continue
        if args.check:
            stale.append(path.name)
        else:
            path.write_text(content, encoding="utf-8")
            print(f"wrote {path.relative_to(CORPUS_DIR.parent.parent)} ({content.count(chr(10))} samples)")
    if stale:
        print("stale: " + ", ".join(stale) + " (run python -m tests.corpus.generate)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
