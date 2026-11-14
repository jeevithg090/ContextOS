"""Evaluate the detection engine on the committed corpus.

    cd backend && .venv/bin/python -m tests.corpus.evaluate                 # both splits
    cd backend && .venv/bin/python -m tests.corpus.evaluate --split test    # held-out numbers
    cd backend && .venv/bin/python -m tests.corpus.evaluate --split dev --json

Content samples go through ``analyze_content``; tool-request samples through ``analyze_tool_request``.
A sample counts as predicted malicious when any hit has severity >= medium (see ``metrics.py``).
Nothing is executed and no network request is made: the corpus is inert text.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from tests.corpus import metrics
from tests.corpus.generate import CORPUS_PATH, TOOL_CORPUS_PATH, load_jsonl, rendered


def _filter(samples: list[dict[str, Any]], split: str) -> list[dict[str, Any]]:
    return samples if split == "all" else [s for s in samples if s["split"] == split]


def evaluate(split: str = "all", *, worst: int = 10) -> dict[str, Any]:
    content = _filter(load_jsonl(CORPUS_PATH), split)
    tools = _filter(load_jsonl(TOOL_CORPUS_PATH), split)
    return {
        "split": split,
        "prediction_rule": f"any hit with severity >= {metrics.PREDICTION_MIN_SEVERITY}",
        "content": metrics.report(
            metrics.run_content(content), dimensions=metrics.CONTENT_DIMENSIONS, worst=worst
        ),
        "tool_requests": metrics.report(
            metrics.run_tools(tools), dimensions=metrics.TOOL_DIMENSIONS, worst=worst
        ),
    }


# --------------------------------------------------------------------------- text rendering


def _fmt(value: float | None) -> str:
    return "  n/a" if value is None else f"{value:.3f}"


def _summary(name: str, c: dict[str, Any]) -> str:
    return (
        f"{name}: n={c['n']} ({c['malicious']} malicious, {c['benign']} benign)\n"
        f"  precision {_fmt(c['precision'])}  recall {_fmt(c['recall'])}  F1 {_fmt(c['f1'])}  "
        f"FP {c['fp']}  FN {c['fn']}  FPR {_fmt(c['false_positive_rate'])}  "
        f"category accuracy {_fmt(c['category_accuracy'])}"
    )


def _table(title: str, rows: dict[str, dict[str, Any]]) -> list[str]:
    width = max([len(title)] + [len(k) for k in rows]) + 2
    lines = [f"  {title:<{width}}{'n':>5}{'mal':>5}{'TP':>5}{'FN':>5}{'FP':>5}  recall  FPR    cat-acc"]
    for key, c in rows.items():
        lines.append(
            f"  {key:<{width}}{c['n']:>5}{c['malicious']:>5}{c['tp']:>5}{c['fn']:>5}{c['fp']:>5}  "
            f"{_fmt(c['recall'])}   {_fmt(c['false_positive_rate'])}  {_fmt(c['category_accuracy'])}"
        )
    return lines


def _rows(title: str, rows: list[dict[str, Any]]) -> list[str]:
    if not rows:
        return [f"  {title}: none"]
    lines = [f"  {title}:"]
    for r in rows:
        low = f"  below threshold: {', '.join(r['low_rule_ids'])}" if r["low_rule_ids"] else ""
        lines.append(
            f"    {r['id']}  max={r['max_severity'] or '-'}  rules={','.join(r['rule_ids']) or '-'}"
            f"  categories={','.join(r['categories']) or '-'}  expected={r['expected_category'] or '-'}{low}"
        )
    return lines


def render_text(result: dict[str, Any]) -> str:
    out = [
        f"ContextOS detection evaluation  split={result['split']}  prediction: {result['prediction_rule']}",
        "",
    ]
    for section, label in (
        ("content", "Content (analyze_content)"),
        ("tool_requests", "Tool requests (analyze_tool_request)"),
    ):
        rep = result[section]
        out.append(_summary(label, rep["overall"]))
        for dim, rows in rep["breakdowns"].items():
            out += _table(dim, rows)
        out += _rows("worst false positives", rep["worst_false_positives"])
        out += _rows("worst false negatives", rep["worst_false_negatives"])
        out += _rows("detected with an unexpected category", rep["miscategorised"])
        out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the detection engine on the corpus.")
    parser.add_argument("--split", choices=["dev", "test", "all"], default="all")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    parser.add_argument("--worst", type=int, default=10, help="how many worst FP/FN samples to list")
    args = parser.parse_args(argv)
    stale = [
        p.name
        for p, content in rendered().items()
        if not p.exists() or p.read_text(encoding="utf-8") != content
    ]
    if stale:
        print(f"corpus is stale ({', '.join(stale)}); run python -m tests.corpus.generate", file=sys.stderr)
        return 2
    result = evaluate(args.split, worst=args.worst)
    print(json.dumps(result, indent=2) if args.json else render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
