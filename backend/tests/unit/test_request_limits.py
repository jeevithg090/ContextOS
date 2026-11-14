"""``json_depth_exceeds``: the pre-parse JSON nesting check of ``RequestLimitsMiddleware`` (pure)."""

from __future__ import annotations

import json
import time

import pytest

from app.api.middleware import MAX_JSON_DEPTH, json_depth_exceeds


def _nested(depth: int, kind: str = "{") -> bytes:
    value: object = 1
    for _ in range(depth):
        value = {"k": value} if kind == "{" else [value]
    return json.dumps(value).encode()


@pytest.mark.parametrize("kind", ["{", "["])
def test_limit_is_exact(kind):
    assert not json_depth_exceeds(_nested(MAX_JSON_DEPTH, kind))
    assert json_depth_exceeds(_nested(MAX_JSON_DEPTH + 1, kind))


def test_brackets_and_escaped_quotes_inside_strings_do_not_count():
    tricky = json.dumps({"a": "[" * 1000 + '\\"' + "{" * 1000, "b": ['"]]]]', "\\", "x"]}).encode()
    assert not json_depth_exceeds(tricky, limit=3)


def test_siblings_do_not_add_up():
    wide = json.dumps([[1]] * 10_000).encode()
    assert not json_depth_exceeds(wide, limit=2)
    assert json_depth_exceeds(wide, limit=1)


@pytest.mark.parametrize(
    "body",
    [
        b'"' * 2_000_000,  # many empty strings
        b'"' + b"a" * 2_000_000,  # one unterminated string
        b'"' + b"\\a" * 700_000,  # escapes without a closing quote
        b'"a' * 1_000_000,  # alternating quotes
        b",[]" * 600_000,  # many shallow brackets
    ],
)
def test_adversarial_bodies_are_scanned_in_linear_time(body):
    started = time.perf_counter()
    json_depth_exceeds(body)
    assert time.perf_counter() - started < 2.0  # ~0.05 s on a laptop; generous for loaded CI machines
