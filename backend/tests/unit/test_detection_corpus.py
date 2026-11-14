"""Regression guard for the detection evaluation corpus (see docs/DETECTION_EVALUATION.md).

* the committed corpus is schema-valid, inert (reserved destinations only) and reproducible;
* held-out (test split) precision / recall stay at or above floors set just below the measured
  numbers, and the dev split (used for tuning) stays at its tuned level;
* benign hard negatives never reach high severity, except the pinned, documented blind spots —
  the pin is exact, so fixing one of them (or adding a new one) fails until the doc is updated.

Pure engine tests: the real detector over committed text, no DB, no network, nothing executed.
"""

from __future__ import annotations

import re
from collections import defaultdict
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit

import pytest

from app.domain.enums import SEVERITY_RANK, FindingCategory, Severity
from tests.corpus import metrics
from tests.corpus.carriers import CARRIERS
from tests.corpus.generate import CORPUS_PATH, TOOL_CORPUS_PATH, load_jsonl, rendered
from tests.corpus.transforms import TRANSFORMS

# Floors: measured test-split numbers (docs/DETECTION_EVALUATION.md) minus a small margin.
CONTENT_TEST_FLOORS = {"precision": 0.96, "recall": 0.92, "category_accuracy": 0.92}
# The tool-request set is small (46 test samples). Its only false positives (`echo $PATH`, tr-ok-08,
# three argument shapes) were fixed after they were seen on the test split, so its 1.000 precision is
# not a clean held-out estimate (disclosed in docs/DETECTION_EVALUATION.md).
TOOL_TEST_FLOORS = {"precision": 0.95, "recall": 0.89, "category_accuracy": 0.99}
DEV_FLOORS = {"precision": 0.99, "recall": 0.99, "category_accuracy": 0.99}

# Benign samples that still reach high severity. Each is a documented blind spot found on the
# held-out split and deliberately not tuned away (see "Known blind spots" in the doc).
KNOWN_HIGH_SEVERITY_BENIGN = {
    # an HTML comment quoted inside a security explainer: the extracted comment loses its context
    *(f"ben-11|{c}|none" for c in CARRIERS if c != "html_comment"),
    # the CSS property name "display" in style="display:none" reads as a verb next to ".env"
    "ben-44|html_display_none|none",
}

_CATEGORIES = {c.value for c in FindingCategory}
_HIGH = SEVERITY_RANK[Severity.HIGH.value]
_RESERVED_SUFFIXES = (".example", ".invalid", ".test", "example.com", "localhost")
_DOC_NETS = [ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


@pytest.fixture(scope="module")
def content() -> list[dict]:
    return load_jsonl(CORPUS_PATH)


@pytest.fixture(scope="module")
def tools() -> list[dict]:
    return load_jsonl(TOOL_CORPUS_PATH)


@pytest.fixture(scope="module")
def content_outcomes(content) -> list[metrics.Outcome]:
    return metrics.run_content(content)


@pytest.fixture(scope="module")
def tool_outcomes(tools) -> list[metrics.Outcome]:
    return metrics.run_tools(tools)


def _split(outcomes: list[metrics.Outcome], split: str) -> list[metrics.Outcome]:
    return [o for o in outcomes if o.sample["split"] == split]


# --------------------------------------------------------------------------- corpus integrity


def test_committed_corpus_is_reproducible():
    for path, expected in rendered().items():
        assert path.read_text(encoding="utf-8") == expected, (
            f"{path.name} differs from the generator output; run `python -m tests.corpus.generate`"
        )


def test_corpus_size_and_balance(content):
    assert len(content) >= 600
    assert sum(s["label"] == "benign" for s in content) >= 150
    for split in ("dev", "test"):
        part = [s for s in content if s["split"] == split]
        assert sum(s["label"] == "malicious" for s in part) >= 200, split
        assert sum(s["label"] == "benign" for s in part) >= 100, split
        malicious = [s for s in part if s["label"] == "malicious"]
        assert {s["carrier"] for s in malicious} == set(CARRIERS), split
        assert {s["technique"] for s in malicious} == set(TRANSFORMS), split


def test_content_samples_are_schema_valid(content):
    keys = {
        "id",
        "seed_id",
        "text",
        "label",
        "family",
        "expected_category",
        "carrier",
        "technique",
        "lang",
        "split",
    }
    ids = [s["id"] for s in content]
    assert len(ids) == len(set(ids))
    for s in content:
        assert set(s) == keys, s["id"]
        assert isinstance(s["text"], str) and s["text"].strip(), s["id"]
        assert s["carrier"] in CARRIERS and s["technique"] in TRANSFORMS, s["id"]
        assert s["split"] in {"dev", "test"} and re.fullmatch(r"[a-z]{2}", s["lang"]), s["id"]
        assert s["id"] == f"{s['seed_id']}|{s['carrier']}|{s['technique']}"
        if s["label"] == "malicious":
            assert s["expected_category"] in _CATEGORIES, s["id"]
            assert not s["family"].startswith("benign"), s["id"]
        else:
            assert s["label"] == "benign", s["id"]
            assert s["expected_category"] is None and s["family"].startswith("benign/"), s["id"]
            assert s["technique"] == "none", s["id"]  # benign text is never obfuscated by the generator


def test_tool_samples_are_schema_valid(tools):
    keys = {
        "id",
        "seed_id",
        "tool",
        "category",
        "arguments",
        "label",
        "family",
        "expected_category",
        "shape",
        "split",
    }
    assert len({s["id"] for s in tools}) == len(tools)
    for s in tools:
        assert set(s) == keys, s["id"]
        assert isinstance(s["arguments"], dict) and s["arguments"], s["id"]
        assert s["split"] in {"dev", "test"} and s["shape"] in {"claude_code", "mcp", "sdk_nested"}, s["id"]
        if s["label"] == "malicious":
            assert s["expected_category"] in _CATEGORIES, s["id"]
        else:
            assert s["label"] == "benign" and s["expected_category"] is None, s["id"]


@pytest.mark.parametrize("corpus_path", [CORPUS_PATH, TOOL_CORPUS_PATH])
def test_no_seed_appears_in_both_splits(corpus_path):
    splits: dict[str, set[str]] = defaultdict(set)
    for s in load_jsonl(corpus_path):
        splits[s["seed_id"]].add(s["split"])
    leaked = {seed: sp for seed, sp in splits.items() if len(sp) > 1}
    assert not leaked, leaked


def _hosts(text: str) -> list[str]:
    return [urlsplit(u).hostname or "" for u in re.findall(r"https?://[^\s\"'<>)\\]+", text)] + re.findall(
        r"@((?:\d{1,3}\.){3}\d{1,3})", text
    )


def _reserved(host: str) -> bool:
    try:
        return any(ip_address(host) in net for net in _DOC_NETS)
    except ValueError:
        return host.endswith(_RESERVED_SUFFIXES)


def test_malicious_samples_only_use_reserved_destinations(content, tools):
    """The corpus is inert: every destination an attack names is a reserved domain or doc IP."""
    for s in content:
        if s["label"] == "malicious" and s["technique"] == "none":
            for host in _hosts(s["text"]):
                assert _reserved(host), (s["id"], host)
    for s in tools:
        if s["label"] == "malicious":
            for host in _hosts(str(s["arguments"])):
                assert _reserved(host), (s["id"], host)


@pytest.mark.parametrize("carrier", sorted(CARRIERS))
def test_carriers_alone_raise_no_alert(carrier):
    """Carrier boilerplate never causes a hit on its own, so results measure the payload."""
    from app.engines.detection import analyze_content

    result = analyze_content(CARRIERS[carrier]("The weather is mild today and the build is green."))
    assert not metrics.qualifying(result.hits), [h.rule_id for h in result.hits]


# --------------------------------------------------------------------------- metric floors


def test_content_test_split_meets_floors(content_outcomes):
    c = metrics.confusion(_split(content_outcomes, "test"))
    assert c["precision"] >= 0.90 and c["recall"] >= 0.85
    for key, floor in CONTENT_TEST_FLOORS.items():
        assert c[key] >= floor, (key, c)


def test_tool_request_test_split_meets_floors(tool_outcomes):
    c = metrics.confusion(_split(tool_outcomes, "test"))
    for key, floor in TOOL_TEST_FLOORS.items():
        assert c[key] >= floor, (key, c)


@pytest.mark.parametrize("which", ["content", "tools"])
def test_dev_split_stays_at_tuned_level(which, content_outcomes, tool_outcomes):
    outcomes = content_outcomes if which == "content" else tool_outcomes
    c = metrics.confusion(_split(outcomes, "dev"))
    for key, floor in DEV_FLOORS.items():
        assert c[key] >= floor, (key, c)


def test_every_obfuscation_technique_keeps_working(content_outcomes):
    """Per-technique recall over both splits: a normalisation regression shows up here first."""
    by_technique = metrics.breakdown(
        [o for o in content_outcomes if o.malicious], lambda o: o.sample["technique"]
    )
    for technique, c in by_technique.items():
        assert c["recall"] >= 0.80, (technique, c)


def test_benign_hard_negatives_never_reach_high_severity_except_pinned(content_outcomes, tool_outcomes):
    high = {
        o.sample["id"]
        for o in content_outcomes + tool_outcomes
        if not o.malicious and SEVERITY_RANK.get(o.max_severity or "", 0) >= _HIGH
    }
    assert high == KNOWN_HIGH_SEVERITY_BENIGN, (
        f"new: {sorted(high - KNOWN_HIGH_SEVERITY_BENIGN)}; fixed (update the pin and the doc): "
        f"{sorted(KNOWN_HIGH_SEVERITY_BENIGN - high)}"
    )


def test_obfuscation_lookalikes_raise_no_alert(content_outcomes):
    """Encoded images/data, minified JS, emoji joiners, non-Latin text, spaced and leet-looking words."""
    flagged = [
        o.sample["id"]
        for o in content_outcomes
        if o.sample["family"].startswith("benign/lookalike")
        and o.predicted
        and o.sample["id"] not in KNOWN_HIGH_SEVERITY_BENIGN
    ]
    assert not flagged, flagged


def test_evaluator_report_shape():
    from tests.corpus.evaluate import evaluate, render_text

    result = evaluate("test", worst=3)
    assert result["prediction_rule"] == "any hit with severity >= medium"
    for section in ("content", "tool_requests"):
        rep = result[section]
        assert set(rep) == {
            "overall",
            "breakdowns",
            "worst_false_positives",
            "worst_false_negatives",
            "miscategorised",
        }
        assert len(rep["worst_false_negatives"]) <= 3
    assert set(result["content"]["breakdowns"]) == {"family", "technique", "carrier", "language"}
    text = render_text(result)
    assert "precision" in text and "worst false positives" in text
