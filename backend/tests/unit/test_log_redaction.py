"""Both log formatters redact every finished line, including extra fields and tracebacks."""

from __future__ import annotations

import logging

import pytest

from app.core.logging import JsonFormatter, KeyValueFormatter

TOKEN = "ghp_" + "Zq8RtY2uV4wX6yA1bC3dE5fG7hJ9kL0mN2pQ"


@pytest.mark.parametrize("formatter", [JsonFormatter(), KeyValueFormatter()])
def test_formatters_redact_messages_extras_and_tracebacks(formatter):
    try:
        raise ValueError(f"could not parse {TOKEN}")
    except ValueError:
        import sys

        exc_info = sys.exc_info()
    record = logging.LogRecord("contextos.test", logging.ERROR, __file__, 1, "failed for %s", (TOKEN,), exc_info)
    record.detail = f"Authorization: Bearer {TOKEN}"
    line = formatter.format(record)
    assert TOKEN not in line
    assert "[REDACTED:" in line and "ValueError" in line  # the line is still useful


def test_clean_lines_are_unchanged():
    record = logging.LogRecord("contextos.test", logging.INFO, __file__, 1, "event.ingested", (), None)
    record.org_id = "org_01ABC"
    assert KeyValueFormatter().format(record).endswith("contextos.test: event.ingested org_id=org_01ABC")
