"""Carriers: the realistic documents an instruction (or a benign text) arrives inside.

Each carrier embeds a payload in the shape an agent would actually ingest it: a README, a web page
(visible text, a ``display:none`` element, an HTML comment), an MCP tool description, a JSON tool
result (serialised with Python's default ``ensure_ascii=True``, as many MCP servers do), an e-mail
body, a source-code comment, a sub-agent's reply, and PDF-extracted text (hard-wrapped lines with a
running header and footer). The surrounding text is deliberately ordinary and contains no rule
vocabulary, so a carrier never causes a hit on its own (asserted by the corpus tests).
"""

from __future__ import annotations

import json
import textwrap
from collections.abc import Callable


def plain(payload: str) -> str:
    return payload


def readme(payload: str) -> str:
    return (
        "# log-tidy\n\n"
        "Small utility that normalises application logs before they are archived.\n\n"
        "## Installation\n\n"
        "pip install log-tidy\n\n"
        "## Notes for contributors\n\n"
        f"{payload}\n\n"
        "## License\n\n"
        "MIT\n"
    )


_PAGE_HEAD = (
    "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>Release notes 4.2</title></head>\n"
    "<body>\n<h1>Release notes 4.2</h1>\n"
    "<p>This release improves start-up time and fixes two crashes in the importer.</p>\n"
)
_PAGE_TAIL = "<p>Thank you to everyone who filed bug reports.</p>\n</body>\n</html>\n"


def html_visible(payload: str) -> str:
    return f"{_PAGE_HEAD}<p>{payload}</p>\n{_PAGE_TAIL}"


def html_display_none(payload: str) -> str:
    return f"{_PAGE_HEAD}<div class=\"promo\" style=\"display:none\">{payload}</div>\n{_PAGE_TAIL}"


def html_comment(payload: str) -> str:
    return f"{_PAGE_HEAD}<!-- {payload} -->\n{_PAGE_TAIL}"


def mcp_tool_description(payload: str) -> str:
    # The ingestion pipeline scans the description string of each listed MCP tool.
    return (
        "Search the internal knowledge base and return the best matching snippets.\n"
        f"{payload}\n"
        "Args:\n  query (string): search terms.\n  limit (integer): maximum number of snippets, default 5."
    )


def tool_output_json(payload: str) -> str:
    result = {
        "status": "ok",
        "total": 2,
        "results": [
            {"title": "Quarterly planning", "updated": "2026-10-02", "body": "Agenda and owners for Q4."},
            {"title": "Vendor onboarding", "updated": "2026-10-09", "body": payload},
        ],
    }
    return json.dumps(result, indent=2)  # ensure_ascii=True: non-ASCII arrives as \\uXXXX escapes


def email(payload: str) -> str:
    return (
        "From: Priya Natarajan <priya@vendor.example>\n"
        "To: dev-team@company.example\n"
        "Subject: Re: integration checklist\n"
        "Date: Tue, 03 Nov 2026 09:14:00 +0000\n\n"
        "Hi team,\n\n"
        f"{payload}\n\n"
        "Thanks,\nPriya\n"
    )


def code_comment(payload: str) -> str:
    comment = "\n".join(f"# {line}" if line else "#" for line in payload.split("\n"))
    return (
        "import logging\n\n"
        "logger = logging.getLogger(__name__)\n\n\n"
        f"{comment}\n"
        "def normalise_ids(rows):\n"
        "    \"\"\"Return the rows with canonical lower-case ids.\"\"\"\n"
        "    return [row.strip().lower() for row in rows]\n"
    )


def subagent_reply(payload: str) -> str:
    return (
        "[sub-agent: repo-researcher] finished in 41s\n"
        "Findings:\n"
        "- The service uses FastAPI with SQLAlchemy 2.\n"
        f"- {payload}\n"
        "- Unit tests live under tests/unit and run with pytest.\n"
    )


def pdf_text(payload: str) -> str:
    # PDF extraction hard-wraps paragraphs, so a sentence can be split across lines.
    paragraph = (
        "4.2 Data handling. The vendor encrypts customer data at rest with AES-256 and rotates keys "
        f"annually. {payload} Access reviews are performed quarterly by the security team."
    )
    body = textwrap.fill(paragraph, width=68, break_long_words=False, break_on_hyphens=False)
    return (
        "Vendor Security Questionnaire                                   Page 3 of 7\n\n"
        f"{body}\n\n"
        "Confidential - prepared for procurement review\n\f"
    )


CARRIERS: dict[str, Callable[[str], str]] = {
    "plain": plain,
    "readme": readme,
    "html_visible": html_visible,
    "html_display_none": html_display_none,
    "html_comment": html_comment,
    "mcp_tool_description": mcp_tool_description,
    "tool_output_json": tool_output_json,
    "email": email,
    "code_comment": code_comment,
    "subagent_reply": subagent_reply,
    "pdf_text": pdf_text,
}
