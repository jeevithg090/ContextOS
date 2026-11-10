"""Identifier generation.

IDs are prefixed, time-sortable ULID-style strings, e.g. ``agt_01JC9Z...``. The prefix makes IDs
self-describing in logs, URLs and evidence exports; the ULID body sorts by creation time.
"""

from __future__ import annotations

import os
import time

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

PREFIXES: dict[str, str] = {
    "organization": "org",
    "user": "usr",
    "membership": "mem",
    "api_key": "key",
    "auth_session": "ses",
    "agent": "agt",
    "agent_session": "asn",
    "agent_relationship": "arl",
    "context_source": "src",
    "context_item": "ctx",
    "provenance_edge": "edg",
    "tool": "tol",
    "tool_invocation": "inv",
    "destination": "dst",
    "trust_rule": "trl",
    "policy": "pol",
    "policy_decision": "dec",
    "approval": "apr",
    "finding": "fnd",
    "incident": "inc",
    "incident_activity": "iac",
    "audit_event": "aud",
    "ingested_event": "evt",
    "integration": "int",
    "simulation_run": "sim",
    "board": "brd",
    "board_column": "col",
    "task": "tsk",
    "task_label": "lbl",
    "task_assignment": "tas",
    "task_comment": "tcm",
    "task_dependency": "tdp",
    "task_attachment": "tat",
    "task_activity": "tac",
    "task_context_ref": "tcr",
    "generated_prompt": "gpr",
    "context_pack": "cpk",
    "prompt_template": "ptm",
    "fix_attempt": "fix",
    "verification_run": "ver",
}


def _ulid() -> str:
    ts = int(time.time() * 1000)
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ts << 80) | rand
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def new_id(kind: str) -> str:
    """Return a new prefixed id. ``kind`` is a key of ``PREFIXES`` or a raw 3-letter prefix."""
    prefix = PREFIXES.get(kind, kind)
    return f"{prefix}_{_ulid()}"
