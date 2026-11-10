"""Deterministic task breakdown: split a task into editable subtask drafts.

``decompose(task)`` picks a plan template from the task type, the linked finding category and a
few unambiguous keywords (for example MCP interception work), then instantiates it with the
parent's title. Output is structured data the UI lets users edit before anything is created;
``depends_on`` holds indexes of *earlier* drafts only, so the graph is acyclic by construction.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.workspace.text import inline

_TITLE_CHARS = 120
_MCP_INTERCEPT = re.compile(r"\bmcp\b.*\b(intercept\w*|gateway|tools/call|bypass\w*|proxy)\b"
                            r"|\b(intercept\w*|gateway|tools/call|bypass\w*|proxy)\b.*\bmcp\b", re.IGNORECASE | re.DOTALL)

_SECURITY_CATEGORIES = {
    "prompt_injection": "prompt_injection", "instruction_override": "prompt_injection",
    "secret_exposure": "data_exposure", "credential_access": "data_exposure", "exfiltration": "data_exposure",
    "dangerous_permissions": "agent_misconfiguration", "permission_escalation": "agent_misconfiguration",
}


@dataclass
class SubtaskDraft:
    title: str
    description: str
    task_type: str
    acceptance_criteria: list[str] = field(default_factory=list)
    testing_requirements: list[str] = field(default_factory=list)
    depends_on: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "task_type": self.task_type,
            "acceptance_criteria": list(self.acceptance_criteria),
            "testing_requirements": list(self.testing_requirements),
            "depends_on": list(self.depends_on),
        }


# Each step: (title template, description, task_type or None to inherit, criteria, tests, depends_on).
_Step = tuple[str, str, str | None, tuple[str, ...], tuple[str, ...], tuple[int, ...]]

_PLANS: dict[str, tuple[_Step, ...]] = {
    "security_vulnerability": (
        ("Reproduce with a failing test: {t}",
         "Write an automated test that demonstrates the vulnerability using the recorded evidence pattern.", None,
         ("The test fails on the current code for the documented reason.",), ("Failing regression test committed.",), ()),
        ("Identify root cause: {t}",
         "Trace the vulnerable path and confirm the root cause with evidence; list every entry point that reaches it.",
         None, ("Root cause and affected entry points documented with file references.",), (), (0,)),
        ("Implement fix: {t}", "Fix the root cause so the check fails closed; avoid unrelated changes.", None,
         ("The reproduction test passes.", "No existing security check is weakened."), ("Related unit tests pass.",),
         (1,)),
        ("Add regression tests: {t}", "Extend tests so the vulnerability cannot return unnoticed.", None,
         ("Regression tests cover every affected entry point.",), ("Unit and integration tests for each entry point.",),
         (2,)),
        ("Add adversarial security tests: {t}",
         "Test plausible bypasses: encoding and case variants, traversal, oversized or malformed input.", None,
         ("Every tested bypass variant is rejected.",), ("Adversarial test cases with fake credentials only.",), (2,)),
        ("Document and verify: {t}",
         "Update docs and record a verification run with the test evidence.", "task",
         ("Docs describe the fixed behaviour honestly (enforced / advisory / observed).",
          "A passed verification run is recorded."), ("Full test suite run; counts reported.",), (3, 4)),
    ),
    "mcp_interception": (
        ("Map the MCP interception path: {t}",
         "Document how tools/call requests flow through the MCP gateway to ContextOS and the upstream server.", None,
         ("Every path from client to upstream tool server is documented.",), (), ()),
        ("Reproduce the bypass with an integration test: {t}",
         "Show a tools/call that reaches the upstream server without a ContextOS decision.", None,
         ("The test fails on the current code.",), ("Integration test against a local stub MCP server.",), (0,)),
        ("Enforce the decision at tools/call: {t}",
         "Request a decision before forwarding and honour DENY and approval outcomes.", None,
         ("Denied calls never reach the upstream server.", "Approval-required calls wait for a decision."),
         ("Unit tests for allow, deny and approval outcomes.",), (1,)),
        ("Fail closed when ContextOS is unavailable: {t}",
         "Apply the configured fail mode (fail_closed by default) on timeouts and server errors.", None,
         ("With fail_closed, calls are refused when ContextOS is unreachable.",),
         ("Tests for timeout, 5xx and malformed decision responses.",), (2,)),
        ("Add adversarial interception tests: {t}",
         "Cover batched requests, renamed tools, malformed JSON-RPC and alternate methods that invoke tools.", None,
         ("No tested variant reaches the upstream server without a decision.",), ("Adversarial integration tests.",),
         (2,)),
        ("Document enforcement and verify: {t}",
         "State the enforcement mode honestly in docs and record a verification run.", "task",
         ("Docs say 'enforced' only for calls that pass through the gateway.", "A passed verification run is recorded."),
         ("Full integration suite run; counts reported.",), (3, 4)),
    ),
    "prompt_injection": (
        ("Reproduce the injection: {t}", "Replay the recorded payload through the same ingestion path in a test.", None,
         ("The test shows the payload influencing agent behaviour or classification.",), ("Failing test.",), ()),
        ("Trace the trust boundary: {t}",
         "Find where untrusted content enters the prompt and why it is not treated as data.", None,
         ("The missing or broken boundary is identified with file references.",), (), (0,)),
        ("Enforce the trust boundary: {t}", "Label or isolate untrusted content so it cannot act as instructions.", None,
         ("The reproduction test passes.",), ("Unit tests for the boundary.",), (1,)),
        ("Adversarial injection corpus: {t}",
         "Add variants: encodings, other languages, nesting in tool output, split payloads.", None,
         ("All variants are detected or neutralised.",), ("Corpus-driven tests.",), (2,)),
        ("Document and verify: {t}", "Update docs and record a verification run.", "task",
         ("A passed verification run is recorded.",), ("Full test suite run; counts reported.",), (3,)),
    ),
    "data_exposure": (
        ("Locate the exposure path: {t}", "Identify where the secret or sensitive data leaves its boundary.", None,
         ("Exposure channel(s) documented.",), (), ()),
        ("Redact at the boundary: {t}", "Apply redaction before storage, logging or forwarding on every channel.", None,
         ("No raw secret is stored, logged or forwarded.",), ("Tests with fake credentials in provider formats.",), (0,)),
        ("Coordinate credential rotation: {t}",
         "A human with access must rotate any exposed credential; agents must not rotate production secrets.", "task",
         ("Rotation confirmed by the credential owner.",), (), (0,)),
        ("Regression tests: {t}", "Prove every output channel stays redacted.", None,
         ("Tests cover responses, logs and exports.",), ("Unit and integration tests.",), (1,)),
        ("Verify: {t}", "Record a verification run with test evidence.", "task",
         ("A passed verification run is recorded.",), ("Full test suite run; counts reported.",), (2, 3)),
    ),
    "agent_misconfiguration": (
        ("Audit current configuration: {t}", "List the agent's tools, scopes, paths and trust settings.", None,
         ("Current configuration documented.",), (), ()),
        ("Define least-privilege configuration: {t}", "Specify only what the agent's tasks require.", None,
         ("Each permission is justified by a task need.",), (), (0,)),
        ("Apply the configuration: {t}", "Change the configuration and policies to the defined scope.", None,
         ("The agent can no longer use removed capabilities.",), ("Policy tests for removed capabilities.",), (1,)),
        ("Verify with simulation or replay: {t}", "Replay recorded sessions or run simulations against the new setup.",
         None, ("Legitimate workflows still succeed; risky ones are blocked or need approval.",),
         ("Simulation or replay run recorded.",), (2,)),
    ),
    "integration_bug": (
        ("Reproduce against the contract: {t}", "Capture a failing request/response pair from the integration.", None,
         ("Failure reproduced in a test.",), ("Failing contract test.",), ()),
        ("Identify the contract mismatch: {t}", "Compare the integration's behaviour with the event contract.", None,
         ("Mismatch documented with references.",), (), (0,)),
        ("Fix the mismatch: {t}", "Fix the side that violates the contract.", None,
         ("The contract test passes.",), ("Unit tests for the changed side.",), (1,)),
        ("Contract tests on both sides: {t}", "Guard the contract from both the integration and the server.", None,
         ("Both sides validate the same contract.",), ("Contract tests in both test suites.",), (2,)),
        ("Verify with a real integration run: {t}", "Run the integration end-to-end and record a verification run.",
         "task", ("A passed verification run is recorded.",), ("End-to-end run.",), (3,)),
    ),
    "performance": (
        ("Establish a baseline: {t}", "Measure the slow operation with realistic data.", None,
         ("Baseline numbers recorded with the command used.",), ("Repeatable benchmark.",), ()),
        ("Profile the hot path: {t}", "Find where time is spent (queries, loops, I/O).", None,
         ("Bottleneck identified with profile evidence.",), (), (0,)),
        ("Implement the optimisation: {t}", "Change the bottleneck without altering behaviour.", None,
         ("Behaviour unchanged; existing tests pass.",), ("Existing test suites.",), (1,)),
        ("Verify the improvement: {t}", "Re-run the baseline and compare.", None,
         ("Measured improvement against the baseline.",), ("Benchmark re-run.",), (2,)),
        ("Add a performance guard: {t}", "Add a test or benchmark that catches regressions.", None,
         ("Guard fails if performance regresses past the agreed threshold.",), ("Performance test.",), (3,)),
    ),
    "feature": (
        ("Specify requirements: {t}", "Write user-facing behaviour and testable acceptance criteria.", "task",
         ("Acceptance criteria agreed with the owner.",), (), ()),
        ("Design the change: {t}", "Agree data model, API contract and UI states.", "task",
         ("Design reviewed.",), (), (0,)),
        ("Implement: {t}", "Build the feature behind the agreed contract.", None,
         ("All acceptance criteria are implemented.",), ("Unit tests for new logic.",), (1,)),
        ("Test: {t}", "Cover the feature end-to-end, including error and empty states.", None,
         ("Tests cover each acceptance criterion.",), ("Unit and integration tests.",), (2,)),
        ("Document and release: {t}", "Update docs and record a verification run.", "task",
         ("Docs updated; a passed verification run is recorded.",), ("Full test suite run.",), (3,)),
    ),
    "tech_debt": (
        ("Characterise current behaviour: {t}", "Add tests that pin today's observable behaviour.", None,
         ("Characterisation tests pass on current code.",), ("Characterisation tests.",), ()),
        ("Refactor incrementally: {t}", "Restructure in small steps, keeping tests green.", None,
         ("Each step passes the test suite.",), ("Existing and characterisation tests.",), (0,)),
        ("Migrate callers and remove dead code: {t}", "Move callers to the new structure and delete the old path.", None,
         ("No callers use the old path.",), ("Tests for migrated callers.",), (1,)),
        ("Full regression and docs: {t}", "Run the full suite and update docs.", "task",
         ("Full suite passes; docs updated.",), ("Full test suite run; counts reported.",), (2,)),
    ),
    "generic": (
        ("Clarify scope and acceptance criteria: {t}", "Confirm what done means and what is out of scope.", "task",
         ("Scope and testable acceptance criteria agreed with the owner.",), (), ()),
        ("Implement: {t}", "Make the change described by the agreed scope.", None,
         ("Every acceptance criterion is addressed.",), ("Unit tests for changed logic.",), (0,)),
        ("Test: {t}", "Cover the change, including error paths.", None,
         ("Tests cover each acceptance criterion.",), ("Related suites pass.",), (1,)),
        ("Verify: {t}", "Run the related suites and record a verification run.", "task",
         ("A passed verification run is recorded.",), ("Related suites; counts reported.",), (2,)),
    ),
    "bug": (
        ("Reproduce with a failing test: {t}", "Capture the bug in an automated test.", None,
         ("The test fails for the reported reason.",), ("Failing regression test.",), ()),
        ("Identify root cause: {t}", "Confirm the cause with evidence.", None,
         ("Root cause documented with file references.",), (), (0,)),
        ("Implement fix: {t}", "Make the smallest change that removes the cause.", None,
         ("The regression test passes.",), ("Related test suites.",), (1,)),
        ("Verify: {t}", "Run the related suites and record a verification run.", "task",
         ("A passed verification run is recorded.",), ("Related suites; counts reported.",), (2,)),
    ),
}

_TYPE_TO_PLAN = {
    "security_vulnerability": "security_vulnerability", "prompt_injection": "prompt_injection",
    "data_exposure": "data_exposure", "agent_misconfiguration": "agent_misconfiguration",
    "integration_bug": "integration_bug", "performance": "performance", "feature": "feature",
    "tech_debt": "tech_debt", "backend": "generic", "frontend": "generic", "task": "generic",
}

PLAN_KEYS = tuple(_PLANS)


def choose_plan(task: Mapping[str, Any]) -> str:
    """Plan key for ``task``: MCP interception keywords, then task type, then linked finding category."""
    task_type = str(task.get("task_type") or "task")
    text = f"{task.get('title') or ''}\n{task.get('description') or ''}"
    if task_type in ("security_vulnerability", "integration_bug", "task", "backend") and _MCP_INTERCEPT.search(text):
        return "mcp_interception"
    if task_type in ("security_vulnerability", "task"):
        category = task.get("category") or task.get("finding_category")
        if category in _SECURITY_CATEGORIES:
            return _SECURITY_CATEGORIES[str(category)]
        if task.get("related_finding_id") or category:
            return "security_vulnerability"
    return _TYPE_TO_PLAN.get(task_type, "generic")


def decompose(task: Mapping[str, Any], *, plan: str | None = None) -> list[SubtaskDraft]:
    """Subtask drafts for ``task`` (``plan`` overrides the automatic choice)."""
    if not isinstance(task, Mapping):
        raise ValueError("task must be a mapping")
    key = plan or choose_plan(task)
    if key not in _PLANS:
        raise ValueError(f"Unknown breakdown plan {key!r}; expected one of: {', '.join(_PLANS)}")
    parent = inline(task.get("title") or "Untitled task", _TITLE_CHARS)
    parent_type = str(task.get("task_type") or "task")
    finding = task.get("related_finding_id")
    drafts: list[SubtaskDraft] = []
    for index, (title, description, step_type, crit, tests, deps) in enumerate(_PLANS[key]):
        criteria = list(crit)
        if finding and index == 0 and key not in ("feature", "tech_debt", "performance", "generic"):
            criteria.append(f"Reproduction matches the evidence recorded on finding {inline(finding, 60)}.")
        drafts.append(SubtaskDraft(
            title=title.format(t=parent),
            description=description,
            task_type=step_type or parent_type,
            acceptance_criteria=criteria,
            testing_requirements=list(tests),
            depends_on=[d for d in deps if d < index],
        ))
    return drafts
