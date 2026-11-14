"""Scenario building blocks for the Simulation Lab.

A :class:`Scenario` is an ordered list of *steps* (what a simulated agent reports to ContextOS)
followed by *expectations* (what the configured pipeline should have recorded). Steps describe
agent activity as event envelopes; the runner (``app.simulations.runner``) submits them to the real
ingestion pipeline — nothing is ever executed and no network request is made.

Step text may be a plain string or a callable taking :class:`RunVars`, so per-run synthetic
credentials (``RunVars.github_token`` …) can be placed into content without storing token-shaped
literals in the repository.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.simulations import payloads

Text = str | Callable[["RunVars"], str]
Args = dict[str, Any] | Callable[["RunVars"], dict[str, Any]]

MAIN = "main"
CHILD = "child"


@dataclass(frozen=True)
class RunVars:
    """Synthetic values generated for one run (never real credentials)."""

    github_token: str
    aws_secret: str

    @classmethod
    def generate(cls) -> RunVars:
        return cls(github_token=payloads.synthetic_github_token(), aws_secret=payloads.synthetic_aws_secret())

    def canaries(self) -> list[str]:
        """Raw secret values that must never appear in any persisted row."""
        return [self.github_token, self.aws_secret]


def resolve_text(value: Text | None, rv: RunVars) -> str | None:
    return value(rv) if callable(value) else value


def resolve_args(value: Args, rv: RunVars) -> dict[str, Any]:
    return dict(value(rv) if callable(value) else value)


# -- steps -----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolCall:
    """The agent asks to run a tool (``POST /decide`` semantics, as an enforcing integration).

    When the decision lets the call run (ALLOW / AUDIT) and ``result`` is set, the simulated
    integration then reports the result as ``tool.completed`` — the way a real hook reports output
    the agent will read. DENY, REQUIRE_APPROVAL and RESTRICT are treated as "not run": the Simulation
    Lab never applies restrictions or waits for a human.
    """

    label: str
    tool: str
    arguments: Args
    result: Text | None = None
    provider: str = "claude_code"
    server: str | None = None
    integration: str = "claude_code"
    actor: str = MAIN


@dataclass(frozen=True)
class ContextRead:
    """Context delivered to the agent outside a tool call (``context.ingested``)."""

    label: str
    source_type: str
    identifier: str
    content: Text
    content_type: str = "text/plain"
    actor: str = MAIN


@dataclass(frozen=True)
class McpListing:
    """The agent connects to an MCP server that advertises tools (``mcp.server_connected``)."""

    label: str
    server: str
    tools: tuple[tuple[str, str], ...]  # (name, description)


@dataclass(frozen=True)
class Delegate:
    """The main agent delegates a task to a child agent (``agent.delegated``)."""

    label: str
    child_agent: str
    task: str


@dataclass(frozen=True)
class ChildReply:
    """The child agent's reply delivered to the main agent (``agent.message``)."""

    label: str
    content: Text


Step = ToolCall | ContextRead | McpListing | Delegate | ChildReply


# -- run state and expectations --------------------------------------------------------------------


@dataclass
class StepOutcome:
    label: str
    kind: str
    decision: str | None = None
    enforcement: str | None = None
    executed: bool | None = None
    approval_id: str | None = None
    refs: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    # Server session the step was recorded in (the parent's or the delegated child's).
    session_id: str | None = None

    def evidence(self) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for key, kind in (
            ("policy_decision_id", "policy_decision"),
            ("tool_invocation_id", "tool_invocation"),
            ("context_item_id", "context_item"),
            ("approval_id", "approval"),
        ):
            value = self.refs.get(key) or (self.approval_id if key == "approval_id" else None)
            if value:
                out.append(
                    {
                        "type": kind,
                        "id": str(value),
                        **({"session_id": self.session_id} if self.session_id else {}),
                    }
                )
        return out


@dataclass
class RunView:
    """What an expectation can inspect: the run's sessions and the outcome of every step."""

    db: Session
    org_id: str
    run_id: str
    session_ids: list[str]
    outcomes: dict[str, StepOutcome]
    vars: RunVars
    audit_seq_before: int


@dataclass(frozen=True)
class CheckResult:
    expected: str
    actual: str
    passed: bool
    evidence: list[dict[str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class Expectation:
    id: str
    description: str  # plain-language statement of what should be true
    check: Callable[[RunView], CheckResult]


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    description: str
    category: str  # FindingCategory-like grouping shown in the catalogue
    use_case: str  # which product use case it exercises
    steps: tuple[Step, ...]
    expectations: tuple[Expectation, ...]
    demo: bool = True
    tags: tuple[str, ...] = ()

    def step_labels(self) -> list[str]:
        return [s.label for s in self.steps]
