"""Organisation-isolation sweep over EVERY API route, enumerated from the FastAPI app.

Organisation A owns one of every org-scoped record (``org_isolation_support.build_org_a``).
Organisation B — as a signed-in owner and as an API key (ingest, decide, read) — then requests
every route with A's ids wherever ids go (path, query, body), and once more with ids of the same
shape that exist nowhere. The sweep asserts:

- ``id`` routes (an org-owned id in the path) and ``ref`` probes (a foreign id in the body or query)
  answer B's owner 404. An API key may instead get 403 when it lacks the route's permission — but
  only if a nonexistent id gets exactly the same answer (no existence oracle).
- Every probe answers the same status and error code for A's id as for an id that does not exist.
- No response to B ever contains one of A's record ids (other than ids B sent itself), so lists,
  stats, graphs and exports leak nothing; no response is a 5xx.
- B's mutations change none of A's rows: every row A owns is byte-identical before and after.
- Every route is classified below. A route added without a classification fails the sweep.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from tests.integration.org_isolation_support import (
    Probe,
    World,
    build_org_a,
    build_org_b_parents,
    error_code,
    ids_in,
    iter_routes,
    org_ids,
    query_id_params,
    snapshot_org,
)

Ids = dict[str, str]
Fn = Callable[[Ids, Ids], Any]


@dataclass(frozen=True)
class R:
    kind: str  # public | self | catalogue | list | id | ref
    body: Fn | None = None
    query: Fn | None = None
    path: Fn | None = None
    reason: str = ""
    ref_statuses: tuple[int, ...] = (404,)  # what B's owner may get for a foreign reference


def public(reason: str) -> R:
    return R("public", reason=reason)


def own(reason: str, body: Fn | None = None, query: Fn | None = None) -> R:
    """Acts on the caller's own organisation or user only; no foreign id can be expressed."""
    return R("self", body=body, query=query, reason=reason)


def catalogue(reason: str, path: Fn | None = None) -> R:
    return R("catalogue", path=path, reason=reason)


def lst(query: Fn | None = None) -> R:
    return R("list", query=query)


def idr(body: Fn | None = None, path: Fn | None = None, query: Fn | None = None) -> R:
    return R("id", body=body, path=path, query=query)


def ref(
    body: Fn | None = None,
    query: Fn | None = None,
    path: Fn | None = None,
    statuses: tuple[int, ...] = (404,),
) -> R:
    return R("ref", body=body, query=query, path=path, ref_statuses=statuses)


def _env(i: Ids, o: Ids) -> dict[str, Any]:
    return {
        "event_id": f"evt-sweep-{len(i)}-{o.get('session', '')[-6:]}",
        "event_type": "tool.requested",
        "timestamp": "2026-11-11T10:00:00+00:00",
        "agent": {"name": o["agent_name"], "framework": "claude_code"},
        "session_id": o["external_session"],
        "integration": "claude_code",
        "tool": {"name": "Read", "provider": "claude_code"},
        "arguments": {"file_path": "/work/app/main.py"},
    }


def _ref_body(kind: str, key: str) -> Fn:
    return lambda i, o: {"ref_type": kind, "ref_id": i[key]}


T = "/workspace/tasks"
AI = "/workspace/ai"
ROUTES: dict[str, R] = {
    # -- public / docs ---------------------------------------------------------------------------------
    "GET /api/v1/health": public("liveness, no data"),
    "GET /api/v1/ready": public("readiness, no data"),
    "GET /api/v1/auth/setup-status": public("first-run flag only"),
    "POST /api/v1/auth/setup": public("first-run setup; refused once any organisation exists"),
    "POST /api/v1/auth/login": public("sign-in; covered by tests/integration/test_auth.py"),
    "POST /api/v1/auth/logout": public("revokes the caller's own session; covered by test_auth.py"),
    "GET /api/openapi.json": public("API schema, no data"),
    "GET /api/docs": public("Swagger UI, no data"),
    "GET /docs/oauth2-redirect": public("Swagger UI helper, no data"),
    "GET /redoc": public("ReDoc UI, no data"),
    # -- caller's own user / organisation ---------------------------------------------------------------
    "GET /api/v1/auth/me": own("the caller's own profile"),
    "GET /api/v1/org": own("the caller's organisation"),
    "PATCH /api/v1/org/settings": own(
        "changes the caller's organisation only", body=lambda i, o: {"retention_days": 7}
    ),
    "GET /api/v1/org/members": lst(),
    "POST /api/v1/org/members": own(
        "adds a member to the caller's organisation",
        body=lambda i, o: {"email": "sweep-member@b.example.test", "name": "Sweep Member", "role": "viewer"},
    ),
    "PATCH /api/v1/org/members/{membership_id}": idr(body=lambda i, o: {"role": "viewer"}),
    "DELETE /api/v1/org/members/{membership_id}": idr(),
    "GET /api/v1/org/api-keys": lst(),
    "POST /api/v1/org/api-keys": ref(
        body=lambda i, o: {"name": "bound", "scopes": ["ingest"], "agent_id": i["agent"]}
    ),
    "DELETE /api/v1/org/api-keys/{key_id}": idr(),
    "POST /api/v1/events": own(
        "records events for the caller's organisation (B reuses A's agent name and session id)",
        body=lambda i, o: {
            "events": [{**_env(i, o), "event_type": "session.started", "tool": None, "arguments": None}]
        },
    ),
    "POST /api/v1/decide": own(
        "decides for the caller's organisation (B reuses A's agent name and session id)",
        body=lambda i, o: {**_env(i, o), "event_id": "evt-sweep-decide"},
    ),
    "GET /api/v1/decide/approvals/{approval_id}": idr(),
    "POST /api/v1/decide/approvals/{approval_id}/cancel": idr(body=lambda i, o: {"reason": "sweep"}),
    "POST /api/v1/scan": own("stateless detection on submitted text", body=lambda i, o: {"content": "hello"}),
    "GET /api/v1/events": lst(),
    "GET /api/v1/events/{event_id}": idr(),
    "GET /api/v1/stream": own(
        "SSE stream of the caller's organisation; not requested here (long-lived) — "
        "isolation is covered by tests/integration/test_stream.py"
    ),
    # -- agents, sessions, context, provenance ----------------------------------------------------------
    "GET /api/v1/agents": lst(),
    "POST /api/v1/agents": own(
        "registers an agent in the caller's organisation", body=lambda i, o: {"name": o["agent_name"]}
    ),
    "GET /api/v1/agents/graph": lst(),
    "GET /api/v1/agents/{agent_id}": idr(),
    "PATCH /api/v1/agents/{agent_id}": idr(body=lambda i, o: {"description": "sweep"}),
    "GET /api/v1/agents/{agent_id}/sessions": idr(),
    "GET /api/v1/agents/{agent_id}/tools": idr(),
    "GET /api/v1/agents/{agent_id}/posture": idr(),
    "GET /api/v1/sessions": lst(),
    "GET /api/v1/sessions/{session_id}": idr(),
    "GET /api/v1/sessions/{session_id}/timeline": idr(),
    "GET /api/v1/context/facets": lst(),
    "GET /api/v1/context/items": lst(),
    "GET /api/v1/context/items/{item_id}": idr(),
    "GET /api/v1/context/items/{item_id}/receipt": idr(),
    "GET /api/v1/context/sources": lst(),
    "GET /api/v1/context/sources/{source_id}": idr(),
    "GET /api/v1/provenance/graph": ref(query=lambda i, o: {"session_id": i["session"]}),
    "GET /api/v1/provenance/scopes": lst(query=lambda i, o: {"q": o["agent_name"]}),
    "GET /api/v1/provenance/nodes/{node_type}/{node_id:path}": idr(
        path=lambda i, o: {"node_type": "agent", "node_id": i["agent"]}
    ),
    # -- trust ----------------------------------------------------------------------------------------
    "GET /api/v1/trust/summary": lst(),
    "GET /api/v1/trust/rules": lst(),
    "POST /api/v1/trust/rules/test": ref(
        body=lambda i, o: {"identifier": "docs.vendor.example", "replace_rule_id": i["trust_rule"]}
    ),
    "POST /api/v1/trust/rules": own(
        "creates a rule in the caller's organisation",
        body=lambda i, o: {"name": "B rule", "pattern": "b.example", "trust_level": "TRUSTED"},
    ),
    "GET /api/v1/trust/rules/{rule_id}": idr(),
    "PATCH /api/v1/trust/rules/{rule_id}": idr(body=lambda i, o: {"enabled": False}),
    "DELETE /api/v1/trust/rules/{rule_id}": idr(),
    "GET /api/v1/trust/sources": lst(),
    "GET /api/v1/trust/sources/{source_id}": idr(),
    "PATCH /api/v1/trust/sources/{source_id}": idr(
        body=lambda i, o: {"trust_level": "TRUSTED", "note": "sweep"}
    ),
    "POST /api/v1/trust/sources/{source_id}/reassess": idr(),
    "POST /api/v1/trust/destinations/verify": own(
        "checks a destination name against the caller's rules",
        body=lambda i, o: {"identifier": "drop.attacker.example"},
    ),
    "GET /api/v1/trust/destinations": lst(),
    "GET /api/v1/trust/destinations/{destination_id}": idr(),
    "PATCH /api/v1/trust/destinations/{destination_id}": idr(
        body=lambda i, o: {"classification": "TRUSTED", "note": "sweep"}
    ),
    # -- findings, policies, approvals, incidents, replay ------------------------------------------------
    "GET /api/v1/findings": lst(),
    "GET /api/v1/findings/stats": lst(),
    "GET /api/v1/findings/{finding_id}": idr(),
    "PATCH /api/v1/findings/{finding_id}": idr(body=lambda i, o: {"status": "false_positive"}),
    "POST /api/v1/findings/{finding_id}/incident": idr(body=lambda i, o: {}),
    "GET /api/v1/policies/fields": catalogue("static field catalogue"),
    "GET /api/v1/policies/operators": catalogue("static operator catalogue"),
    "POST /api/v1/policies/validate": own(
        "validates a draft; nothing stored",
        body=lambda i, o: {"conditions": {"field": "tool.name", "op": "eq", "value": "x"}},
    ),
    "POST /api/v1/policies/test": ref(
        body=lambda i, o: {"policy_decision_id": i["decision"], "with_org_policies": True}
    ),
    "GET /api/v1/policies/recent-decisions": lst(),
    "GET /api/v1/policies": lst(),
    "POST /api/v1/policies": own(
        "creates a policy in the caller's organisation",
        body=lambda i, o: {
            "name": "B policy",
            "outcome": "AUDIT",
            "conditions": {"field": "tool.name", "op": "eq", "value": "x"},
        },
    ),
    "GET /api/v1/policies/{policy_id}": idr(),
    "PATCH /api/v1/policies/{policy_id}": idr(body=lambda i, o: {"enabled": False}),
    "DELETE /api/v1/policies/{policy_id}": idr(),
    "GET /api/v1/policies/{policy_id}/decisions": idr(),
    "GET /api/v1/approvals": lst(),
    "GET /api/v1/approvals/{approval_id}": idr(),
    "POST /api/v1/approvals/{approval_id}/decide": idr(body=lambda i, o: {"approve": True}),
    "GET /api/v1/incidents": lst(),
    "POST /api/v1/incidents": ref(
        body=lambda i, o: {"title": "B", "severity": "low", "finding_ids": [i["finding"]]}
    ),
    "GET /api/v1/incidents/{incident_id}": idr(),
    "PATCH /api/v1/incidents/{incident_id}": idr(
        body=lambda i, o: {"status": "resolved", "resolution": "sweep"}
    ),
    "POST /api/v1/incidents/{incident_id}/notes": idr(body=lambda i, o: {"body": "sweep"}),
    "POST /api/v1/incidents/{incident_id}/findings": idr(body=lambda i, o: {"finding_ids": [i["finding"]]}),
    "GET /api/v1/incidents/{incident_id}/timeline": idr(),
    "GET /api/v1/incidents/{incident_id}/export": idr(),
    "GET /api/v1/replay/sessions/{session_id}": idr(),
    "POST /api/v1/replay/counterfactual": ref(body=lambda i, o: {"session_id": i["session"]}),
    # -- simulation lab, overview, integrations, audit --------------------------------------------------
    "GET /api/v1/simulations/scenarios": catalogue("built-in scenario catalogue"),
    "GET /api/v1/simulations/scenarios/{scenario_id}": catalogue(
        "built-in scenario", path=lambda i, o: {"scenario_id": "benign-baseline"}
    ),
    "POST /api/v1/simulations/runs": ref(
        body=lambda i, o: {"scenario_id": "benign-baseline", "agent_id": i["agent"]}
    ),
    "GET /api/v1/simulations/runs": lst(),
    "GET /api/v1/simulations/runs/{run_id}": idr(),
    "POST /api/v1/simulations/suites": ref(
        body=lambda i, o: {"scenario_ids": ["benign-baseline"], "agent_id": i["agent"]}
    ),
    "GET /api/v1/simulations/suites": lst(),
    "GET /api/v1/simulations/suites/compare": ref(
        query=lambda i, o: {"base": i["suite_run"], "head": i["suite_run"]}
    ),
    "GET /api/v1/simulations/suites/{suite_run_id}": idr(),
    "GET /api/v1/overview/nav-counts": lst(),
    "GET /api/v1/overview": lst(),
    "GET /api/v1/integrations": lst(),
    "GET /api/v1/integrations/{kind}/setup": catalogue(
        "setup instructions for an integration kind", path=lambda i, o: {"kind": "claude_code"}
    ),
    "GET /api/v1/audit": lst(),
    "GET /api/v1/audit/verify": lst(),
    "GET /api/v1/audit/export": lst(),
    # -- engineering workspace -------------------------------------------------------------------------
    "GET /api/v1/workspace/boards/templates": catalogue("built-in board templates"),
    "GET /api/v1/workspace/boards": lst(),
    "POST /api/v1/workspace/boards": own(
        "creates a board in the caller's organisation", body=lambda i, o: {"name": "B board 2"}
    ),
    "GET /api/v1/workspace/boards/{board_id}": idr(),
    "PATCH /api/v1/workspace/boards/{board_id}": idr(body=lambda i, o: {"name": "renamed"}),
    "DELETE /api/v1/workspace/boards/{board_id}": idr(),
    "POST /api/v1/workspace/boards/{board_id}/duplicate": idr(body=lambda i, o: {}),
    "POST /api/v1/workspace/boards/{board_id}/columns": idr(body=lambda i, o: {"name": "Sweep"}),
    "POST /api/v1/workspace/boards/{board_id}/columns/reorder": idr(
        body=lambda i, o: {"column_ids": [i["column"]]}
    ),
    "PATCH /api/v1/workspace/boards/{board_id}/columns/{column_id}": idr(
        body=lambda i, o: {"name": "renamed"}
    ),
    "DELETE /api/v1/workspace/boards/{board_id}/columns/{column_id}": idr(),
    "GET /api/v1/workspace/tasks": lst(),
    "POST /api/v1/workspace/tasks": ref(
        body=lambda i, o: {"title": "B", "board_id": o["board"], "related_finding_id": i["finding"]}
    ),
    "GET /api/v1/workspace/tasks/labels": lst(),
    "POST /api/v1/workspace/tasks/labels": own(
        "creates a label in the caller's organisation", body=lambda i, o: {"name": "b-label"}
    ),
    "POST /api/v1/workspace/tasks/from-finding": ref(body=lambda i, o: {"finding_id": i["finding"]}),
    "POST /api/v1/workspace/tasks/from-incident": ref(body=lambda i, o: {"incident_id": i["incident"]}),
    "PATCH /api/v1/workspace/tasks/comments/{comment_id}": idr(body=lambda i, o: {"body": "edited"}),
    "DELETE /api/v1/workspace/tasks/comments/{comment_id}": idr(),
    "DELETE /api/v1/workspace/tasks/dependencies/{dependency_id}": idr(),
    "DELETE /api/v1/workspace/tasks/refs/{ref_id}": idr(),
    "DELETE /api/v1/workspace/tasks/attachments/{attachment_id}": idr(),
    "PATCH /api/v1/workspace/tasks/fix-attempts/{attempt_id}": idr(body=lambda i, o: {"status": "failed"}),
    "GET /api/v1/workspace/tasks/{task_id}": idr(),
    "PATCH /api/v1/workspace/tasks/{task_id}": idr(body=lambda i, o: {"title": "renamed"}),
    "DELETE /api/v1/workspace/tasks/{task_id}": idr(),
    "POST /api/v1/workspace/tasks/{task_id}/move": idr(body=lambda i, o: {"column_id": i["column"]}),
    "PUT /api/v1/workspace/tasks/{task_id}/assignees": idr(body=lambda i, o: {"assignees": []}),
    "POST /api/v1/workspace/tasks/{task_id}/comments": idr(body=lambda i, o: {"body": "sweep"}),
    "POST /api/v1/workspace/tasks/{task_id}/dependencies": idr(
        body=lambda i, o: {"depends_on_task_id": o["task"]}
    ),
    "POST /api/v1/workspace/tasks/{task_id}/refs": idr(
        body=lambda i, o: {"ref_type": "agent", "ref_id": i["agent"]}
    ),
    "POST /api/v1/workspace/tasks/{task_id}/attachments": idr(
        body=lambda i, o: {"name": "x", "content": "y"}
    ),
    "POST /api/v1/workspace/tasks/{task_id}/links": idr(body=lambda i, o: {"kind": "branch", "ref": "fix/x"}),
    "DELETE /api/v1/workspace/tasks/{task_id}/links/{kind}/{index}": idr(
        path=lambda i, o: {"task_id": i["task"], "kind": "pull_request", "index": "0"}
    ),
    "POST /api/v1/workspace/tasks/{task_id}/fix-attempts": idr(body=lambda i, o: {"status": "planned"}),
    "POST /api/v1/workspace/tasks/{task_id}/verifications": idr(
        body=lambda i, o: {"kind": "manual", "status": "passed"}
    ),
    "POST /api/v1/workspace/tasks/{task_id}/verify-with-simulation": idr(
        body=lambda i, o: {"scenario_id": "benign-baseline"}
    ),
    "GET /api/v1/workspace/ai/modes": ref(query=lambda i, o: {"task_id": i["task"]}),
    "POST /api/v1/workspace/ai/context-packs": ref(body=lambda i, o: {"task_id": i["task"]}),
    "GET /api/v1/workspace/ai/context-packs": lst(),
    "GET /api/v1/workspace/ai/context-packs/{pack_id}": idr(),
    "GET /api/v1/workspace/ai/context-packs/{pack_id}/export": idr(),
    "PATCH /api/v1/workspace/ai/context-packs/{pack_id}": idr(
        body=lambda i, o: {"items": [{"key": "x", "included": False}]}
    ),
    "DELETE /api/v1/workspace/ai/context-packs/{pack_id}": idr(),
    "POST /api/v1/workspace/ai/fix-context": ref(body=lambda i, o: {"task_id": i["task"]}),
    "GET /api/v1/workspace/ai/prompts": lst(),
    "GET /api/v1/workspace/ai/prompts/{prompt_id}": idr(),
    "PATCH /api/v1/workspace/ai/prompts/{prompt_id}": idr(body=lambda i, o: {"extra_instructions": "sweep"}),
    "POST /api/v1/workspace/ai/prompts/{prompt_id}/regenerate-section": idr(
        body=lambda i, o: {"section_key": "task_summary"}
    ),
    "GET /api/v1/workspace/ai/prompts/{prompt_id}/export": idr(),
    "GET /api/v1/workspace/ai/templates": lst(),
    "POST /api/v1/workspace/ai/templates": own(
        "creates a template in the caller's organisation",
        body=lambda i, o: {"name": "B template", "mode": "refactor"},
    ),
    "GET /api/v1/workspace/ai/templates/{template_id}": idr(),
    "PATCH /api/v1/workspace/ai/templates/{template_id}": idr(body=lambda i, o: {"name": "renamed"}),
    "DELETE /api/v1/workspace/ai/templates/{template_id}": idr(),
    "POST /api/v1/workspace/ai/breakdown": ref(body=lambda i, o: {"task_id": i["task"]}),
    "POST /api/v1/workspace/ai/breakdown/apply": ref(
        body=lambda i, o: {"task_id": i["task"], "drafts": [{"title": "x"}]}
    ),
    "GET /api/v1/workspace/analytics": lst(),
    "GET /api/v1/workspace/analytics/remediation": lst(),
}

# B's own parent with A's child, or A's id in an otherwise valid body for B's own record.
MIXED: list[tuple[str, str, Fn, Fn | None, Fn | None, tuple[int, ...]]] = [
    (
        "PATCH",
        "/workspace/boards/{board}/columns/{column}",
        lambda i, o: {"board": o["board"], "column": i["column"]},
        lambda i, o: {"name": "renamed"},
        None,
        (404,),
    ),
    (
        "DELETE",
        "/workspace/boards/{board}/columns/{column}",
        lambda i, o: {"board": o["board"], "column": i["column"]},
        None,
        None,
        (404,),
    ),
    (
        "POST",
        "/workspace/boards/{board}/columns/reorder",
        lambda i, o: {"board": o["board"]},
        lambda i, o: {"column_ids": [o["column"], i["column"]]},
        None,
        (404, 422),
    ),
    (
        "POST",
        T + "/{task}/move",
        lambda i, o: {"task": o["task"]},
        lambda i, o: {"column_id": i["column"]},
        None,
        (404,),
    ),
    (
        "POST",
        T + "/{task}/dependencies",
        lambda i, o: {"task": o["task"]},
        lambda i, o: {"depends_on_task_id": i["task"]},
        None,
        (404,),
    ),
    *[
        ("POST", T + "/{task}/refs", lambda i, o: {"task": o["task"]}, _ref_body(kind, key), None, (404,))
        for kind, key in (
            ("finding", "finding"),
            ("incident", "incident"),
            ("event", "event"),
            ("session", "session"),
            ("agent", "agent"),
            ("tool_invocation", "invocation"),
            ("policy_decision", "decision"),
            ("context_item", "item"),
            ("source", "source"),
            ("approval", "approval"),
            ("destination", "destination"),
        )
    ],
    (
        "POST",
        T + "/{task}/fix-attempts",
        lambda i, o: {"task": o["task"]},
        lambda i, o: {"generated_prompt_id": i["prompt"]},
        None,
        (404,),
    ),
    (
        "POST",
        T + "/{task}/verifications",
        lambda i, o: {"task": o["task"]},
        lambda i, o: {"kind": "manual", "status": "passed", "fix_attempt_id": i["fix_attempt"]},
        None,
        (404,),
    ),
    (
        "POST",
        T + "/{task}/verifications",
        lambda i, o: {"task": o["task"]},
        lambda i, o: {"kind": "simulation", "simulation_run_id": i["run"]},
        None,
        (404,),
    ),
    (
        "PUT",
        T + "/{task}/assignees",
        lambda i, o: {"task": o["task"]},
        lambda i, o: {"assignees": [{"user_id": i["user"]}]},
        None,
        (404, 422),
    ),
    (
        "PATCH",
        T + "/{task}",
        lambda i, o: {"task": o["task"]},
        lambda i, o: {"related_incident_id": i["incident"]},
        None,
        (404,),
    ),
    (
        "PATCH",
        T + "/{task}",
        lambda i, o: {"task": o["task"]},
        lambda i, o: {"parent_task_id": i["task"]},
        None,
        (404,),
    ),
    (
        "PATCH",
        T + "/{task}",
        lambda i, o: {"task": o["task"]},
        lambda i, o: {"label_ids": [i["label"]]},
        None,
        (404,),
    ),
    (
        "PATCH",
        T + "/{task}",
        lambda i, o: {"task": o["task"]},
        lambda i, o: {"related_agent_id": i["agent"]},
        None,
        (404,),
    ),
    ("POST", T, lambda i, o: {}, lambda i, o: {"title": "B", "board_id": i["board"]}, None, (404,)),
    (
        "POST",
        T,
        lambda i, o: {},
        lambda i, o: {"title": "B", "board_id": o["board"], "column_id": i["column"]},
        None,
        (404,),
    ),
    (
        "POST",
        "/findings/{finding}/incident",
        lambda i, o: {"finding": i["finding"]},
        lambda i, o: {},
        None,
        (404,),
    ),
    (
        "POST",
        AI + "/fix-context",
        lambda i, o: {},
        lambda i, o: {"task_id": o["task"], "context_pack_id": i["pack"]},
        None,
        (404,),
    ),
    (
        "POST",
        AI + "/fix-context",
        lambda i, o: {},
        lambda i, o: {"task_id": o["task"], "template_id": i["template"]},
        None,
        (404,),
    ),
    (
        "POST",
        "/workspace/boards/{board}/columns",
        lambda i, o: {"board": o["board"]},
        lambda i, o: {
            "name": "auto",
            "automation": [{"trigger": "verification_passed", "move_to_column_id": i["column"]}],
        },
        None,
        (404, 422),
    ),
    (
        "POST",
        "/replay/counterfactual",
        lambda i, o: {},
        lambda i, o: {"session_id": o["session"], "policy_set": {"disable_policy_ids": [i["policy"]]}},
        None,
        (404,),
    ),
    (
        "GET",
        "/replay/sessions/{session}",
        lambda i, o: {"session": o["session"]},
        None,
        lambda i, o: {"decision_id": i["decision"]},
        (200,),
    ),
    (
        "GET",
        "/sessions/{session}/timeline",
        lambda i, o: {"session": o["session"]},
        None,
        lambda i, o: {"invocation_id": i["invocation"]},
        (200,),
    ),
    (
        "POST",
        "/policies/test",
        lambda i, o: {},
        lambda i, o: {"policy_ids": [i["policy"]], "input": {}},
        None,
        (404,),
    ),
    (
        "POST",
        "/trust/rules/test",
        lambda i, o: {},
        lambda i, o: {
            "identifier": "x.example",
            "applies_to": "destination",
            "replace_rule_id": i["trust_rule"],
        },
        None,
        (404,),
    ),
    (
        "PATCH",
        "/incidents/{incident}",
        lambda i, o: {"incident": o["incident"]},
        lambda i, o: {"assignee_user_id": i["user"]},
        None,
        (404, 422),
    ),
    (
        "POST",
        "/incidents/{incident}/findings",
        lambda i, o: {"incident": o["incident"]},
        lambda i, o: {"finding_ids": [i["finding"]]},
        None,
        (404,),
    ),
]

PARAM_KEYS = {
    "membership_id": "membership",
    "key_id": "api_key",
    "approval_id": "approval",
    "event_id": "event",
    "agent_id": "agent",
    "session_id": "session",
    "item_id": "item",
    "source_id": "source",
    "rule_id": "trust_rule",
    "destination_id": "destination",
    "finding_id": "finding",
    "policy_id": "policy",
    "incident_id": "incident",
    "run_id": "run",
    "suite_run_id": "suite_run",
    "board_id": "board",
    "column_id": "column",
    "comment_id": "comment",
    "dependency_id": "dependency",
    "ref_id": "ref",
    "attachment_id": "attachment",
    "attempt_id": "fix_attempt",
    "task_id": "task",
    "pack_id": "pack",
    "prompt_id": "prompt",
    "template_id": "template",
}
QUERY_KEYS = {
    **PARAM_KEYS,
    "context_item_id": "item",
    "parent_task_id": "task",
    "related_finding_id": "finding",
    "related_incident_id": "incident",
    "decision_id": "decision",
    "invocation_id": "invocation",
    "actor_id": "user",
    "target_id": "incident",
    "assignee_user_id": "user",
}


# -- the sweep ----------------------------------------------------------------------------------------

NOT_REQUESTED = {"GET /api/v1/stream"}  # long-lived SSE; see its classification


def _key(method: str, path: str) -> str:
    return f"{method} {path}"


def _api_path(path: str) -> str:
    assert path.startswith("/api/v1"), path
    return path[len("/api/v1") :]


def _format(template: str, params: dict[str, str]) -> str:
    return re.sub(r"\{([^}:]+)(?::path)?\}", lambda m: params[m.group(1)], template)


def _probes(method: str, path: str, route: Any, spec: R, ids: Ids, own: Ids) -> list[Probe]:
    """The request this route gets as B, built from ``ids`` (A's ids or ids that exist nowhere)."""
    names = re.findall(r"\{([^}:]+)(?::path)?\}", path)
    params = spec.path(ids, own) if spec.path else {n: ids[PARAM_KEYS[n]] for n in names}
    body = spec.body(ids, own) if spec.body else ({} if method in ("POST", "PUT", "PATCH") else None)
    if method in ("POST", "PUT", "PATCH") and spec.body is None and spec.kind in ("id", "self"):
        body = None  # routes whose body is optional (or that take none)
    query = spec.query(ids, own) if spec.query else None
    probes = [Probe(method, _format(_api_path(path), params), body, query)]
    if spec.kind == "list" and method == "GET":
        filled = {q: ids[QUERY_KEYS[q]] for q in query_id_params(route) if q in QUERY_KEYS}
        if filled:
            probes.append(Probe(method, _format(_api_path(path), params), None, {**(query or {}), **filled}))
    return probes


def _sweep_requests(world: World) -> list[tuple[str, str, Callable[[Ids], list[Probe]], tuple[int, ...]]]:
    """(label, kind, build(ids) -> probes, statuses B's owner may get) for every route and mixed probe."""
    from app.main import create_app

    out = []
    for method, path, route in iter_routes(create_app()):
        key = _key(method, path)
        spec = ROUTES[key]
        if spec.kind == "public" or key in NOT_REQUESTED:
            continue
        statuses = (404,) if spec.kind == "id" else spec.ref_statuses if spec.kind == "ref" else ()
        out.append(
            (
                key,
                spec.kind,
                lambda ids, m=method, p=path, r=route, s=spec: _probes(m, p, r, s, ids, world.own),
                statuses,
            )
        )
    for method, template, params, body, query, statuses in MIXED:
        label = f"{method} {template} (mixed)"

        def build(ids: Ids, m=method, t=template, pa=params, b=body, q=query) -> list[Probe]:
            path = _format(t, pa(ids, world.own))
            return [
                Probe(
                    m,
                    path,
                    b(ids, world.own) if b else ({} if m in ("POST", "PUT", "PATCH") else None),
                    q(ids, world.own) if q else None,
                )
            ]

        out.append((label, "ref", build, statuses))
    return out


def _send(client: Any, probe: Probe, headers: dict[str, str], problems: list[str], where: str) -> Any:
    try:
        return probe.send(client, headers)
    except Exception as exc:  # noqa: BLE001 - the TestClient re-raises unhandled server errors
        problems.append(f"{where}: unhandled server error {type(exc).__name__}: {exc}")
        return None


def test_every_route_is_classified(app) -> None:
    served = {_key(m, p) for m, p, _ in iter_routes(app)}
    missing = sorted(served - ROUTES.keys())
    stale = sorted(ROUTES.keys() - served)
    assert not missing, f"New routes need an isolation classification in ROUTES: {missing}"
    assert not stale, f"ROUTES lists routes the app no longer serves: {stale}"
    for key, spec in ROUTES.items():
        if spec.kind in ("public", "self", "catalogue"):
            assert spec.reason, f"{key}: public/self/catalogue routes need a reason"


def test_another_organisation_can_neither_see_nor_change_anything(client, seeded_org, other_org, db) -> None:
    a, b = seeded_org, other_org
    world = build_org_a(client, a, db)
    build_org_b_parents(client, b, world)
    before = snapshot_org(db, a.org_id, [a.user_id, world.ids["user"]])
    a_ids = org_ids(before) | {a.user_id}
    assert {world.ids[k] for k in ("agent", "incident", "task", "prompt", "suite_run")} <= a_ids
    absent = world.fake()
    problems: list[str] = []

    for label, kind, build, statuses in _sweep_requests(world):
        for who, headers in (("user", b.user_headers), ("key", b.api_headers)):
            for foreign, missing in zip(build(world.ids), build(absent), strict=True):
                where = f"{label} as B's {who} ({foreign.method} {foreign.path})"
                got, ref = (
                    _send(client, foreign, headers, problems, where),
                    _send(client, missing, headers, problems, where),
                )
                if got is None or ref is None:
                    continue
                if got.status_code >= 500 or ref.status_code >= 500:
                    problems.append(
                        f"{where}: server error {got.status_code}/{ref.status_code}: {got.text[:200]}"
                    )
                    continue
                leaked = (ids_in(got.text) & a_ids) - foreign.sent
                if leaked:
                    problems.append(f"{where}: response contains A's ids {sorted(leaked)[:3]}")
                if kind in ("id", "ref"):
                    if (got.status_code, error_code(got)) != (ref.status_code, error_code(ref)):
                        problems.append(
                            f"{where}: A's id answered {got.status_code} {error_code(got)} but an absent "
                            f"id answered {ref.status_code} {error_code(ref)} (existence oracle)"
                        )
                    if who == "user" and got.status_code not in statuses:
                        problems.append(
                            f"{where}: expected {statuses}, got {got.status_code}: {got.text[:200]}"
                        )
                    if who == "key" and got.status_code not in (*statuses, 403):
                        problems.append(
                            f"{where}: expected {statuses} or 403, got {got.status_code}: {got.text[:200]}"
                        )

    after = snapshot_org(db, a.org_id, [a.user_id, world.ids["user"]])
    changed = sorted(t for t in before if before[t] != after[t])
    assert not problems, "\n".join(problems)
    assert not changed, f"B's requests changed rows organisation A owns, in tables: {changed}"
