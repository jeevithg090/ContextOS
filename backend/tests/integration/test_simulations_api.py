"""Simulation Lab: scenarios through the real pipeline, regression suites, isolation, permissions."""

from __future__ import annotations

import json
import re

import pytest
from sqlalchemy import select

from app.database.base import Base
from app.models import Agent, AgentSession, Approval, AuditEvent, SecurityFinding, SimulationRun
from app.services.simulations import list_scenarios, run_scenario
from app.simulations.scenarios import SCENARIOS

API = "/api/v1/simulations"
SCENARIO_IDS = [s.id for s in SCENARIOS]
_TOKEN_SHAPE = re.compile(r"ghp_[A-Za-z0-9]{36}")


def _run(client, headers, scenario_id, **body):
    response = client.post(f"{API}/runs", json={"scenario_id": scenario_id, **body}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def test_catalogue_lists_every_scenario_with_its_checks(client, seeded_org):
    body = client.get(f"{API}/scenarios", headers=seeded_org.api_headers).json()
    assert [s["id"] for s in body["items"]] == SCENARIO_IDS
    assert "nothing is executed" in body["note"].lower()
    readme = next(s for s in body["items"] if s["id"] == "malicious-readme")
    assert readme["steps"] == ["read-readme", "read-ssh-key", "send-key"]
    assert all(c["description"] for c in readme["checks"])
    assert (
        client.get(f"{API}/scenarios/benign-baseline", headers=seeded_org.api_headers).json()["category"]
        == "baseline"
    )
    assert client.get(f"{API}/scenarios/nope", headers=seeded_org.api_headers).status_code == 404


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_every_scenario_passes_against_the_default_policies(client, seeded_org, db, scenario_id):
    run = _run(client, seeded_org.user_headers, scenario_id)
    failing = [r for r in run["results"] if r["kind"] == "expectation" and not r["passed"]]
    assert run["status"] == "completed" and run["passed"] is True, failing
    assert run["checks_total"] >= 2 and run["checks_passed"] == run["checks_total"]
    assert run["is_simulation"] is True and run["session_id"]

    db.rollback()
    sessions = list(db.scalars(select(AgentSession).where(AgentSession.simulation_run_id == run["id"])))
    assert sessions and all(s.is_simulation and s.status == "ended" for s in sessions)
    ids = [s.id for s in sessions]
    findings = list(db.scalars(select(SecurityFinding).where(SecurityFinding.session_id.in_(ids))))
    assert all(f.is_simulation for f in findings)
    # Simulated approval requests never wait in the queue.
    assert not list(
        db.scalars(select(Approval).where(Approval.session_id.in_(ids), Approval.status == "pending"))
    )


def test_benign_baseline_raises_no_findings_and_never_blocks(client, seeded_org, db):
    run = _run(client, seeded_org.user_headers, "benign-baseline")
    decisions = [r["decision"] for r in run["results"] if r["kind"] == "observation"]
    assert set(decisions) <= {"ALLOW", "AUDIT"}
    db.rollback()
    sessions = [
        s.id for s in db.scalars(select(AgentSession).where(AgentSession.simulation_run_id == run["id"]))
    ]
    assert not list(db.scalars(select(SecurityFinding).where(SecurityFinding.session_id.in_(sessions))))


def test_synthetic_credentials_are_never_stored_raw(client, seeded_org, db):
    for scenario_id in ("sensitive-file-exfiltration", "poisoned-mcp-server", "lethal-trifecta"):
        run = _run(client, seeded_org.user_headers, scenario_id)
        assert not _TOKEN_SHAPE.search(json.dumps(run))
    db.rollback()
    for table in Base.metadata.sorted_tables:
        for row in db.execute(table.select()).mappings():
            text = json.dumps(dict(row), default=str)
            assert not _TOKEN_SHAPE.search(text), f"raw token-shaped value stored in {table.name}"


def test_approvals_opened_by_a_run_are_cancelled_and_audited(client, seeded_org, db):
    run = _run(client, seeded_org.user_headers, "lethal-trifecta")
    assert "closed automatically" in run["summary"]
    db.rollback()
    approvals = list(db.scalars(select(Approval).where(Approval.session_id == run["session_id"])))
    assert approvals and all(a.status == "cancelled" and a.is_simulation for a in approvals)
    actions = set(
        db.scalars(select(AuditEvent.action).where(AuditEvent.organization_id == seeded_org.org_id))
    )
    assert {"approval.cancelled", "simulation.completed"} <= actions
    listed = client.get("/api/v1/approvals", headers=seeded_org.user_headers).json()
    assert all(item["id"] not in {a.id for a in approvals} for item in listed["items"])


def test_disabling_a_policy_is_reported_as_a_regression(client, seeded_org):
    h = seeded_org.user_headers
    suite = ["sensitive-file-exfiltration", "benign-baseline"]
    base = client.post(f"{API}/suites", json={"scenario_ids": suite}, headers=h)
    assert base.status_code == 201, base.text
    base = base.json()
    assert base["run_count"] == 2 and base["passed_count"] == 2

    policies = client.get("/api/v1/policies", params={"limit": 200}, headers=h).json()["items"]
    target = next(p for p in policies if p["name"] == "Block credential exfiltration")
    assert (
        client.patch(f"/api/v1/policies/{target['id']}", json={"enabled": False}, headers=h).status_code
        == 200
    )

    head = client.post(f"{API}/suites", json={"scenario_ids": suite}, headers=h).json()
    assert head["passed_count"] == 1
    diff = client.get(
        f"{API}/suites/compare",
        params={"base": base["suite_run_id"], "head": head["suite_run_id"]},
        headers=h,
    ).json()
    assert diff["regressions"] == 1
    exfil = next(s for s in diff["scenarios"] if s["scenario_id"] == "sensitive-file-exfiltration")
    assert exfil["status"] == "regressed"
    assert any(
        c["check"] == "decision:send-token" and c["head_passed"] is False for c in exfil["check_changes"]
    )
    assert any(d["step"] == "send-token" and d["base"] == "DENY" for d in exfil["decision_changes"])
    assert (
        next(s for s in diff["scenarios"] if s["scenario_id"] == "benign-baseline")["status"]
        == "unchanged_pass"
    )
    assert any(
        p["policy_id"] == target["id"] and "enabled: True → False" in p["change"]
        for p in diff["policy_changes"]
    )

    listed = client.get(f"{API}/suites", headers=h).json()
    assert listed["total"] == 2 and listed["items"][0]["suite_run_id"] == head["suite_run_id"]
    detail = client.get(f"{API}/suites/{base['suite_run_id']}", headers=h).json()
    assert {r["scenario_id"] for r in detail["runs"]} == set(suite)
    runs = client.get(
        f"{API}/runs", params={"suite_run_id": head["suite_run_id"], "passed": False}, headers=h
    ).json()
    assert [r["scenario_id"] for r in runs["items"]] == ["sensitive-file-exfiltration"]


def test_regression_run_against_a_registered_agent_keeps_its_identity(client, seeded_org, db):
    h = seeded_org.user_headers
    created = client.post(
        "/api/v1/agents",
        json={"name": "release-bot", "framework": "claude_code", "version": "1.4.0"},
        headers=h,
    )
    assert created.status_code in (200, 201), created.text
    agent_id = created.json()["id"]
    run = _run(client, h, "destructive-command", agent_id=agent_id, agent_version="1.5.0-rc1")
    assert run["passed"] is True and run["agent_id"] == agent_id and run["agent_version"] == "1.5.0-rc1"
    db.rollback()
    agent = db.get(Agent, agent_id)
    assert (
        agent.version == "1.4.0" and agent.is_simulation is False
    )  # a simulation never edits the real agent
    session = db.get(AgentSession, run["session_id"])
    assert session.agent_id == agent_id and session.is_simulation is True
    by_agent = client.get(f"{API}/runs", params={"agent_id": agent_id}, headers=h).json()
    assert by_agent["total"] == 1


def test_other_organisations_cannot_see_or_use_runs(client, seeded_org, other_org):
    run = _run(client, seeded_org.user_headers, "destructive-command")
    suite = client.post(
        f"{API}/suites", json={"scenario_ids": ["destructive-command"]}, headers=seeded_org.user_headers
    ).json()
    agent_id = client.post(
        "/api/v1/agents",
        json={"name": "acme-coder", "framework": "claude_code"},
        headers=seeded_org.user_headers,
    ).json()["id"]
    for headers in (other_org.user_headers, other_org.api_headers):
        assert client.get(f"{API}/runs/{run['id']}", headers=headers).status_code == 404
        assert client.get(f"{API}/suites/{suite['suite_run_id']}", headers=headers).status_code == 404
        assert (
            client.get(
                f"{API}/suites/compare",
                params={"base": suite["suite_run_id"], "head": suite["suite_run_id"]},
                headers=headers,
            ).status_code
            == 404
        )
        assert client.get(f"{API}/runs", headers=headers).json()["total"] == 0
        assert client.get(f"{API}/suites", headers=headers).json()["total"] == 0
    assert (
        client.post(
            f"{API}/runs",
            json={"scenario_id": "destructive-command", "agent_id": agent_id},
            headers=other_org.user_headers,
        ).status_code
        == 404
    )


def test_permissions(client, seeded_org, make_org):
    viewer = make_org("Viewer Co", role="viewer")
    assert client.get(f"{API}/scenarios", headers=viewer.user_headers).status_code == 200
    assert (
        client.post(
            f"{API}/runs", json={"scenario_id": "benign-baseline"}, headers=viewer.user_headers
        ).status_code
        == 403
    )
    reader = make_org("Reader Co", scopes=["read"])
    assert (
        client.post(
            f"{API}/runs", json={"scenario_id": "benign-baseline"}, headers=reader.api_headers
        ).status_code
        == 403
    )
    ingest_only = make_org("Ingest Co", scopes=["ingest"])
    assert client.get(f"{API}/runs", headers=ingest_only.api_headers).status_code == 403
    assert (
        client.post(
            f"{API}/runs", json={"scenario_id": "benign-baseline"}, headers=ingest_only.api_headers
        ).status_code
        == 201
    )  # the CLI's `contextos simulate`
    assert client.get(f"{API}/runs").status_code == 401
    bad = client.post(f"{API}/runs", json={"scenario_id": ""}, headers=seeded_org.user_headers)
    assert bad.status_code == 422
    assert (
        client.post(
            f"{API}/runs", json={"scenario_id": "no-such-scenario"}, headers=seeded_org.user_headers
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"{API}/suites",
            json={"scenario_ids": ["benign-baseline", "no-such-scenario"]},
            headers=seeded_org.user_headers,
        ).status_code
        == 404
    )


def test_agent_bound_key_may_only_simulate_its_agent(client, seeded_org, db):
    from app.core.ids import new_id
    from app.core.security import generate_api_key
    from app.models import ApiKey

    agent = client.post(
        "/api/v1/agents", json={"name": "bound-bot", "framework": "custom"}, headers=seeded_org.user_headers
    ).json()
    raw, prefix, key_hash = generate_api_key()
    db.add(
        ApiKey(
            id=new_id("api_key"),
            organization_id=seeded_org.org_id,
            name="bound",
            prefix=prefix,
            key_hash=key_hash,
            scopes=["ingest", "read"],
            agent_id=agent["id"],
        )
    )
    db.commit()
    headers = {"Authorization": f"Bearer {raw}"}
    assert (
        client.post(f"{API}/runs", json={"scenario_id": "benign-baseline"}, headers=headers).status_code
        == 403
    )
    assert (
        client.post(
            f"{API}/runs", json={"scenario_id": "benign-baseline", "agent_id": agent["id"]}, headers=headers
        ).status_code
        == 201
    )


def test_service_contract_used_by_seed_demo_and_task_verification(seeded_org, db):
    scenarios = list_scenarios()
    assert all(hasattr(s, "id") and hasattr(s, "demo") for s in scenarios)
    run = run_scenario(db, seeded_org.org_id, "malicious-readme")  # positional, as the callers use it
    assert isinstance(run, SimulationRun) and run.status == "completed" and run.passed is True and run.summary
    db.rollback()  # flush only: nothing was committed by the service
    assert db.get(SimulationRun, run.id) is None


def test_verify_with_simulation_records_a_real_run(client, seeded_org):
    h = seeded_org.user_headers
    boards = client.get("/api/v1/workspace/boards", headers=h).json()
    board = (
        boards["items"][0]
        if boards.get("items")
        else client.post("/api/v1/workspace/boards", json={"name": "Security"}, headers=h).json()
    )
    detail = client.get(f"/api/v1/workspace/boards/{board['id']}", headers=h).json()
    column_id = detail["columns"][0]["id"]
    task = client.post(
        "/api/v1/workspace/tasks",
        json={"board_id": board["id"], "column_id": column_id, "title": "Block credential exfiltration"},
        headers=h,
    )
    assert task.status_code == 201, task.text
    out = client.post(
        f"/api/v1/workspace/tasks/{task.json()['id']}/verify-with-simulation",
        json={"scenario_id": "sensitive-file-exfiltration"},
        headers=h,
    )
    assert out.status_code == 201, out.text
    assert out.json()["status"] == "passed" and out.json()["kind"] == "simulation"


def test_steps_and_evidence_name_their_session_and_enforcement(client, seeded_org, db):
    """Evidence from the delegated sub-agent opens in the child session, not the parent's."""
    from app.models import AgentSession, PolicyDecision, ToolInvocation

    run = _run(client, seeded_org.user_headers, "multi-agent-contamination")
    steps = {r["step"]: r for r in run["results"] if r["kind"] == "observation"}
    sessions = {
        s.external_session_id: s.id
        for s in db.scalars(select(AgentSession).where(AgentSession.simulation_run_id == run["id"]))
    }
    parent, child = sessions[f"{run['id']}-main"], sessions[f"{run['id']}-child"]

    assert steps["subagent-fetch"]["session_id"] == child
    assert steps["upload-env"]["session_id"] == parent and steps["delegate-research"]["session_id"] == parent
    assert steps["upload-env"]["enforcement"] == "enforced"
    assert steps["upload-env"]["decision"] in {"DENY", "REQUIRE_APPROVAL"}
    assert steps["delegate-research"]["enforcement"] is None  # no tool decision at this step

    for row in steps["subagent-fetch"]["evidence"]:
        assert row["session_id"] == child
        model = {"policy_decision": PolicyDecision, "tool_invocation": ToolInvocation}.get(row["type"])
        if model is not None:  # the referenced record really belongs to the child session
            assert db.get(model, row["id"]).session_id == child
    checks = {r["step"]: r for r in run["results"] if r["kind"] == "expectation"}
    contamination = checks["finding:cross_agent_contamination"]["evidence"]
    assert contamination and all(e["session_id"] in {parent, child} for e in contamination)
