"""Task evidence: attachments, code links, context references, fix attempts and verification runs
(including Simulation Lab verification)."""

from __future__ import annotations

import sys
import types

from sqlalchemy import select

from app.core.ids import new_id
from app.models import Agent, IngestedEvent, SimulationRun, TaskAttachment, VerificationRun
from tests.integration.ingestion_support import GITHUB_TOKEN, run_tool
from tests.integration.workspace_support import (
    API,
    activity_kinds,
    board_by_name,
    column,
    create_task,
    get_task,
    move,
    ok,
    verify,
)


def test_attachments_are_redacted_and_capped(client, org, db):
    task = create_task(client, org.user_headers)
    path = f"{API}/tasks/{task['id']}/attachments"
    att = ok(
        client.post(
            path,
            json={"name": "ci.log", "kind": "log", "content": f"export GH={GITHUB_TOKEN}\nok"},
            headers=org.user_headers,
        ),
        201,
    )
    assert GITHUB_TOKEN not in att["content"] and "[REDACTED:" in att["content"]
    assert att["size"] == len(att["content"].encode()) and att["created_by"]["id"] == org.user_id
    too_big = client.post(
        path,
        json={"name": "huge.log", "kind": "log", "content": "x" * (100 * 1024 + 1)},
        headers=org.user_headers,
    )
    assert too_big.status_code == 413
    assert client.post(path, json={"name": "l", "kind": "link"}, headers=org.user_headers).status_code == 422
    assert (
        client.post(
            path, json={"name": "l", "kind": "link", "url": "javascript:alert(1)"}, headers=org.user_headers
        ).status_code
        == 422
    )
    link = ok(
        client.post(
            path,
            json={"name": "Runbook", "kind": "link", "url": "https://wiki.acme.test/runbook"},
            headers=org.user_headers,
        ),
        201,
    )
    ok(client.delete(f"{API}/tasks/attachments/{link['id']}", headers=org.user_headers), 204)
    detail = get_task(client, org.user_headers, task["id"])
    assert [a["id"] for a in detail["attachments"]] == [att["id"]]
    db.rollback()
    assert all(GITHUB_TOKEN not in (a.content or "") for a in db.scalars(select(TaskAttachment)))


def test_code_links(client, org):
    task = create_task(client, org.user_headers)
    path = f"{API}/tasks/{task['id']}/links"
    ok(
        client.post(path, json={"kind": "branch", "ref": "fix/ctx-1-injection"}, headers=org.user_headers),
        201,
    )
    links = ok(client.post(path, json={"kind": "commit", "ref": "a1b2c3d4e5"}, headers=org.user_headers), 201)
    assert [c["ref"] for c in links["commit"]] == ["a1b2c3d4e5"] and links["branch"][0]["index"] == 0
    assert (
        client.post(path, json={"kind": "commit", "ref": "not-a-sha"}, headers=org.user_headers).status_code
        == 422
    )
    pr = {
        "kind": "pull_request",
        "url": "https://github.com/acme/app/pull/9",
        "title": "Fix",
        "state": "draft",
    }
    links = ok(client.post(path, json=pr, headers=org.user_headers), 201)
    assert links["pull_request"][0]["state"] == "draft"
    assert client.post(path, json=pr, headers=org.user_headers).status_code == 409
    bad_state = client.post(
        path,
        json={**pr, "url": "https://github.com/acme/app/pull/10", "state": "weird"},
        headers=org.user_headers,
    )
    assert bad_state.status_code == 422
    remaining = ok(client.delete(f"{path}/branch/0", headers=org.user_headers))
    assert remaining["branch"] == []
    assert client.delete(f"{path}/branch/0", headers=org.user_headers).status_code == 404
    assert {"linked", "unlinked"} <= set(activity_kinds(get_task(client, org.user_headers, task["id"])))


def test_context_refs_must_exist_in_the_same_organisation(client, seeded_org, other_org, db):
    run_tool(
        client,
        seeded_org.api_headers,
        "Read",
        {"file_path": "/work/app/notes.md"},
        "Plain notes, nothing unusual.",
    )
    db.rollback()
    agent_id = db.scalar(select(Agent.id).where(Agent.organization_id == seeded_org.org_id))
    row = db.scalars(select(IngestedEvent).where(IngestedEvent.organization_id == seeded_org.org_id)).first()
    event = {"id": row.id, "event_type": row.event_type}
    task = create_task(client, seeded_org.user_headers)
    path = f"{API}/tasks/{task['id']}/refs"

    ref = ok(
        client.post(
            path,
            json={"ref_type": "agent", "ref_id": agent_id, "note": "affected agent"},
            headers=seeded_org.user_headers,
        ),
        201,
    )
    assert ref["label"] == "coder" and ref["exists"] is True and "claude_code" in ref["detail"]
    ev = ok(
        client.post(path, json={"ref_type": "event", "ref_id": event["id"]}, headers=seeded_org.user_headers),
        201,
    )
    assert ev["label"].startswith(event["event_type"])
    assert (
        client.post(
            path, json={"ref_type": "agent", "ref_id": agent_id}, headers=seeded_org.user_headers
        ).status_code
        == 409
    )
    assert (
        client.post(
            path, json={"ref_type": "finding", "ref_id": "fnd_missing"}, headers=seeded_org.user_headers
        ).status_code
        == 404
    )
    # The other organisation cannot attach this organisation's records to its own tasks.
    theirs = create_task(client, other_org.user_headers)
    leaked = client.post(
        f"{API}/tasks/{theirs['id']}/refs",
        json={"ref_type": "agent", "ref_id": agent_id},
        headers=other_org.user_headers,
    )
    assert leaked.status_code == 404
    assert client.delete(f"{API}/tasks/refs/{ref['id']}", headers=other_org.user_headers).status_code == 404
    ok(client.delete(f"{API}/tasks/refs/{ref['id']}", headers=seeded_org.user_headers), 204)
    assert [r["ref_type"] for r in get_task(client, seeded_org.user_headers, task["id"])["refs"]] == ["event"]


def test_claimed_complete_never_verifies_or_resolves(client, org):
    board = board_by_name(client, org.user_headers, "Security Remediation")
    verified = column(board, "Verified")
    task = create_task(client, org.user_headers, board_id=board["id"])
    attempt = ok(
        client.post(
            f"{API}/tasks/{task['id']}/fix-attempts",
            json={
                "agent_tool": "claude_code",
                "status": "in_progress",
                "branch": "fix/ctx-1",
                "pr_url": "https://github.com/acme/app/pull/3",
                "notes": f"used {GITHUB_TOKEN}",
            },
            headers=org.user_headers,
        ),
        201,
    )
    assert attempt["started_at"] is not None and GITHUB_TOKEN not in attempt["notes"]
    claimed = ok(
        client.patch(
            f"{API}/tasks/fix-attempts/{attempt['id']}",
            json={"status": "claimed_complete"},
            headers=org.user_headers,
        )
    )
    assert claimed["is_claim_only"] is True and claimed["completed_at"] is not None
    detail = get_task(client, org.user_headers, task["id"])
    assert detail["verification_status"] == "unverified" and detail["resolution"] is None
    assert detail["is_done"] is False and detail["column_name"] == "Triage"
    assert [p["url"] for p in detail["links"]["pull_request"]] == ["https://github.com/acme/app/pull/3"]
    claim = next(a for a in detail["activity"] if a["kind"] == "fix_attempt_updated")
    assert "Claim only" in claim["details"]["note"]
    assert move(client, org.user_headers, task["id"], verified["id"]).status_code == 409

    direct = client.patch(
        f"{API}/tasks/fix-attempts/{attempt['id']}", json={"status": "verified"}, headers=org.user_headers
    )
    assert direct.status_code == 409 and "verification run" in direct.json()["error"]["message"]
    created_verified = client.post(
        f"{API}/tasks/{task['id']}/fix-attempts", json={"status": "verified"}, headers=org.user_headers
    )
    assert created_verified.status_code == 409

    run = verify(
        client,
        org.user_headers,
        task["id"],
        "passed",
        fix_attempt_id=attempt["id"],
        evidence={"tests_passed": 120, "tests_failed": 0},
        command="pytest -q",
    )
    assert run["fix_attempt_id"] == attempt["id"] and run["evidence"]["tests_passed"] == 120
    detail = get_task(client, org.user_headers, task["id"])
    assert detail["verification_status"] == "passed" and detail["verified_at"] is not None
    assert detail["fix_attempts"][0]["status"] == "verified"


def test_failed_verification_after_pass_regresses(client, org):
    task = create_task(client, org.user_headers)
    verify(client, org.user_headers, task["id"], "passed")
    errored = verify(client, org.user_headers, task["id"], "error")
    assert errored["task_verification_status"] == "passed"  # an errored run proves nothing either way
    failed = verify(client, org.user_headers, task["id"], "failed", kind="code_review")
    assert failed["task_verification_status"] == "failed"
    detail = get_task(client, org.user_headers, task["id"])
    assert detail["verified_at"] is None
    regressed = next(a for a in detail["activity"] if a["kind"] == "verification_regressed")
    assert (regressed["from_value"], regressed["to_value"]) == ("passed", "failed")
    assert [r["status"] for r in detail["verification_runs"]] == ["failed", "error", "passed"]
    missing_status = client.post(
        f"{API}/tasks/{task['id']}/verifications", json={"kind": "manual"}, headers=org.user_headers
    )
    assert missing_status.status_code == 422


def _sim_run(db, org_id: str, passed: bool | None, status: str = "completed") -> SimulationRun:
    run = SimulationRun(
        id=new_id("simulation_run"),
        organization_id=org_id,
        scenario_id="prompt_injection_readme",
        scenario_name="Prompt injection in README",
        status=status,
        passed=passed,
        results=[{"step": 1, "passed": bool(passed)}, {"step": 2, "passed": True}],
        summary="Injected instructions were flagged and the exfiltration call was denied.",
    )
    db.add(run)
    db.commit()
    return run


def test_simulation_verification_takes_status_from_the_recorded_run(client, org, other_org, db):
    task = create_task(client, org.user_headers)
    path = f"{API}/tasks/{task['id']}/verifications"
    run = _sim_run(db, org.org_id, passed=False)
    out = ok(
        client.post(path, json={"kind": "simulation", "simulation_run_id": run.id}, headers=org.user_headers),
        201,
    )
    assert out["status"] == "failed" and out["simulation_run_id"] == run.id
    assert (
        out["evidence"]["scenario_id"] == "prompt_injection_readme" and out["evidence"]["results_total"] == 2
    )
    forged = client.post(
        path,
        json={"kind": "simulation", "simulation_run_id": run.id, "status": "passed"},
        headers=org.user_headers,
    )
    assert forged.status_code == 422
    foreign = _sim_run(db, other_org.org_id, passed=True)
    assert (
        client.post(
            path, json={"kind": "simulation", "simulation_run_id": foreign.id}, headers=org.user_headers
        ).status_code
        == 404
    )
    assert client.post(path, json={"kind": "simulation"}, headers=org.user_headers).status_code == 422


def test_verify_with_simulation_runs_the_scenario(client, org, db, monkeypatch):
    calls: list[tuple[str, str]] = []

    def run_scenario(session, org_id, scenario_id):
        calls.append((org_id, scenario_id))
        run = SimulationRun(
            id=new_id("simulation_run"),
            organization_id=org_id,
            scenario_id=scenario_id,
            scenario_name="Credential exfiltration",
            status="completed",
            passed=True,
            results=[{"step": 1, "passed": True}],
            summary="Exfiltration attempt was denied.",
        )
        session.add(run)
        session.flush()
        return run

    fake = types.ModuleType("app.services.simulations")
    fake.run_scenario = run_scenario  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "app.services.simulations", fake)
    task = create_task(client, org.user_headers)
    out = ok(
        client.post(
            f"{API}/tasks/{task['id']}/verify-with-simulation",
            json={"scenario_id": "cred_exfil"},
            headers=org.user_headers,
        ),
        201,
    )
    assert calls == [(org.org_id, "cred_exfil")]
    assert (
        out["kind"] == "simulation"
        and out["status"] == "passed"
        and out["task_verification_status"] == "passed"
    )
    assert out["summary"] == "Exfiltration attempt was denied."
    db.rollback()
    stored = db.scalar(select(VerificationRun).where(VerificationRun.id == out["id"]))
    sim = db.get(SimulationRun, stored.simulation_run_id)
    assert sim.organization_id == org.org_id and sim.triggered_by_user_id == org.user_id

    monkeypatch.setitem(sys.modules, "app.services.simulations", None)
    unavailable = client.post(
        f"{API}/tasks/{task['id']}/verify-with-simulation",
        json={"scenario_id": "x"},
        headers=org.user_headers,
    )
    assert unavailable.status_code == 503 and unavailable.json()["error"]["code"] == "simulation_unavailable"


def test_evidence_endpoints_are_isolated(client, org, other_org):
    task = create_task(client, org.user_headers)
    attempt = ok(
        client.post(f"{API}/tasks/{task['id']}/fix-attempts", json={}, headers=org.user_headers), 201
    )
    h = other_org.user_headers
    assert (
        client.patch(f"{API}/tasks/fix-attempts/{attempt['id']}", json={"notes": "x"}, headers=h).status_code
        == 404
    )
    assert (
        client.post(
            f"{API}/tasks/{task['id']}/verifications", json={"kind": "manual", "status": "passed"}, headers=h
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"{API}/tasks/{task['id']}/links", json={"kind": "branch", "ref": "x"}, headers=h
        ).status_code
        == 404
    )
    theirs = create_task(client, h)
    cross = client.post(
        f"{API}/tasks/{theirs['id']}/verifications",
        json={"kind": "manual", "status": "passed", "fix_attempt_id": attempt["id"]},
        headers=h,
    )
    assert cross.status_code == 404
