from app.core.ids import new_id
from app.services.audit import append_audit, verify_chain


def test_ids_are_prefixed_and_sortable():
    a, b = new_id("agent"), new_id("agent")
    assert a.startswith("agt_") and len(a) == 30
    assert a != b


def test_health(client):
    assert client.get("/api/v1/health").json() == {"status": "ok"}
    assert client.get("/api/v1/ready").json()["database"] == "ok"


def test_audit_chain_detects_tampering(db, org, monkeypatch):
    import app.services.audit as audit

    monkeypatch.setattr(audit, "_safe_details", lambda d: d or {})
    for i in range(3):
        append_audit(db, org.org_id, action="test.action", details={"i": i})
    db.commit()
    assert verify_chain(db, org.org_id)["valid"] is True
    from app.models import AuditEvent

    entry = db.query(AuditEvent).filter_by(organization_id=org.org_id, seq=2).one()
    entry.details = {"i": 99}
    db.commit()
    result = verify_chain(db, org.org_id)
    assert result["valid"] is False and result["first_invalid_seq"] == 2
