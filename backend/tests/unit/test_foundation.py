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


def test_audit_details_are_redacted_before_storage(db, org):
    import json

    from app.models import AuditEvent

    token = "ghp_" + "Zq8RtY2uV4wX6yA1bC3dE5fG7hJ9kL0mN2pQ"
    append_audit(db, org.org_id, action="test.secret", details={"note": f"leaked {token}", "nested": {"k": [token]}})
    db.commit()
    stored = db.query(AuditEvent).filter_by(organization_id=org.org_id, action="test.secret").one()
    assert token not in json.dumps(stored.details) and "leaked" in stored.details["note"]
    assert verify_chain(db, org.org_id)["valid"] is True


def test_audit_without_details_stores_an_empty_object(db, org):
    entry = append_audit(db, org.org_id, action="test.empty")
    db.commit()
    assert entry.details == {} and verify_chain(db, org.org_id)["valid"] is True
