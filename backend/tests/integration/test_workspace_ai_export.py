"""Engineering Workspace AI: context-pack export, suggested profiles and the server-side repository root."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.core.config import Settings, get_settings
from app.models import AuditEvent, Task
from app.services.workspace_ai_packs import default_profile
from app.workspace.modes import PromptMode
from tests.integration.ingestion_support import GITHUB_TOKEN
from tests.integration.workspace_ai_support import AI, ENV_SECRET, injection_task, item_by_ref, make_repo
from tests.integration.workspace_support import add_member, create_task, ok


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    root = make_repo(tmp_path)
    monkeypatch.setattr(get_settings(), "workspace_repo_root", str(root))
    return root


@pytest.fixture()
def no_root(monkeypatch):
    monkeypatch.setattr(get_settings(), "workspace_repo_root", None)


def _pack(client, headers, task_id: str, **body) -> dict:
    return ok(client.post(f"{AI}/context-packs", json={"task_id": task_id, **body}, headers=headers), 201)


def _audits(db, org_id: str, action: str) -> list[AuditEvent]:
    db.rollback()
    return list(db.scalars(select(AuditEvent).where(AuditEvent.organization_id == org_id,
                                                    AuditEvent.action == action)))


# ----------------------------------------------------------------------------- export


def test_export_downloads_the_pack_as_redacted_json_and_audits_it(client, org, db, repo):
    h = org.user_headers
    task = create_task(client, h, "Harden the loader", task_type="backend", related_files=["src/loader.py", ".env"])
    pack = _pack(client, h, task["id"], profile="standard")

    res = client.get(f"{AI}/context-packs/{pack['id']}/export", headers=h)
    assert res.status_code == 200, res.text
    assert res.headers["content-type"].startswith("application/json")
    disposition = res.headers["content-disposition"]
    assert disposition.startswith("attachment;") and f"context-pack-{task['key']}-standard.json" in disposition
    assert res.headers["cache-control"] == "no-store"
    doc = json.loads(res.text)
    assert doc["external_transfer"] is False and "no external AI provider" in doc["generated_by"]
    assert doc["task"] == {"id": task["id"], "key": task["key"], "title": "Harden the loader"}
    exported = doc["context_pack"]
    assert exported["id"] == pack["id"] and exported["profile"] == "standard"
    assert [i["key"] for i in exported["items"]] == [i["key"] for i in pack["items"]]
    assert "def load" in item_by_ref(exported, "src/loader.py")["excerpt"]
    # Secrets in repository files never leave the server: neither the token in source nor the .env value.
    assert GITHUB_TOKEN not in res.text and ENV_SECRET not in res.text
    assert item_by_ref(exported, ".env")["status"] == "excluded_sensitive"

    [entry] = _audits(db, org.org_id, "context_pack.exported")
    assert entry.target_type == "context_pack" and entry.target_id == pack["id"]
    assert entry.actor_type == "user" and entry.actor_id == org.user_id
    assert entry.details["task_id"] == task["id"] and entry.details["format"] == "json"
    assert entry.details["included"] == exported["counts"]["included"]


def test_export_of_a_pack_built_without_a_repository(client, seeded_org, db, no_root):
    task, finding = injection_task(client, seeded_org, db)
    pack = _pack(client, seeded_org.user_headers, task["id"])
    res = client.get(f"{AI}/context-packs/{pack['id']}/export", headers=seeded_org.user_headers)
    assert res.status_code == 200
    doc = res.json()
    assert doc["context_pack"]["repository_verified"] is False
    assert any(n.startswith("No repository root configured") for n in doc["context_pack"]["notes"])
    assert item_by_ref(doc["context_pack"], f"finding:{finding.id}")["included"] is True
    assert GITHUB_TOKEN not in res.text


def test_export_isolation_and_permissions(client, org, other_org, db, no_root, make_org):
    task = create_task(client, org.user_headers, "Investigate")
    pack = _pack(client, org.user_headers, task["id"])
    url = f"{AI}/context-packs/{pack['id']}/export"

    assert client.get(url, headers=other_org.user_headers).status_code == 404
    assert client.get(f"{AI}/context-packs/ctp_00000000000000000000000000/export",
                      headers=org.user_headers).status_code == 404
    assert client.get(url).status_code == 401
    _, viewer = add_member(db, org.org_id, "viewer", "Vera Viewer")
    db.commit()
    assert client.get(url, headers=viewer).status_code == 200  # exporting is a read
    ingest_only = make_org("Ingest Only", scopes=["ingest"])
    assert client.get(url, headers=ingest_only.api_headers).status_code == 403  # no read scope
    assert client.get(f"{AI}/modes", headers=ingest_only.api_headers).status_code == 403
    # Only the successful exports were audited, in the owning organisation only.
    assert len(_audits(db, org.org_id, "context_pack.exported")) == 1
    assert _audits(db, other_org.org_id, "context_pack.exported") == []


# ----------------------------------------------------------------------------- suggested profile


def test_modes_suggest_a_profile_for_a_task(client, seeded_org, db, no_root):
    h = seeded_org.user_headers
    plain = create_task(client, h, "Tidy the README", task_type="feature")
    out = ok(client.get(f"{AI}/modes", params={"task_id": plain["id"]}, headers=h))
    assert out["task_id"] == plain["id"] and out["mode"] == "implement_fix"
    assert out["suggested_profile"] == "standard"
    assert set(out["suggested_profiles"]) == {m.value for m in PromptMode}
    assert out["suggested_profiles"]["security_harden"] == "security_critical"
    assert out["suggested_profiles"]["full_autonomous_remediation"] == "deep"
    assert out["suggested_profiles"]["investigate_only"] == "standard"
    assert out["modes"] and out["profiles"]  # still the full catalogue

    harden = ok(client.get(f"{AI}/modes", params={"task_id": plain["id"], "mode": "security_harden"}, headers=h))
    assert harden["mode"] == "security_harden" and harden["suggested_profile"] == "security_critical"

    # A task opened from a finding is security work in every mode — the same rule the server applies
    # when it builds a pack without an explicit profile.
    security, _ = injection_task(client, seeded_org, db)
    sec = ok(client.get(f"{AI}/modes", params={"task_id": security["id"]}, headers=h))
    assert set(sec["suggested_profiles"].values()) == {"security_critical"}
    db.rollback()
    row = db.scalars(select(Task).where(Task.id == security["id"])).one()
    assert all(sec["suggested_profiles"][m.value] == default_profile(row, m.value) for m in PromptMode)


def test_modes_without_task_and_errors(client, org, other_org, no_root):
    out = ok(client.get(f"{AI}/modes", headers=org.user_headers))
    assert out["task_id"] is None and out["suggested_profile"] is None and out["suggested_profiles"] == {}
    foreign = create_task(client, other_org.user_headers, "Globex task")
    assert client.get(f"{AI}/modes", params={"task_id": foreign["id"]}, headers=org.user_headers).status_code == 404
    own = create_task(client, org.user_headers, "Mine")
    bad = client.get(f"{AI}/modes", params={"task_id": own["id"], "mode": "rm_rf"}, headers=org.user_headers)
    assert bad.status_code == 422 and bad.json()["error"]["code"]


# ----------------------------------------------------------------------------- repository root


def test_repository_root_comes_only_from_server_settings(client, org, repo, tmp_path):
    h = org.user_headers
    task = create_task(client, h, "Loader")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    for body in ({"repo_root": str(elsewhere)}, {"repository_root": str(elsewhere)}, {"workspace_repo_root": "/"}):
        res = client.post(f"{AI}/context-packs", json={"task_id": task["id"], **body}, headers=h)
        assert res.status_code == 422, body
    assert ok(client.get(f"{AI}/modes", headers=h))["repository_configured"] is True
    pack = _pack(client, h, task["id"], extra_paths=["src/loader.py"])
    assert pack["repository_verified"] is True and item_by_ref(pack, "src/loader.py")["verified"] is True


def test_repo_root_setting_names(monkeypatch, tmp_path):
    monkeypatch.delenv("CONTEXTOS_WORKSPACE_ROOT", raising=False)
    monkeypatch.setenv("CONTEXTOS_WORKSPACE_REPO_ROOT", f"  {tmp_path}  ")
    assert Settings().workspace_repo_root == str(tmp_path)
    monkeypatch.delenv("CONTEXTOS_WORKSPACE_REPO_ROOT")
    monkeypatch.setenv("CONTEXTOS_WORKSPACE_ROOT", str(tmp_path))  # the older name still works
    assert Settings().workspace_repo_root == str(tmp_path)
    monkeypatch.setenv("CONTEXTOS_WORKSPACE_ROOT", "   ")
    assert Settings().workspace_repo_root is None
    monkeypatch.delenv("CONTEXTOS_WORKSPACE_ROOT")
    monkeypatch.setenv("WORKSPACE_REPO_ROOT", "/not-a-contextos-variable")
    assert Settings().workspace_repo_root is None
