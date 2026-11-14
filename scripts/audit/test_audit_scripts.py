"""Tests for route_audit.py and doc_paths.py.

    backend/.venv/bin/python -m pytest -q -p no:cacheprovider scripts/audit
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import doc_paths  # noqa: E402
import route_audit  # noqa: E402

route_audit.prepare_environment()

from app.api.deps import Principal, get_principal, require, require_user  # noqa: E402
from app.core.errors import register_error_handlers  # noqa: E402
from fastapi import APIRouter, Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


def _tiny_app() -> FastAPI:
    inner = APIRouter(prefix="/items")

    @inner.get("")
    def list_items(p: Principal = Depends(require("read"))) -> dict:
        return {}

    @inner.get("/stats")
    def stats(p: Principal = Depends(require("read"))) -> dict:
        return {}

    @inner.get("/{item_id}")
    def get_item(item_id: str, p: Principal = Depends(get_principal)) -> dict:
        return {}

    @inner.patch("/{item_id}")
    def edit_item(item_id: str, p: Principal = Depends(require("read"))) -> dict:
        return {}

    @inner.get("/files/{path:path}")
    def get_file(path: str) -> dict:
        return {"path": path}

    @inner.get("/me")
    def me(p: Principal = Depends(require_user)) -> dict:
        return {}

    api = APIRouter(prefix="/api/v1")
    api.include_router(inner)
    app = FastAPI()
    register_error_handlers(app)
    app.include_router(api)
    return app


def _infos(app: FastAPI) -> list[route_audit.RouteInfo]:
    return [i for path, route, inh in route_audit.iter_api_routes(app.router) for i in route_audit.analyse(path, route, inh)]


def test_walk_yields_full_paths_in_registration_order() -> None:
    paths = [(i.method, i.path) for i in _infos(_tiny_app())]
    assert paths == [("GET", "/api/v1/items"), ("GET", "/api/v1/items/stats"), ("GET", "/api/v1/items/{item_id}"),
                     ("PATCH", "/api/v1/items/{item_id}"), ("GET", "/api/v1/items/files/{path:path}"),
                     ("GET", "/api/v1/items/me")]


def test_analyse_detects_principal_permissions_and_user_only() -> None:
    by = {(i.method, i.path): i for i in _infos(_tiny_app())}
    assert by[("GET", "/api/v1/items")].permissions == ["read"]
    assert by[("GET", "/api/v1/items/{item_id}")].authenticated and by[("GET", "/api/v1/items/{item_id}")].permissions == []
    assert not by[("GET", "/api/v1/items/files/{path:path}")].authenticated
    assert by[("GET", "/api/v1/items/me")].user_only and by[("GET", "/api/v1/items/me")].authenticated


def test_template_regex_and_first_match_wins() -> None:
    assert route_audit.template_regex("/a/{x}").match("/a/abc")
    assert not route_audit.template_regex("/a/{x}").match("/a/abc/def")
    assert route_audit.template_regex("/a/{p:path}").match("/a/b/c.txt")
    infos = _infos(_tiny_app())
    patterns = [route_audit.template_regex(i.path) for i in infos]
    hit = route_audit.match_route(infos, patterns, "GET", "/api/v1/items/stats")
    assert hit is not None and hit.path == "/api/v1/items/stats"  # static route registered before {item_id}
    hit = route_audit.match_route(infos, patterns, "PATCH", "/api/v1/items/itm_1")
    assert hit is not None and hit.method == "PATCH" and hit.path == "/api/v1/items/{item_id}"
    assert route_audit.match_route(infos, patterns, "DELETE", "/api/v1/items/itm_1") is None


def test_recorder_captures_requests_only_inside_a_test_and_restores_transport() -> None:
    from starlette import testclient

    original = testclient._TestClientTransport.handle_request
    recorder = route_audit.Recorder()
    recorder.pytest_sessionstart(session=None)
    try:
        with TestClient(_tiny_app()) as client:
            client.get("/api/v1/items/files/a/b")  # outside a test item: not recorded
            recorder.current = "tests/integration/test_x.py::test_isolated"
            client.get("/api/v1/items/files/a/b")
            client.get("/api/v1/items")  # no credentials → 401
    finally:
        recorder.pytest_sessionfinish(session=None, exitstatus=0)
    assert testclient._TestClientTransport.handle_request is original
    assert [(h.method, h.path, h.status) for h in recorder.hits] == [
        ("GET", "/api/v1/items/files/a/b", 200), ("GET", "/api/v1/items", 401)]


def test_apply_hits_marks_requests_and_404s() -> None:
    infos = _infos(_tiny_app())
    route_audit.apply_hits(infos, [route_audit.Hit("t", "GET", "/api/v1/items/x", 404),
                                   route_audit.Hit("t", "GET", "/api/v1/items", 200)])
    by = {(i.method, i.path): i for i in infos}
    assert by[("GET", "/api/v1/items/{item_id}")].isolation_404
    assert by[("GET", "/api/v1/items")].isolation_requests == 1
    assert by[("PATCH", "/api/v1/items/{item_id}")].isolation_requests == 0


def test_real_application_routes_walk_and_public_set() -> None:
    infos, _empty, unregistered = route_audit.collect_routes()  # raises if the walk disagrees with OpenAPI
    keys = {(i.method, i.path) for i in infos}
    assert route_audit.PUBLIC <= keys
    assert ("GET", "/api/v1/findings/{finding_id}") in keys
    assert unregistered == []
    assert all(i.authenticated for i in infos if i.path.startswith("/api/v1/findings"))


def test_doc_paths_heuristics() -> None:
    assert doc_paths.looks_like_path("backend/app/core/errors.py")
    assert doc_paths.looks_like_path("features/intelligence/api.ts")
    assert doc_paths.looks_like_path("docs/**/*.md")
    for not_a_path in ("tools/call", "*Out", "Page[T]", "trust-*", "203.0.113.0/24", "/api/v1/events",
                       "cd backend && pytest", "features/<name>/api.ts", "https://example.com/a.md"):
        assert not doc_paths.looks_like_path(not_a_path), not_a_path


def test_doc_paths_resolution(tmp_path: Path) -> None:
    assert doc_paths._exists("integrations/claude_code/enforce.py", tmp_path)  # suffix of sdk/contextos/...
    assert doc_paths._exists("tests/integration/*_support.py", tmp_path)
    assert doc_paths._exists("frontend/src/**/*.{ts,tsx}", tmp_path)
    assert not doc_paths._exists("docs/NO_SUCH_DOC.md", tmp_path)
    assert doc_paths.check_dotted("app.services.scoping.get_scoped") is None
    assert doc_paths.check_dotted("app.core.errors") is None
    assert doc_paths.check_dotted("app.core.errors.NoSuchError") is not None
    assert doc_paths.check_dotted("app.nowhere.deeper") == "'nowhere.deeper' not found in backend/app/__init__.py"
    assert doc_paths.check_dotted("contextos.nowhere") is not None
    assert doc_paths._dotted_alternatives("app.services.scoping.scoped/get_scoped") == [
        "app.services.scoping.scoped", "app.services.scoping.get_scoped"]


def test_doc_paths_scan_document_reports_only_missing(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text("See `backend/app/main.py`, `app.core.ids.new_id` and `docs/MISSING.md`.\n"
                   "```bash\ncat docs/ALSO_MISSING_BUT_IN_A_FENCE.md\n```\n"
                   "Settings live in `.claude/settings.json` of your project. Link: [x](nope/gone.md)\n")
    found = [(m.line, m.ref) for m in doc_paths.scan_document(doc)]
    assert found == [(1, "docs/MISSING.md"), (5, "nope/gone.md")]
