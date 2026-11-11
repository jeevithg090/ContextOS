#!/usr/bin/env python3
"""Audit the ContextOS API surface: authentication, permissions and org-isolation test coverage.

Run from the repository root with the backend virtualenv:

    backend/.venv/bin/python .claude/skills/repo-audit/scripts/route_audit.py           # static + isolation run
    backend/.venv/bin/python .claude/skills/repo-audit/scripts/route_audit.py --static  # no tests (seconds)
    backend/.venv/bin/python .claude/skills/repo-audit/scripts/route_audit.py --json    # machine-readable
    ... --tests tests/integration/test_findings_api.py   # limit the isolation run (default tests/integration)
    ... --strict                                          # exit 1 when any gap is reported

Reports:
1. Routes with no authenticated principal (no ``get_principal`` in the dependency tree) that are
   not in ``PUBLIC``.
2. Unsafe methods (POST/PUT/PATCH/DELETE) guarded only by the ``read`` permission, except the
   reviewed dry-run POSTs in ``READ_ONLY_POSTS``.
3. Route modules in ``app/api/routes`` that register no routes, or are not included in the API router.
4. Isolation coverage (skipped with ``--static``): runs only the tests whose fixtures include
   ``other_org`` with a recorder on the TestClient transport, then lists authenticated routes never
   requested during such a test and id routes that never answered 404 there.

Coverage is evidence, not proof: a route requested in an isolation test may have been called only
with the owning organisation's headers. Read the test before relying on it.
Exit codes: 0 ok (or gaps without --strict), 1 gaps with --strict, 2 the audit itself failed.
"""

from __future__ import annotations

import argparse
import atexit
import contextlib
import importlib
import inspect
import json
import os
import pkgutil
import re
import shutil
import sys
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[4]
BACKEND = REPO / "backend"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
PUBLIC = {  # intentionally unauthenticated: liveness, first-run setup and sign-in
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/ready"),
    ("GET", "/api/v1/auth/setup-status"),
    ("POST", "/api/v1/auth/setup"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/logout"),
}
# POSTs that only need ``read`` because they are reviewed dry runs (nothing persisted) or check a
# stronger permission inline before persisting. Add a route here only after reading its service.
READ_ONLY_POSTS = {
    "/api/v1/scan",                       # detection on submitted content, nothing stored
    "/api/v1/trust/rules/test",           # trust_service_dryrun.run_rule_test
    "/api/v1/trust/destinations/verify",  # destination checks on the name only
    "/api/v1/policies/validate",          # draft validation
    "/api/v1/policies/test",              # policy dry run
    "/api/v1/replay/counterfactual",      # simulation, nothing persisted
    "/api/v1/workspace/ai/fix-context",   # save=true requires write inline
    "/api/v1/workspace/ai/breakdown",     # draft only; creating tasks is a separate write route
}


@dataclass
class RouteInfo:
    method: str
    path: str
    endpoint: str
    authenticated: bool
    user_only: bool
    permissions: list[str]
    isolation_requests: int = 0
    isolation_404: bool = False

    @property
    def has_id(self) -> bool:
        return "{" in self.path


@dataclass
class Hit:
    nodeid: str
    method: str
    path: str
    status: int


@dataclass
class Report:
    routes: list[RouteInfo]
    unexpected_public: list[str] = field(default_factory=list)
    read_guarded_writes: list[str] = field(default_factory=list)
    empty_modules: list[str] = field(default_factory=list)
    unregistered_modules: list[str] = field(default_factory=list)
    isolation_run: bool = False
    isolation_tests: int = 0
    pytest_exit: int | None = None
    not_isolation_tested: list[str] = field(default_factory=list)
    id_routes_without_404: list[str] = field(default_factory=list)

    @property
    def gaps(self) -> int:
        return sum(len(x) for x in (self.unexpected_public, self.read_guarded_writes, self.empty_modules,
                                    self.unregistered_modules, self.not_isolation_tested,
                                    self.id_routes_without_404)) + (1 if self.pytest_exit not in (None, 0) else 0)


def prepare_environment() -> None:
    """Make ``app`` importable without touching backend/data. The values mirror
    backend/tests/conftest.py so the isolation run behaves exactly like a normal test run."""
    os.environ.setdefault("CONTEXTOS_ENV", "test")
    os.environ.setdefault("CONTEXTOS_SECRET_KEY", "test-secret-key-for-contextos-unit-tests-0123456789")
    os.environ.setdefault("CONTEXTOS_SERVE_FRONTEND", "false")
    scratch = tempfile.mkdtemp(prefix="contextos-route-audit-")
    atexit.register(shutil.rmtree, scratch, True)
    os.environ.setdefault("CONTEXTOS_DATABASE_URL", f"sqlite:///{Path(scratch) / 'audit.db'}")
    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))


def iter_api_routes(router: Any, prefix: str = "", inherited: tuple[Callable[..., Any], ...] = ()) -> Iterator[tuple[str, Any, tuple]]:
    """Yield ``(full_path, APIRoute, router-level dependency callables)`` in registration order.

    Handles both FastAPI layouts: routes copied into the parent router (older releases) and
    lazily included routers exposing ``original_router`` / ``include_context`` (0.16x+).
    """
    from fastapi.routing import APIRoute

    for route in router.routes:
        if isinstance(route, APIRoute):
            yield prefix + route.path, route, inherited
        elif hasattr(route, "original_router"):
            ctx = getattr(route, "include_context", None)
            deps = tuple(d.dependency for d in (getattr(ctx, "dependencies", None) or []) if d.dependency)
            yield from iter_api_routes(route.original_router, prefix + (getattr(ctx, "prefix", "") or ""),
                                       inherited + deps)


def _dependency_calls(dependant: Any) -> Iterator[Callable[..., Any]]:
    for dep in dependant.dependencies:
        if dep.call is not None:
            yield dep.call
        yield from _dependency_calls(dep)


def analyse(path: str, route: Any, inherited: tuple = ()) -> list[RouteInfo]:
    from app.api.deps import get_principal, require, require_user

    require_code = require("read").__code__
    calls = list(_dependency_calls(route.dependant)) + list(inherited)
    permissions: set[str] = set()
    for call in calls:
        if getattr(call, "__code__", None) is require_code:
            permissions.add(str(inspect.getclosurevars(call).nonlocals.get("permission")))
    authenticated = any(c is get_principal for c in calls) or bool(permissions) or any(c is require_user for c in calls)
    user_only = any(c is require_user for c in calls)
    endpoint = f"{route.endpoint.__module__}.{route.endpoint.__name__}"
    return [RouteInfo(m, path, endpoint, authenticated, user_only, sorted(permissions))
            for m in sorted(route.methods - {"HEAD", "OPTIONS"})]


def template_regex(path: str) -> re.Pattern[str]:
    """``/api/v1/tasks/{task_id}`` → regex; ``{x:path}`` spans slashes, ``{x}`` does not."""
    out, pos = [], 0
    for m in re.finditer(r"\{([^}:]+)(:path)?\}", path):
        out.append(re.escape(path[pos:m.start()]))
        out.append(".+" if m.group(2) else "[^/]+")
        pos = m.end()
    out.append(re.escape(path[pos:]))
    return re.compile("^" + "".join(out) + "$")


def match_route(routes: list[RouteInfo], patterns: list[re.Pattern[str]], method: str, path: str) -> RouteInfo | None:
    """First route (registration order) whose template and method match, as Starlette routes it."""
    for info, pattern in zip(routes, patterns, strict=True):
        if info.method == method and pattern.match(path):
            return info
    return None


class Recorder:
    """pytest plugin: keep only ``other_org`` tests and record every TestClient request they make."""

    def __init__(self) -> None:
        self.current: str | None = None
        self.hits: list[Hit] = []
        self.selected = 0

    def pytest_collection_modifyitems(self, config: Any, items: list[Any]) -> None:
        keep = [i for i in items if "other_org" in getattr(i, "fixturenames", ())]
        dropped = [i for i in items if i not in keep]
        if dropped:
            config.hook.pytest_deselected(items=dropped)
        items[:] = keep
        self.selected = len(keep)

    def pytest_runtest_setup(self, item: Any) -> None:
        self.current = item.nodeid

    def pytest_runtest_teardown(self, item: Any) -> None:
        self.current = None

    # Patch inside the session (not before pytest.main) so pytest's assertion rewriting sees a clean import state.
    def pytest_sessionstart(self, session: Any) -> None:
        from starlette import testclient

        transport = getattr(testclient, "_TestClientTransport", None)
        if transport is None:
            raise RuntimeError("starlette.testclient._TestClientTransport not found; update route_audit.py")
        original = transport.handle_request
        recorder = self

        def handle_request(transport_self: Any, request: Any) -> Any:
            response = original(transport_self, request)
            if recorder.current is not None:
                recorder.hits.append(Hit(recorder.current, request.method, request.url.path, response.status_code))
            return response

        self._restore = (transport, original)
        transport.handle_request = handle_request  # type: ignore[method-assign]

    def pytest_sessionfinish(self, session: Any, exitstatus: int) -> None:
        restore = getattr(self, "_restore", None)
        if restore is not None:
            restore[0].handle_request = restore[1]


def collect_routes() -> tuple[list[RouteInfo], list[str], list[str]]:
    import app.api.routes as routes_pkg
    from app.main import create_app

    app = create_app()
    infos: list[RouteInfo] = []
    endpoints: set[Any] = set()
    for path, route, inherited in iter_api_routes(app.router):
        infos.extend(analyse(path, route, inherited))
        endpoints.add(route.endpoint)
    schema_paths = set(app.openapi()["paths"])
    walked = {re.sub(r":path\}", "}", r.path) for r in infos if r.path.startswith("/api/")}  # OpenAPI drops ":path"
    if not walked or not walked <= schema_paths:
        raise RuntimeError(f"route walk disagrees with OpenAPI ({sorted(walked - schema_paths)[:5]}); "
                           "FastAPI internals changed — update iter_api_routes")
    empty, unregistered = [], []
    for mod in pkgutil.iter_modules(routes_pkg.__path__):
        router = getattr(importlib.import_module(f"app.api.routes.{mod.name}"), "router", None)
        if router is None:
            continue
        if not router.routes:
            empty.append(f"backend/app/api/routes/{mod.name}.py")
        elif not any(getattr(r, "endpoint", None) in endpoints for r in router.routes):
            unregistered.append(f"backend/app/api/routes/{mod.name}.py")
    return infos, empty, unregistered


def run_isolation(test_paths: list[str], quiet_stdout: bool) -> tuple[int, int, list[Hit]]:
    """Run the ``other_org`` tests under ``backend/`` and return (pytest exit code, tests run, requests)."""
    import pytest

    recorder = Recorder()
    cwd = Path.cwd()
    os.chdir(BACKEND)  # backend/pyproject.toml carries the pytest configuration
    try:
        redirect = contextlib.redirect_stdout(sys.stderr) if quiet_stdout else contextlib.nullcontext()
        with redirect:
            code = int(pytest.main(["-q", "-p", "no:cacheprovider", *test_paths], plugins=[recorder]))
    finally:
        os.chdir(cwd)
    return code, recorder.selected, recorder.hits


def apply_hits(infos: list[RouteInfo], hits: list[Hit]) -> None:
    patterns = [template_regex(r.path) for r in infos]
    for hit in hits:
        info = match_route(infos, patterns, hit.method, hit.path)
        if info is not None:
            info.isolation_requests += 1
            info.isolation_404 = info.isolation_404 or hit.status == 404


def build_report(static: bool, test_paths: list[str], quiet_stdout: bool) -> Report:
    hits: list[Hit] = []
    pytest_exit, selected = None, 0
    if not static:  # before importing the app, so the test session starts from a clean import state
        pytest_exit, selected, hits = run_isolation(test_paths, quiet_stdout)
    infos, empty, unregistered = collect_routes()
    report = Report(routes=infos, empty_modules=empty, unregistered_modules=unregistered)
    for r in infos:
        label = f"{r.method} {r.path}"
        if not r.authenticated and (r.method, r.path) not in PUBLIC:
            report.unexpected_public.append(f"{label}  ({r.endpoint})")
        if r.method in UNSAFE and r.permissions == ["read"] and not (r.method == "POST" and r.path in READ_ONLY_POSTS):
            report.read_guarded_writes.append(f"{label}  ({r.endpoint})")
    if not static:
        report.isolation_run, report.pytest_exit, report.isolation_tests = True, pytest_exit, selected
        apply_hits(infos, hits)
        for r in infos:
            if not r.authenticated or (r.method, r.path) in PUBLIC:
                continue
            if r.isolation_requests == 0:
                report.not_isolation_tested.append(f"{r.method} {r.path}")
            elif r.has_id and not r.isolation_404:
                report.id_routes_without_404.append(f"{r.method} {r.path}")
    return report


def render_text(report: Report) -> str:
    lines = [f"Routes: {len(report.routes)} ({sum(r.authenticated for r in report.routes)} authenticated)"]

    def section(title: str, items: list[str]) -> None:
        lines.append(f"\n{title}: {len(items)}")
        lines.extend(f"  - {item}" for item in items)

    section("Unauthenticated routes not in PUBLIC", report.unexpected_public)
    section("Unsafe methods guarded only by 'read' (not in READ_ONLY_POSTS)", report.read_guarded_writes)
    section("Route modules with no routes (placeholder interfaces)", report.empty_modules)
    section("Route modules not included in app/api/router.py", report.unregistered_modules)
    if report.isolation_run:
        lines.append(f"\nIsolation run: {report.isolation_tests} tests using other_org, pytest exit {report.pytest_exit}")
        section("Authenticated routes never requested in an other_org test", report.not_isolation_tested)
        section("Id routes that never answered 404 in an other_org test", report.id_routes_without_404)
    else:
        lines.append("\nIsolation run: skipped (--static)")
    lines.append(f"\nGaps: {report.gaps}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--static", action="store_true", help="skip running the isolation tests")
    parser.add_argument("--tests", nargs="+", default=["tests/integration"], help="test paths relative to backend/")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument("--strict", action="store_true", help="exit 1 when any gap is reported")
    args = parser.parse_args(argv)
    prepare_environment()
    try:
        report = build_report(args.static, args.tests, quiet_stdout=args.json)
    except Exception as exc:  # the audit itself is broken: say so, never report a clean result
        print(f"route_audit failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if args.json:
        payload = asdict(report) | {"gaps": report.gaps}
        print(json.dumps(payload, indent=2))
    else:
        print(render_text(report))
    return 1 if args.strict and report.gaps else 0


if __name__ == "__main__":
    sys.exit(main())
