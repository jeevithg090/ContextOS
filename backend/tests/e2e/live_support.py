"""A real ContextOS server process for the live integration tests.

Everything is set up the way an operator would, with ``contextos-server`` subprocesses on a scratch
SQLite file: ``init-db`` (Alembic migrations), ``create-org`` (owner + built-in policies and trust
rules), ``create-api-key`` (ingest, decide, read), then ``serve`` on a random free port in
18000-18999. Tests talk to it over real HTTP — as the integration (API key) and as the signed-in
owner (session cookie + CSRF header) — and run the integrations as subprocesses against it.

The owner password and the API key are generated per run and never leave the temporary directory.
"""

from __future__ import annotations

import os
import random
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parents[3]
EXAMPLES = REPO / "examples"
BIN = Path(sys.executable).parent
API = "/api/v1"
STARTUP_TIMEOUT_S = 180.0  # the machine running the suite may be heavily loaded


def tool_path(name: str) -> Path | None:
    """A console script installed next to this interpreter (``contextos``, ``contextos-server``)."""
    path = BIN / name
    return path if path.exists() else (Path(found) if (found := shutil.which(name)) else None)


def free_port() -> int:
    ports = list(range(18000, 19000))
    random.shuffle(ports)
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free port in 18000-18999")


def server_env(root: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("CONTEXTOS_")}
    env.update(
        {
            "CONTEXTOS_DATABASE_URL": f"sqlite:///{root / 'live.db'}",
            "CONTEXTOS_SECRET_KEY": secrets.token_urlsafe(48),
            "CONTEXTOS_ENV": "development",
            "CONTEXTOS_SERVE_FRONTEND": "false",
            "CONTEXTOS_LOG_LEVEL": "WARNING",
            "PYTHONUNBUFFERED": "1",
        }
    )
    return env


def client_env(server: LiveServer, home: Path, **extra: str) -> dict[str, str]:
    """Environment for an integration subprocess: only this server's settings, an isolated home."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CONTEXTOS_", "CLAUDE_"))}
    env.update(
        {
            "CONTEXTOS_URL": server.url,
            "CONTEXTOS_API_KEY": server.api_key,
            "CONTEXTOS_HOME": str(home),
            "PYTHONUNBUFFERED": "1",
            **extra,
        }
    )
    return env


@dataclass
class LiveServer:
    url: str
    api_key: str
    org_slug: str
    email: str
    password: str = field(repr=False)
    root: Path
    process: subprocess.Popen[bytes] | None = field(default=None, repr=False)
    _user: httpx.Client | None = field(default=None, repr=False)

    def key(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.url + API, headers={"Authorization": f"Bearer {self.api_key}"}, timeout=60
        )

    @property
    def user(self) -> httpx.Client:
        """The owner, signed in through POST /auth/login (httpOnly cookie + CSRF header)."""
        if self._user is None:
            client = httpx.Client(
                base_url=self.url + API, headers={"X-Requested-With": "contextos"}, timeout=60
            )
            response = client.post("/auth/login", json={"email": self.email, "password": self.password})
            response.raise_for_status()
            self._user = client
        return self._user

    def get(self, path: str, **params: Any) -> Any:
        response = self.user.get(path, params=params)
        assert response.status_code == 200, f"GET {path}: {response.status_code} {response.text}"
        return response.json()

    def post(self, path: str, body: dict[str, Any], status: int = 200) -> Any:
        response = self.user.post(path, json=body)
        assert response.status_code == status, f"POST {path}: {response.status_code} {response.text}"
        return response.json()

    def session(self, external_id: str) -> dict[str, Any] | None:
        items = self.get("/sessions", q=external_id, include_simulated=False, limit=50)["items"]
        return next((s for s in items if s["external_session_id"] == external_id), None)

    def log_tail(self, lines: int = 60) -> str:
        path = self.root / "server.log"
        if not path.exists():
            return ""
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])

    def close(self) -> None:
        if self._user is not None:
            self._user.close()
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=30)


def _admin(exe: Path, env: dict[str, str], cwd: Path, *args: str) -> str:
    done = subprocess.run(  # noqa: S603
        [str(exe), *args],
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if done.returncode != 0:
        raise RuntimeError(
            f"contextos-server {args[0]} failed ({done.returncode}): {done.stderr or done.stdout}"
        )
    return done.stdout


@contextmanager
def live_server(root: Path) -> Iterator[LiveServer]:
    exe = tool_path("contextos-server")
    if exe is None:
        raise FileNotFoundError("contextos-server")
    env = server_env(root)
    password = secrets.token_urlsafe(18)
    email = "owner@live-e2e.test"
    _admin(exe, env, root, "init-db")
    created = _admin(
        exe,
        env,
        root,
        "create-org",
        "--name",
        "Live E2E",
        "--email",
        email,
        "--name-of-owner",
        "Live Owner",
        "--password",
        password,
    )
    slug_match = re.search(r"Slug\s+(\S+)", created)
    if slug_match is None:
        raise RuntimeError(f"could not read the organisation slug from: {created}")
    slug = slug_match.group(1)
    api_key = _admin(
        exe,
        env,
        root,
        "create-api-key",
        "--org-slug",
        slug,
        "--name",
        "live e2e",
        "--scopes",
        "ingest,decide,read",
        "--quiet",
    ).strip()
    if not api_key.startswith("ctxk_"):
        raise RuntimeError("create-api-key --quiet did not print a key")
    port = free_port()
    log = (root / "server.log").open("wb")
    process = subprocess.Popen(  # noqa: S603
        [str(exe), "serve", "--host", "127.0.0.1", "--port", str(port)],
        env=env,
        cwd=root,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    server = LiveServer(f"http://127.0.0.1:{port}", api_key, slug, email, password, root, process)
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT_S
        while True:
            if process.poll() is not None:
                raise RuntimeError(f"the server exited ({process.returncode}):\n{server.log_tail()}")
            try:
                if httpx.get(f"{server.url}{API}/ready", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError(f"the server did not become ready:\n{server.log_tail()}")
            time.sleep(0.25)
        yield server
    finally:
        server.close()
        log.close()


def run(
    args: list[str],
    env: dict[str, str],
    *,
    stdin: bytes | None = None,
    cwd: Path | None = None,
    timeout: float = 300,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603
        args,
        input=stdin,
        env=env,
        cwd=cwd,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


__all__ = ["EXAMPLES", "LiveServer", "client_env", "free_port", "live_server", "run", "tool_path"]
