"""Fixtures for the end-to-end tests.

``live`` tests run a real ``contextos-server`` process and the real integrations as subprocesses
(Claude Code hook, MCP gateway, SDK example). They are marked ``live`` so a reduced environment can
deselect them with ``-m "not live"``; a missing console script or optional dependency skips them
with the reason. In this repository's virtualenv they must run and pass.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from tests.e2e.live_support import LiveServer, live_server, tool_path


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "live: starts a real ContextOS server and integration subprocesses")


@pytest.fixture(scope="session")
def live(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LiveServer]:
    for script in ("contextos-server", "contextos"):
        if tool_path(script) is None:
            pytest.skip(f"the '{script}' console script is not installed in this environment")
    with live_server(tmp_path_factory.mktemp("live-server")) as server:
        yield server
