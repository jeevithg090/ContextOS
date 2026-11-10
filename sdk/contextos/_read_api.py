"""Read helpers used by the CLI (agents, events, policies, incidents, sessions, simulations).

All of them need an API key with the ``read`` scope. Lists return the server's ``Page`` shape
(``{"items", "total", "limit", "offset"}``) unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import quote


def _seg(value: str) -> str:
    return quote(str(value), safe="")


class ReadAPIMixin:
    if TYPE_CHECKING:  # provided by ContextOSClient
        def _request(self, method: str, path: str, *, json_body: Any = None, params: dict[str, Any] | None = None,
                     retry: Literal["all", "connect", "none"] = "all", auth: bool = True) -> Any: ...

    def list_agents(self, *, limit: int = 50, offset: int = 0, search: str | None = None) -> Any:
        return self._request("GET", "/agents", params={"limit": limit, "offset": offset, "search": search})

    def list_events(self, *, session_id: str | None = None, event_type: str | None = None,
                    limit: int = 50, offset: int = 0) -> Any:
        params = {"session_id": session_id, "event_type": event_type, "limit": limit, "offset": offset}
        return self._request("GET", "/events", params=params)

    def list_policies(self, *, limit: int = 200, offset: int = 0) -> Any:
        return self._request("GET", "/policies", params={"limit": limit, "offset": offset})

    def list_incidents(self, *, status: str | None = None, limit: int = 50, offset: int = 0) -> Any:
        return self._request("GET", "/incidents", params={"status": status, "limit": limit, "offset": offset})

    def get_session(self, session_id: str) -> Any:
        return self._request("GET", f"/sessions/{_seg(session_id)}")

    def session_timeline(self, session_id: str) -> Any:
        return self._request("GET", f"/sessions/{_seg(session_id)}/timeline")

    def list_scenarios(self) -> Any:
        return self._request("GET", "/simulations/scenarios")

    def run_simulation(self, scenario_id: str, **options: Any) -> Any:
        """Start a Simulation Lab run. Not retried on failure (a run is a write)."""
        body = {"scenario_id": scenario_id, **{k: v for k, v in options.items() if v is not None}}
        return self._request("POST", "/simulations/runs", json_body=body, retry="connect")

    def get_simulation_run(self, run_id: str) -> Any:
        return self._request("GET", f"/simulations/runs/{_seg(run_id)}")


__all__ = ["ReadAPIMixin"]
