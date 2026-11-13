"""Read helpers used by the CLI (agents, events, policies, incidents, sessions, simulations).

They need an API key with the ``read`` scope, except :meth:`run_simulation`, which writes simulated
events and needs ``ingest`` (signed-in users need ``write``). Lists return the server's ``Page``
shape (``{"items", "total", "limit", "offset"}``) unchanged. Simulation Lab data is left out of
lists unless ``include_simulated`` is set (the event log returns both, each flagged
``is_simulation``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import quote

from contextos.errors import APIError


def _seg(value: str) -> str:
    return quote(str(value), safe="")


class ReadAPIMixin:
    if TYPE_CHECKING:  # provided by ContextOSClient
        def _request(self, method: str, path: str, *, json_body: Any = None, params: dict[str, Any] | None = None,
                     retry: Literal["all", "connect", "none"] = "all", auth: bool = True) -> Any: ...

    def list_agents(self, *, limit: int = 50, offset: int = 0, search: str | None = None,
                    include_simulated: bool = False) -> Any:
        params = {"limit": limit, "offset": offset, "q": search,  # the server's search parameter is ``q``
                  "include_simulated": "true" if include_simulated else None}
        return self._request("GET", "/agents", params=params)

    def list_events(self, *, session_id: str | None = None, event_type: str | None = None,
                    limit: int = 50, offset: int = 0, include_simulated: bool = False) -> Any:
        params = {"session_id": session_id, "event_type": event_type, "limit": limit, "offset": offset,
                  "include_simulated": "true" if include_simulated else None}
        return self._request("GET", "/events", params=params)

    def list_policies(self, *, limit: int = 200, offset: int = 0) -> Any:
        return self._request("GET", "/policies", params={"limit": limit, "offset": offset})

    def list_incidents(self, *, status: str | None = None, limit: int = 50, offset: int = 0,
                       include_simulated: bool = False) -> Any:
        params = {"status": status, "limit": limit, "offset": offset,
                  "include_simulated": "true" if include_simulated else None}
        return self._request("GET", "/incidents", params=params)

    def get_session(self, session_id: str) -> Any:
        return self._request("GET", f"/sessions/{_seg(session_id)}")

    def find_session(self, session_ref: str) -> Any:
        """A session by ContextOS id (``asn_…``) or by the integration's own session id (what an SDK
        or hook reports, e.g. ``ses_…`` or Claude Code's UUID). Raises :class:`APIError` 404 when
        neither matches."""
        try:
            return self.get_session(session_ref)
        except APIError as exc:
            if exc.status_code != 404:
                raise
        page = self._request("GET", "/sessions", params={"q": session_ref, "include_simulated": "true",
                                                         "limit": 50})
        for item in (page or {}).get("items", []) if isinstance(page, dict) else []:
            if isinstance(item, dict) and item.get("external_session_id") == session_ref and item.get("id"):
                return self.get_session(str(item["id"]))
        raise APIError(404, "not_found", f"No session '{session_ref}' (neither a ContextOS session id nor an "
                                         "integration session id)")

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
