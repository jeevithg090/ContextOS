"""A scripted stand-in for the OpenAI Responses API, so a REAL Codex process can be driven offline.

Codex talks to its model provider over ``POST {base_url}/responses`` (server-sent events). Pointing a
custom ``[model_providers.<id>]`` at this server (``wire_api = "responses"``,
``requires_openai_auth = false``) lets the live verification run the real Codex binary — its tool
router, sandbox, approval policy and hooks — with a model whose every step is known in advance. No
OpenAI account is used and nothing leaves 127.0.0.1.

The script file maps a substring of the latest user message to a list of steps; ``"*"`` is the
default. Each request is answered with the step whose index is the number of tool outputs already in
the conversation, so the server also works for sub-agents (their task is their user message)::

    {"*": [{"item": {"type": "function_call", "name": "exec_command", "arguments": "{\\"cmd\\": \\"ls\\"}"}},
           {"message": "Finished."}],
     "say hi": [{"message": "hi"}]}

A step is ``{"item": <Responses output item>}`` (``call_id`` is filled in), ``{"message": <assistant
text>}``, or ``{"wait_for_spawned_agent": <timeout ms>}`` — a ``wait_agent`` call (multi-agent v1)
for the ``agent_id`` the latest ``spawn_agent`` output returned. Every request is appended to the log file (JSONL) with the tool
names offered and the tool outputs Codex sent back — which is how the verification sees what the
model received for a blocked call.

    python examples/codex/fake_model_server.py --port 18766 --script steps.json --log requests.jsonl

The SSE event shapes follow Codex's own test helpers (``codex-rs/core/tests/common/responses.rs``).
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

_OUTPUT_TYPES = ("function_call_output", "custom_tool_call_output")
_USAGE = {"input_tokens": 0, "input_tokens_details": None, "output_tokens": 0, "output_tokens_details": None,
          "total_tokens": 0}


def _last_user_text(items: list[Any]) -> str:
    text = ""
    for item in items:
        if isinstance(item, dict) and item.get("role") == "user":
            content = item.get("content")
            if isinstance(content, list):
                text = " ".join(str(c.get("text", "")) for c in content if isinstance(c, dict))
            elif isinstance(content, str):
                text = content
    return text


def _spawned_agents(outputs: list[dict[str, Any]]) -> list[str]:
    found = []
    for output in outputs:
        text = output.get("output")
        try:
            data = json.loads(text) if isinstance(text, str) else None
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and isinstance(data.get("agent_id"), str):
            found.append(data["agent_id"])
    return found


def _sse(events: list[dict[str, Any]]) -> bytes:
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def make_handler(script: dict[str, list[dict[str, Any]]], log: Path) -> type[BaseHTTPRequestHandler]:
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            return

        def _record(self, entry: dict[str, Any]) -> None:
            with lock, log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")

        def do_GET(self) -> None:  # model listings: nothing to offer
            body = json.dumps({"object": "list", "data": [], "models": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            try:
                request = json.loads(raw)
            except json.JSONDecodeError:
                request = {}
            items = request.get("input") if isinstance(request.get("input"), list) else []
            outputs = [i for i in items if isinstance(i, dict) and i.get("type") in _OUTPUT_TYPES]
            last = _last_user_text(items)
            steps = next((v for k, v in script.items() if k != "*" and k in last), script.get("*", []))
            index = len(outputs)
            self._record({"path": self.path, "step": index, "user": last[-300:],
                          "tools": [t.get("name") or t.get("type") for t in request.get("tools") or []
                                    if isinstance(t, dict)],
                          "outputs": [o.get("output") for o in outputs]})
            response_id = f"resp_{index}"
            events: list[dict[str, Any]] = [{"type": "response.created", "response": {"id": response_id}}]
            step = steps[index] if index < len(steps) else {"message": "Done."}
            if "wait_for_spawned_agent" in step:
                step = {"item": {"type": "function_call", "namespace": "multi_agent_v1", "name": "wait_agent",
                                 "arguments": json.dumps({"targets": _spawned_agents(outputs)[-1:],
                                                          "timeout_ms": int(step["wait_for_spawned_agent"])})}}
            if "item" in step:
                item = dict(step["item"])
                item.setdefault("call_id", f"call_{index}_{abs(hash(last)) % 100000}")
            else:
                item = {"type": "message", "role": "assistant", "id": f"msg_{index}",
                        "content": [{"type": "output_text", "text": str(step.get("message", "Done."))}]}
            events.append({"type": "response.output_item.done", "item": item})
            events.append({"type": "response.completed", "response": {"id": response_id, "usage": _USAGE}})
            body = _sse(events)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    script = json.loads(args.script.read_text(encoding="utf-8"))
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(script, args.log))
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
