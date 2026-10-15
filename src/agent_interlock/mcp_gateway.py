"""MCP gateway: run the interlock in front of any stdio MCP server.

    interlock mcp-proxy --policy cell.toml --agent planner-01 -- python my_server.py

The MCP client (Claude Code, an ADK MCPToolset, Gemini CLI, ...) launches
the gateway instead of the server. The gateway launches the real server and
relays newline-delimited JSON-RPC both ways (MCP spec 2026-07-28, stdio
transport). It changes only two kinds of messages:

* ``tools/call`` requests are checked first. A blocked call is never
  forwarded. The client gets a normal tool result with ``isError: true``
  and the reason, so the model can self-correct (spec: tool execution
  errors belong in the result, not in a protocol error).
* ``tools/list`` responses are filtered down to the tools the policy
  declares (least privilege), unless ``hide_unlisted=False``.

Every message the gateway forwards is re-serialised from what it parsed.
Raw bytes are never passed through. A server whose JSON parser treats
duplicate keys differently therefore cannot see a different tool name or
argument than the one the interlock checked.
"""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import IO, Any

from .decision import Decision, ToolCall
from .engine import Interlock
from .policy import Policy, PolicyError

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
INVALID_PARAMS = -32602


def _encode(msg: dict[str, Any]) -> bytes:
    return json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def _error(id_: Any, code: int, message: str) -> bytes:
    return _encode({"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}})


def _blocked(id_: Any, d: Decision) -> bytes:
    text = f"Blocked by agent-interlock [{d.verdict.value}"
    text += f" {d.rule}]: {d.reason}" if d.rule else f"]: {d.reason}"
    return _encode(
        {
            "jsonrpc": "2.0",
            "id": id_,
            "result": {
                "resultType": "complete",
                "content": [{"type": "text", "text": text}],
                "isError": True,
            },
        }
    )


class McpGateway:
    """Protocol logic, independent of how bytes are moved (testable without processes)."""

    def __init__(self, interlock: Interlock, agent: str, hide_unlisted: bool = True) -> None:
        self.interlock = interlock
        self.agent = agent
        self.hide_unlisted = hide_unlisted
        self._pending_lists: set[str] = set()
        self._lock = threading.Lock()

    def from_client(self, line: bytes) -> tuple[bytes | None, bytes | None]:
        """Return (bytes for the server, bytes for the client). Either may be None."""
        if not line.strip():
            return None, None
        try:
            msg = json.loads(line)
        except ValueError:
            return None, _error(None, PARSE_ERROR, "Parse error")
        if not isinstance(msg, dict):
            # JSON-RPC batches were removed from MCP; refuse rather than inspect half of one.
            return None, _error(None, INVALID_REQUEST, "Invalid Request: batches not supported")

        method = msg.get("method")
        if method == "tools/call":
            if "id" not in msg:
                return None, None  # a tool call can't be a notification; drop it
            params = msg.get("params")
            params = params if isinstance(params, dict) else {}
            name, args = params.get("name"), params.get("arguments", {})
            if not isinstance(name, str) or not isinstance(args, dict):
                return None, _error(msg["id"], INVALID_PARAMS, "Invalid params for tools/call")
            d = self.interlock.check(ToolCall(self.agent, name, args))
            if not d.allowed:
                return None, _blocked(msg["id"], d)
        elif method == "tools/list" and "id" in msg:
            with self._lock:
                self._pending_lists.add(json.dumps(msg["id"]))
        return _encode(msg), None

    def from_server(self, line: bytes) -> bytes | None:
        if not line.strip():
            return None
        try:
            msg = json.loads(line)
        except ValueError:
            return None  # spec: server stdout carries only MCP messages; drop noise
        if not isinstance(msg, dict):
            return None
        if "method" not in msg and "id" in msg:
            key = json.dumps(msg["id"])
            with self._lock:
                is_list = key in self._pending_lists
                self._pending_lists.discard(key)
            result = msg.get("result")
            if is_list and self.hide_unlisted and isinstance(result, dict):
                tools = result.get("tools")
                if isinstance(tools, list):
                    allowed = self.interlock.policy.tools
                    result["tools"] = [
                        t for t in tools if isinstance(t, dict) and t.get("name") in allowed
                    ]
        return _encode(msg)


def run_stdio(
    gateway: McpGateway,
    command: Sequence[str],
    policy_path: str | Path | None = None,
    stdin: IO[bytes] | None = None,
    stdout: IO[bytes] | None = None,
) -> int:
    """Launch the MCP server and relay stdio through the gateway until it exits."""
    cin = stdin or sys.stdin.buffer
    cout = stdout or sys.stdout.buffer
    out_lock = threading.Lock()
    proc = subprocess.Popen(list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert proc.stdin is not None and proc.stdout is not None

    def to_client(data: bytes) -> None:
        with out_lock:
            cout.write(data)
            cout.flush()

    def client_to_server() -> None:
        try:
            for line in cin:
                fwd, reply = gateway.from_client(line)
                if reply:
                    to_client(reply)
                if fwd:
                    proc.stdin.write(fwd)
                    proc.stdin.flush()
        except (BrokenPipeError, ValueError):
            pass
        finally:
            try:
                proc.stdin.close()  # client gone: let the server shut down
            except OSError:
                pass

    def server_to_client() -> None:
        for line in proc.stdout:
            if (out := gateway.from_server(line)) is not None:
                to_client(out)

    if policy_path is not None and hasattr(signal, "SIGHUP"):

        def reload(_sig: int, _frame: Any) -> None:
            try:
                gateway.interlock.reload(Policy.from_file(policy_path), operator="SIGHUP")
            except (PolicyError, OSError) as e:
                gateway.interlock.audit.event("policy_reload_failed", error=str(e))
                print(f"interlock: reload failed, keeping old policy: {e}", file=sys.stderr)

        signal.signal(signal.SIGHUP, reload)

    threading.Thread(target=client_to_server, daemon=True).start()
    pump = threading.Thread(target=server_to_client, daemon=True)
    pump.start()
    code = proc.wait()
    pump.join(timeout=5)
    return code
