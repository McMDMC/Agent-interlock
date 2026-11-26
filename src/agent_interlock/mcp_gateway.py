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
* ``tools/call`` responses for calls it let through close the loop, like
  the ADK plugin: the tool's ``trip`` rules run on ``structuredContent``,
  and an ``isError`` result from a tool class in ``estop_on_fault`` latches
  the E-stop. The reason is appended to the result for the model.

The protocol logic here (``McpGateway``) is shared with the Streamable HTTP
gateway in ``mcp_http.py``.

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
from collections import OrderedDict
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


def _blocked_result(d: Decision) -> dict[str, Any]:
    text = f"Blocked by agent-interlock [{d.verdict.value}"
    text += f" {d.rule}]: {d.reason}" if d.rule else f"]: {d.reason}"
    return {
        "resultType": "complete",
        "content": [{"type": "text", "text": text}],
        "isError": True,
    }


def _blocked(id_: Any, d: Decision) -> bytes:
    return _encode({"jsonrpc": "2.0", "id": id_, "result": _blocked_result(d)})


class ToolReportedError(Exception):
    """An MCP tool returned ``isError: true``. Passed to ``Interlock.fault``."""


def _result_payload(result: dict[str, Any]) -> Any:
    """What trips read: ``structuredContent``, else a lone text block that holds a JSON object.

    Anything else yields None, and a trip on a missing field fires
    (normally-closed: no reading is a stop signal).
    """
    if "structuredContent" in result:
        return result["structuredContent"]
    content = result.get("content")
    if isinstance(content, list) and len(content) == 1 and isinstance(content[0], dict):
        if content[0].get("type") == "text" and isinstance(content[0].get("text"), str):
            try:
                value = json.loads(content[0]["text"])
            except ValueError:
                return None
            return value if isinstance(value, dict) else None
    return None


def _error_text(result: dict[str, Any]) -> str:
    content = result.get("content")
    if isinstance(content, list):
        texts = [c.get("text") for c in content if isinstance(c, dict)]
        joined = " ".join(t for t in texts if isinstance(t, str))
        if joined:
            return joined
    return "tool returned isError"


_MAX_PENDING = 10_000  # requests that never get an answer must not grow the map forever


class McpGateway:
    """Protocol logic, independent of how bytes are moved (testable without processes)."""

    def __init__(self, interlock: Interlock, agent: str, hide_unlisted: bool = True) -> None:
        self.interlock = interlock
        self.agent = agent
        self.hide_unlisted = hide_unlisted
        # json(id) -> None for a pending tools/list, ToolCall for a pending allowed tools/call.
        self._pending: OrderedDict[str, ToolCall | None] = OrderedDict()
        self._lock = threading.Lock()

    # ------------------------------------------------- shared by both transports

    def gate(self, msg: dict[str, Any]) -> tuple[ToolCall | None, dict[str, Any] | None]:
        """Check a ``tools/call`` request.

        Returns ``(call, None)`` if it may run, or ``(None, error)`` where
        ``error`` is either a JSON-RPC ``error`` object (malformed request)
        or a tool ``result`` saying why it was blocked.
        """
        params = msg.get("params")
        params = params if isinstance(params, dict) else {}
        name, args = params.get("name"), params.get("arguments", {})
        if args is None:
            args = {}
        if not isinstance(name, str) or not isinstance(args, dict):
            return None, {"error": {"code": INVALID_PARAMS, "message": "Invalid params"}}
        call = ToolCall(self.agent, name, args)
        d = self.interlock.check(call)
        if not d.allowed:
            return None, {"result": _blocked_result(d)}
        return call, None

    def filter_tools(self, result: Any) -> None:
        """Drop tools the policy does not declare from a ``tools/list`` result (in place)."""
        if not (self.hide_unlisted and isinstance(result, dict)):
            return
        tools = result.get("tools")
        if isinstance(tools, list):
            allowed = self.interlock.policy.tools
            result["tools"] = [t for t in tools if isinstance(t, dict) and t.get("name") in allowed]

    def after_call(self, call: ToolCall, msg: dict[str, Any]) -> None:
        """Run trips / fault handling on the response to an allowed call (in place).

        A JSON-RPC ``error`` is a protocol failure (the tool did not run), so
        it is left alone. Results that are not final (``input_required``,
        extension types such as tasks) are not evaluated: the call is not over.
        """
        result = msg.get("result")
        if not isinstance(result, dict) or result.get("resultType", "complete") != "complete":
            return
        if result.get("isError") is True:
            reason = self.interlock.fault(call, ToolReportedError(_error_text(result)))
        else:
            reason = self.interlock.check_result(call, _result_payload(result))
        if reason is None:
            return
        content = result.get("content")
        if not isinstance(content, list):
            content = result["content"] = []
        content.append({"type": "text", "text": f"agent-interlock: E-stop latched: {reason}"})

    # -------------------------------------------------------------- stdio

    def _track(self, id_: Any, call: ToolCall | None) -> None:
        with self._lock:
            self._pending[json.dumps(id_)] = call
            while len(self._pending) > _MAX_PENDING:
                self._pending.popitem(last=False)

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
            call, reply = self.gate(msg)
            if reply is not None:
                return None, _encode({"jsonrpc": "2.0", "id": msg["id"], **reply})
            self._track(msg["id"], call)
        elif method == "tools/list" and "id" in msg:
            self._track(msg["id"], None)
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
                known = key in self._pending
                call = self._pending.pop(key, None)
            if known and call is None:
                self.filter_tools(msg.get("result"))
            elif call is not None:
                self.after_call(call, msg)
        return _encode(msg)


def install_reload(gateway: McpGateway, policy_path: str | Path) -> None:
    """SIGHUP reloads the policy. A broken file is rejected and the old policy stays."""
    if not hasattr(signal, "SIGHUP"):
        return

    def reload(_sig: int, _frame: Any) -> None:
        try:
            gateway.interlock.reload(Policy.from_file(policy_path), operator="SIGHUP")
        except (PolicyError, OSError) as e:
            gateway.interlock.audit.event("policy_reload_failed", error=str(e))
            print(f"interlock: reload failed, keeping old policy: {e}", file=sys.stderr)

    signal.signal(signal.SIGHUP, reload)


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

    if policy_path is not None:
        install_reload(gateway, policy_path)

    threading.Thread(target=client_to_server, daemon=True).start()
    pump = threading.Thread(target=server_to_client, daemon=True)
    pump.start()
    code = proc.wait()
    pump.join(timeout=5)
    return code
