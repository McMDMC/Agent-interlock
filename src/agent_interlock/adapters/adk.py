"""Google ADK integration (checked against google-adk 2.14.0).

Two ways in:

* ``InterlockPlugin`` – register once on the App/Runner; gates every tool of
  every agent. This is the recommended path and the only one that also
  covers what happens *after* a call (trips and faults, see below).
* ``before_tool_callback(interlock)`` – per-agent callback for
  ``LlmAgent(before_tool_callback=...)``. Gate only.

Before the call (``before_tool_callback``): ADK skips the real tool when the
callback returns a dict and hands that dict to the model as the tool result,
so the model sees why it was stopped and can re-plan.

After the call, the plugin closes the loop the way a safety circuit does:

* ``after_tool_callback`` runs the tool's ``trip`` rules on its result. A
  light curtain that reports "breached" latches the E-stop, and the model
  gets the result back with the E-stop reason attached.
* ``on_tool_error_callback`` records the fault. If the tool's class is in
  ``estop_on_fault`` (default: ``actuate``), the E-stop latches and the model
  gets a fault result instead of the run crashing. Other faults re-raise as
  before.

ADK also runs ``after_tool_callback`` when a before-callback answered the
call or an error callback produced the result. Trips are only evaluated for
calls the interlock let through and that returned normally; otherwise a
blocked call's reason dict ("no sensor value") would trip the E-stop.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from ..decision import Decision, ToolCall
from ..engine import Interlock

_MAX_PENDING = 10_000  # calls cancelled mid-run never reach after/error; bound the map


def _blocked_result(d: Decision) -> dict[str, Any]:
    return {
        "status": "blocked_by_interlock",
        "verdict": d.verdict.value,
        "rule": d.rule,
        "reason": d.reason,
    }


def _call(tool: Any, args: dict[str, Any], ctx: Any) -> ToolCall:
    agent = getattr(ctx, "agent_name", None) or "unknown"
    return ToolCall(agent, tool.name, dict(args))


def _gate(interlock: Interlock, tool: Any, args: dict[str, Any], ctx: Any) -> dict | None:
    d = interlock.check(_call(tool, args, ctx))
    return None if d.allowed else _blocked_result(d)


def before_tool_callback(interlock: Interlock):
    """Return a callback for ``LlmAgent(before_tool_callback=...)``."""

    def callback(tool: Any, args: dict[str, Any], tool_context: Any) -> dict | None:
        return _gate(interlock, tool, args, tool_context)

    return callback


def InterlockPlugin(interlock: Interlock, name: str = "agent_interlock"):  # noqa: N802
    """Build an ADK plugin instance. Requires ``pip install agent-interlock[adk]``."""
    from google.adk.plugins.base_plugin import BasePlugin

    class _InterlockPlugin(BasePlugin):
        def __init__(self, name: str) -> None:
            super().__init__(name=name)
            # function_call_id -> True for calls we let through and that have not finished.
            self._running: OrderedDict[str, bool] = OrderedDict()

        def _mark(self, ctx: Any) -> None:
            call_id = getattr(ctx, "function_call_id", None)
            if call_id:
                self._running[call_id] = True
                while len(self._running) > _MAX_PENDING:
                    self._running.popitem(last=False)

        def _finish(self, ctx: Any) -> bool:
            call_id = getattr(ctx, "function_call_id", None)
            return bool(call_id) and self._running.pop(call_id, False)

        async def before_tool_callback(self, *, tool, tool_args, tool_context):
            blocked = _gate(interlock, tool, tool_args, tool_context)
            if blocked is None:
                self._mark(tool_context)
            return blocked

        async def on_tool_error_callback(self, *, tool, tool_args, tool_context, error):
            self._finish(tool_context)  # a faulted call has no result to check
            reason = interlock.fault(_call(tool, tool_args, tool_context), error)
            if reason is None:
                return None  # not a safety fault: let ADK raise as usual
            return {
                "status": "tool_fault",
                "error": f"{type(error).__name__}: {error}"[:300],
                "interlock": {"estop": "latched", "reason": reason},
            }

        async def after_tool_callback(self, *, tool, tool_args, tool_context, result):
            if not self._finish(tool_context):
                return None  # blocked, faulted, or answered by someone else
            reason = interlock.check_result(_call(tool, tool_args, tool_context), result)
            if reason is None:
                return None
            base = result if isinstance(result, dict) else {"result": result}
            return {**base, "interlock": {"estop": "latched", "reason": reason}}

    return _InterlockPlugin(name=name)
