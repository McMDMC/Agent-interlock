"""Google ADK integration (checked against google-adk 2.12.0).

Two ways in:

* ``InterlockPlugin`` – register once on the Runner; gates every tool of
  every agent. This is the recommended path.
* ``before_tool_callback(interlock)`` – per-agent callback for
  ``LlmAgent(before_tool_callback=...)``.

In both cases ADK skips the real tool when the callback returns a dict and
hands that dict to the model as the tool result, so the model sees why it
was stopped and can re-plan.
"""

from __future__ import annotations

from typing import Any

from ..decision import Decision, ToolCall
from ..engine import Interlock


def _blocked_result(d: Decision) -> dict[str, Any]:
    return {
        "status": "blocked_by_interlock",
        "verdict": d.verdict.value,
        "rule": d.rule,
        "reason": d.reason,
    }


def _gate(interlock: Interlock, tool: Any, args: dict[str, Any], ctx: Any) -> dict | None:
    agent = getattr(ctx, "agent_name", None) or "unknown"
    d = interlock.check(ToolCall(agent, tool.name, dict(args)))
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
        async def before_tool_callback(self, *, tool, tool_args, tool_context):
            return _gate(interlock, tool, tool_args, tool_context)

    return _InterlockPlugin(name=name)
