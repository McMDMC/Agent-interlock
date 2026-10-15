"""ADK adapter tests with stand-in objects; the real plugin is tested if google-adk is installed."""

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_interlock import Interlock
from agent_interlock.adapters.adk import InterlockPlugin, before_tool_callback

CELL = Path(__file__).resolve().parent.parent / "policies" / "robot_cell.toml"
TOOL = SimpleNamespace(name="move_arm")
CTX = SimpleNamespace(agent_name="cell_operator")
OK = {"x": 0.1, "y": 0.1, "z": 0.4, "speed": 0.1}


def test_callback_passes_allowed_calls():
    cb = before_tool_callback(Interlock.from_file(CELL))
    assert cb(TOOL, OK, CTX) is None


def test_callback_returns_reason_when_blocked():
    il = Interlock.from_file(CELL)
    out = before_tool_callback(il)(TOOL, {**OK, "speed": 2.0}, CTX)
    assert out["status"] == "blocked_by_interlock" and out["rule"] == "param:speed"
    assert il.audit.records[-1]["agent"] == "cell_operator"


def test_real_adk_plugin():
    pytest.importorskip("google.adk")
    plugin = InterlockPlugin(Interlock.from_file(CELL))
    bad = {**OK, "x": 0.45, "y": 0.0}
    blocked = asyncio.run(plugin.before_tool_callback(tool=TOOL, tool_args=bad, tool_context=CTX))
    assert blocked["rule"] == "keepout:operator_station"
    allowed = asyncio.run(plugin.before_tool_callback(tool=TOOL, tool_args=OK, tool_context=CTX))
    assert allowed is None
