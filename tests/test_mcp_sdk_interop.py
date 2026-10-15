"""Official MCP SDK client -> interlock mcp-proxy -> official MCP SDK server, over real stdio."""

import asyncio
import sys
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp")
from mcp import Client, StdioServerParameters  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def test_sdk_client_through_gateway(tmp_path):
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m", "agent_interlock.cli", "mcp-proxy",
            "--policy", str(ROOT / "policies" / "robot_cell.toml"),
            "--agent", "planner-01",
            "--audit", str(tmp_path / "audit.jsonl"),
            "--", sys.executable, str(ROOT / "examples" / "mcp_robot_server.py"),
        ],
    )  # fmt: skip

    async def session():
        async with Client(params) as client:
            tools = await client.list_tools()
            ok = await client.call_tool("move_arm", {"x": 0.1, "y": 0.1, "z": 0.4, "speed": 0.1})
            fast = await client.call_tool("move_arm", {"x": 0.1, "y": 0.1, "z": 0.4, "speed": 3})
            wipe = await client.call_tool("format_controller_disk", {})
            return tools, ok, fast, wipe

    tools, ok, fast, wipe = asyncio.run(asyncio.wait_for(session(), 60))
    assert {t.name for t in tools.tools} == {"move_arm", "read_sensor"}
    assert not ok.is_error and "arm moved" in ok.content[0].text
    assert fast.is_error and "param:speed" in fast.content[0].text
    assert wipe.is_error and "unknown_tool" in wipe.content[0].text
