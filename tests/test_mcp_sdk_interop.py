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


# ------------------------------------------------ Streamable HTTP, real processes


def _free_port():
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(port, path="/", deadline=20.0):
    import http.client
    import time

    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", path)
            conn.getresponse().read()
            return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"nothing listening on {port}")


@pytest.fixture
def http_cell(tmp_path, monkeypatch):
    import os
    import subprocess

    up, gw = _free_port(), _free_port()
    env = {**os.environ, "CELL_LIGHT_CURTAIN": "breached"}
    server = subprocess.Popen(
        [sys.executable, str(ROOT / "examples" / "mcp_robot_server.py"), "--http", str(up)],
        env=env, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    gateway = subprocess.Popen(
        [
            sys.executable, "-m", "agent_interlock.cli", "mcp-http",
            "--policy", str(ROOT / "policies" / "robot_cell.toml"),
            "--agent", "planner-01", "--upstream", f"http://127.0.0.1:{up}/mcp",
            "--listen", f"127.0.0.1:{gw}", "--audit", str(tmp_path / "audit.jsonl"),
            "--state", str(tmp_path / "latch.json"),
        ],
        stderr=subprocess.DEVNULL,
    )  # fmt: skip
    try:
        _wait_for(up)
        _wait_for(gw, "/healthz")
        yield f"http://127.0.0.1:{gw}/mcp", tmp_path
    finally:
        for p in (gateway, server):
            p.terminate()
            p.wait(10)


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_sdk_client_through_http_gateway(http_cell, mode):
    from agent_interlock import audit

    url, tmp = http_cell

    async def session():
        async with Client(url, mode=mode) as client:
            tools = await client.list_tools()
            ok = await client.call_tool("move_arm", {"x": 0.1, "y": 0.1, "z": 0.4, "speed": 0.1})
            fast = await client.call_tool("move_arm", {"x": 0.1, "y": 0.1, "z": 0.4, "speed": 3})
            wipe = await client.call_tool("format_controller_disk", {})
            curtain = await client.call_tool("read_sensor", {"sensor": "light_curtain"})
            after = await client.call_tool("move_arm", {"x": 0.1, "y": 0.1, "z": 0.4, "speed": 0.1})
            return tools, ok, fast, wipe, curtain, after

    tools, ok, fast, wipe, curtain, after = asyncio.run(asyncio.wait_for(session(), 60))
    assert {t.name for t in tools.tools} == {"move_arm", "read_sensor"}
    assert not ok.is_error and "arm moved" in ok.content[0].text
    assert fast.is_error and "param:speed" in fast.content[0].text
    assert wipe.is_error and "unknown_tool" in wipe.content[0].text
    assert "E-stop latched" in curtain.content[-1].text  # trip read structuredContent
    assert after.is_error and "estop" in after.content[0].text
    ok_chain, _ = audit.verify(audit.load(tmp / "audit.jsonl"))
    assert ok_chain
