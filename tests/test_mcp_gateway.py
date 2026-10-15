import io
import json
import subprocess
import sys
from pathlib import Path

from agent_interlock import Interlock, Policy
from agent_interlock.mcp_gateway import McpGateway, run_stdio

HERE = Path(__file__).resolve().parent
CELL = HERE.parent / "policies" / "robot_cell.toml"
SERVER = [sys.executable, str(HERE / "fake_mcp_server.py")]
OK_MOVE = {"x": 0.1, "y": 0.1, "z": 0.4, "speed": 0.1}


def req(id_, method, **params):
    return (
        json.dumps({"jsonrpc": "2.0", "id": id_, "method": method, "params": params}) + "\n"
    ).encode()


def call(id_, name, args):
    return req(id_, "tools/call", name=name, arguments=args)


def gw(**kw):
    return McpGateway(Interlock(Policy.from_file(CELL)), agent="planner-01", **kw)


# --------------------------------------------------------- protocol logic


def test_allowed_call_is_forwarded():
    fwd, reply = gw().from_client(call(1, "move_arm", OK_MOVE))
    assert reply is None and json.loads(fwd)["params"]["name"] == "move_arm"


def test_blocked_call_never_reaches_server():
    fwd, reply = gw().from_client(call(7, "move_arm", {**OK_MOVE, "speed": 2.0}))
    assert fwd is None
    r = json.loads(reply)
    assert r["id"] == 7 and r["result"]["isError"] is True
    assert r["result"]["resultType"] == "complete"
    assert "param:speed" in r["result"]["content"][0]["text"]


def test_duplicate_keys_cannot_smuggle_a_different_call():
    # Python keeps the last duplicate key. The gateway checks that value and
    # forwards its own re-serialisation, so a server whose parser keeps the
    # first key never sees "format_disk".
    raw = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
        b'{"name":"format_disk","name":"read_sensor","arguments":{"sensor":"light_curtain"}}}\n'
    )
    fwd, _ = gw().from_client(raw)
    assert b"format_disk" not in fwd


def test_malformed_input_fails_closed():
    g = gw()
    assert json.loads(g.from_client(b"{oops\n")[1])["error"]["code"] == -32700
    batch = b'[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}]\n'
    fwd, reply = g.from_client(batch)
    assert fwd is None and json.loads(reply)["error"]["code"] == -32600
    fwd, reply = g.from_client(req(3, "tools/call", name=42))
    assert fwd is None and json.loads(reply)["error"]["code"] == -32602
    note = b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"move_arm"}}\n'
    assert g.from_client(note) == (None, None)  # tool call without id: dropped


def test_other_traffic_passes_untouched():
    g = gw()
    fwd, reply = g.from_client(req(1, "initialize", protocolVersion="2026-07-28"))
    assert reply is None and json.loads(fwd)["method"] == "initialize"
    srv = b'{"jsonrpc":"2.0","id":"s1","method":"sampling/createMessage","params":{}}\n'
    assert json.loads(g.from_server(srv))["method"] == "sampling/createMessage"
    assert g.from_server(b"some log line on stdout\n") is None


def test_tools_list_hides_tools_missing_from_policy():
    g = gw()
    g.from_client(req("L1", "tools/list"))
    tools = [{"name": "move_arm"}, {"name": "format_disk"}]
    resp = {"jsonrpc": "2.0", "id": "L1", "result": {"tools": tools, "ttlMs": 5}}
    out = json.loads(g.from_server(json.dumps(resp).encode()))
    assert [t["name"] for t in out["result"]["tools"]] == ["move_arm"]
    assert out["result"]["ttlMs"] == 5
    # a later response that reuses the id but isn't a tools/list answer is not touched
    out = json.loads(g.from_server(json.dumps(resp).encode()))
    assert len(out["result"]["tools"]) == 2


def test_show_all_keeps_full_tool_list():
    g = gw(hide_unlisted=False)
    g.from_client(req(1, "tools/list"))
    resp = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "format_disk"}]}}
    assert len(json.loads(g.from_server(json.dumps(resp).encode()))["result"]["tools"]) == 1


# ----------------------------------------------------- real server process


def run_session(lines, **kw):
    out = io.BytesIO()
    code = run_stdio(gw(**kw), SERVER, stdin=io.BytesIO(b"".join(lines)), stdout=out)
    return code, {m["id"]: m for m in map(json.loads, out.getvalue().splitlines())}


def test_end_to_end_with_real_server_process():
    code, by_id = run_session(
        [
            req(1, "initialize", protocolVersion="2026-07-28"),
            req(2, "tools/list"),
            call(3, "move_arm", OK_MOVE),
            call(4, "move_arm", {**OK_MOVE, "x": 0.45, "y": 0.0}),
            call(5, "format_disk", {}),
        ]
    )
    assert code == 0
    assert [t["name"] for t in by_id[2]["result"]["tools"]] == ["move_arm", "read_sensor"]
    assert by_id[3]["result"]["content"][0]["text"].startswith("EXECUTED move_arm")
    assert by_id[4]["result"]["isError"] and "keepout" in by_id[4]["result"]["content"][0]["text"]
    assert (
        by_id[5]["result"]["isError"] and "unknown_tool" in by_id[5]["result"]["content"][0]["text"]
    )


def test_cli_proxy_and_shared_estop(tmp_path):
    state = tmp_path / "latch.json"
    estop = subprocess.run(
        [sys.executable, "-m", "agent_interlock.cli", "estop", "--state", str(state),
         "--source", "plc", "--reason", "door open"],
        check=True, capture_output=True,
    )  # fmt: skip
    assert estop.returncode == 0
    proc = subprocess.run(
        [sys.executable, "-m", "agent_interlock.cli", "mcp-proxy", "--policy", str(CELL),
         "--state", str(state), "--audit", str(tmp_path / "a.jsonl"), "--", *SERVER],
        input=call(1, "move_arm", OK_MOVE) + call(2, "read_sensor", {"sensor": "light_curtain"}),
        capture_output=True, timeout=30,
    )  # fmt: skip
    by_id = {m["id"]: m for m in map(json.loads, proc.stdout.splitlines())}
    assert "E-stop latched: door open (from plc)" in by_id[1]["result"]["content"][0]["text"]
    assert by_id[2]["result"]["content"][0]["text"].startswith("EXECUTED read_sensor")
