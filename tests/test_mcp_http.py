"""Streamable HTTP gateway: header/body validation, gating, filtering, trips. Stdlib only."""

import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent_interlock import Interlock, Policy
from agent_interlock.mcp_gateway import McpGateway
from agent_interlock.mcp_http import (
    HttpGateway,
    Rejected,
    decode_header_value,
    encode_header_value,
    expected_param_headers,
    header_map,
    iter_sse,
    validate_routing_headers,
)

V = "2026-07-28"
OK_CONV = {"zone": "A", "speed": 0.1}
POLICY = """
[interlock]
lockout_after = 0

[tools.read_sensor]
class = "read"
params.sensor = { enum = ["light_curtain", "temp"] }

[[tools.read_sensor.trip]]
name = "light_curtain"
when = { sensor = "light_curtain" }
field = "value"
in = ["breached"]

[tools.set_conveyor]
class = "actuate"
params.zone = { enum = ["A", "B"] }
params.speed = { type = "number", min = 0, max = 0.5 }
"""

TOOLS = [
    {"name": "read_sensor", "inputSchema": {"type": "object"}},
    {
        "name": "set_conveyor",
        "inputSchema": {
            "type": "object",
            "properties": {
                "zone": {"type": "string", "x-mcp-header": "Zone"},
                "speed": {"type": "number"},
            },
        },
    },
    {"name": "format_disk", "inputSchema": {"type": "object"}},
]


# ------------------------------------------------------------ fake upstream


class Upstream:
    """Records every request it receives. Answers as JSON or SSE."""

    def __init__(self):
        self.received: list[tuple[dict[str, str], dict]] = []
        self.sse = False
        self.curtain = "clear"
        up = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                up.received.append(({k.lower(): v for k, v in self.headers.items()}, msg))
                if "id" not in msg:
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                result = up.answer(msg)
                reply = {"jsonrpc": "2.0", "id": msg["id"], "result": result}
                if up.sse:
                    note = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
                    body = (
                        ": ping\n\n"
                        f"event: message\ndata: {json.dumps(note)}\n\n"
                        f"event: message\nid: e1\ndata: {json.dumps(reply)}\n\n"
                    ).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                    self.close_connection = True
                    return
                body = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Upstream", "yes")
                self.end_headers()
                self.wfile.write(body)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, args=(0.05,), daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}/mcp"

    def answer(self, msg):
        if msg["method"] == "tools/list":
            return {"resultType": "complete", "tools": json.loads(json.dumps(TOOLS))}
        if msg["method"] == "tools/call":
            p = msg["params"]
            if p["name"] == "read_sensor":
                value = self.curtain if p["arguments"]["sensor"] == "light_curtain" else "ok"
                return {
                    "resultType": "complete",
                    "content": [{"type": "text", "text": "read"}],
                    "structuredContent": {"value": value},
                }
            return {"resultType": "complete", "content": [{"type": "text", "text": "EXECUTED"}]}
        return {"resultType": "complete"}

    def calls(self):
        return [m for _, m in self.received if m.get("method") == "tools/call"]


@pytest.fixture
def cell():
    up = Upstream()
    il = Interlock(Policy.from_toml(POLICY))
    gw = HttpGateway(
        McpGateway(il, agent="planner-01"),
        upstream=up.url,
        allowed_origins=["http://localhost:3000"],
        max_body=4096,
    )
    srv = gw.serve("127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    yield up, il, gw, srv.server_port
    srv.shutdown()
    up.srv.shutdown()


def meta():
    return {
        "io.modelcontextprotocol/protocolVersion": V,
        "io.modelcontextprotocol/clientCapabilities": {},
    }  # noqa: E501


def post(port, msg, headers=None, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = raw if raw is not None else json.dumps(msg).encode()
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    conn.request("POST", "/mcp", body=body, headers={**h, **(headers or {})})
    r = conn.getresponse()
    data = r.read()
    conn.close()
    ctype = r.getheader("Content-Type") or ""
    if "event-stream" in ctype:
        events = [
            json.loads(e["data"])
            for e in iter_sse(data.splitlines(True))
            if isinstance(e, dict) and e.get("data")
        ]  # noqa: E501
        return r, events
    return r, (json.loads(data) if data and "json" in ctype else data)


def tool_call(port, id_, name, args, extra=None, **over):
    msg = {"jsonrpc": "2.0", "id": id_, "method": "tools/call",
           "params": {"name": name, "arguments": args, "_meta": meta()}}  # fmt: skip
    headers = {"MCP-Protocol-Version": V, "Mcp-Method": "tools/call", "Mcp-Name": name}
    headers.update(extra or {})
    headers.update(over)
    return post(port, msg, headers)


# ------------------------------------------------------------- pure helpers


def test_header_value_codec_matches_spec_examples():
    assert encode_header_value("us-west1") == "us-west1"
    assert encode_header_value("Hello, 世界") == "=?base64?SGVsbG8sIOS4lueVjA==?="
    assert encode_header_value(" padded ") == "=?base64?IHBhZGRlZCA=?="
    assert encode_header_value("line1\nline2") == "=?base64?bGluZTEKbGluZTI=?="
    assert encode_header_value("=?base64?literal?=") == "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="
    for v in ("us-west1", "Hello, 世界", " padded ", "=?base64?literal?="):
        assert decode_header_value(encode_header_value(v)) == v
    assert decode_header_value("=?base64?!!!?=") is None  # malformed never matches


def test_header_map_follows_only_properties_chains():
    schema = {
        "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "cfg": {"properties": {"tenant": {"type": "string", "x-mcp-header": "Tenant"}}},
            "list": {"items": {"properties": {"x": {"x-mcp-header": "Nope"}}}},
        }
    }
    assert header_map(schema) == {("region",): "Region", ("cfg", "tenant"): "Tenant"}
    exp = expected_param_headers(header_map(schema), {"region": "eu", "cfg": {"tenant": None}})
    assert exp == {"mcp-param-region": ("Mcp-Param-Region", "eu")}


def body(method, **params):
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": {**params, "_meta": meta()}}


@pytest.mark.parametrize(
    "headers, why",
    [
        ([("MCP-Protocol-Version", V), ("Mcp-Name", "read_sensor")], "missing Mcp-Method"),
        ([("MCP-Protocol-Version", V), ("Mcp-Method", "tools/call")], "missing Mcp-Name"),
        (
            [
                ("MCP-Protocol-Version", V),
                ("Mcp-Method", "tools/list"),
                ("Mcp-Name", "read_sensor"),
            ],
            "Mcp-Method header does not match",
        ),  # fmt: skip
        (
            [
                ("MCP-Protocol-Version", "2026-12-01"),
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "read_sensor"),
            ],
            "does not match _meta",
        ),  # fmt: skip
        (
            [
                ("MCP-Protocol-Version", V),
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "read_sensor"),
                ("mcp-name", "format_disk"),
            ],
            "more than once",
        ),  # fmt: skip
    ],
)
def test_routing_header_mismatch_is_rejected(headers, why):
    with pytest.raises(Rejected, match=why) as e:
        validate_routing_headers(headers, body("tools/call", name="read_sensor", arguments={}))
    assert e.value.code == -32020 and e.value.status == 400


def test_legacy_requests_need_no_mirrored_headers_but_must_not_lie():
    legacy = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x"}}
    validate_routing_headers([("MCP-Protocol-Version", "2025-11-25")], legacy)
    with pytest.raises(Rejected):
        validate_routing_headers([("Mcp-Name", "y")], legacy)


# ---------------------------------------------------------------- over HTTP


def test_allowed_call_is_forwarded_with_regenerated_headers(cell):
    up, _, _, port = cell
    r, out = tool_call(port, 1, "read_sensor", {"sensor": "temp"})
    assert r.status == 200 and out["result"]["content"][0]["text"] == "read"
    assert r.getheader("X-Upstream") == "yes"  # response headers relayed
    headers, msg = up.received[-1]
    assert msg["params"]["name"] == "read_sensor"
    assert headers["mcp-name"] == "read_sensor" and headers["mcp-method"] == "tools/call"
    assert "origin" not in headers and headers.get("accept-encoding") == "identity"


def test_blocked_call_never_reaches_upstream(cell):
    up, *_, port = cell
    r, out = tool_call(port, 2, "set_conveyor", {"zone": "A", "speed": 9}, {"Mcp-Param-Zone": "A"})
    assert r.status == 200 and out["result"]["isError"]
    assert "param:speed" in out["result"]["content"][0]["text"]
    r, out = tool_call(port, 3, "format_disk", {})
    assert out["result"]["isError"] and "unknown_tool" in out["result"]["content"][0]["text"]
    assert up.calls() == []


def test_mcp_name_smuggling_is_rejected_and_audited(cell):
    # Body says read_sensor (allowed); header says format_disk. A router that
    # trusts the header must never get this request.
    up, il, _, port = cell
    r, out = tool_call(port, 4, "read_sensor", {"sensor": "temp"}, **{"Mcp-Name": "format_disk"})
    assert r.status == 400 and out["error"]["code"] == -32020
    assert up.received == []
    assert any(rec["kind"] == "mcp_rejected" for rec in il.audit.records)


def test_mcp_param_headers_are_checked_against_body(cell):
    up, *_, port = cell
    # Gateway has not seen tools/list yet: it fetches the schema to validate.
    r, _ = tool_call(port, 5, "set_conveyor", {"zone": "A", "speed": 0.1}, {"Mcp-Param-Zone": "B"})
    assert r.status == 400
    assert up.calls() == []
    r, out = tool_call(port, 6, "set_conveyor", OK_CONV, {"mcp-param-zone": "A"})
    assert r.status == 200 and out["result"]["content"][0]["text"] == "EXECUTED"
    headers, _ = up.received[-1]
    assert headers["mcp-param-zone"] == "A"
    # Value is in the body but the header is missing: non-conforming, rejected.
    r, _ = tool_call(port, 7, "set_conveyor", {"zone": "B", "speed": 0.1})
    assert r.status == 400 and len(up.calls()) == 1


@pytest.mark.parametrize("sse", [False, True])
def test_tools_list_is_filtered_json_and_sse(cell, sse):
    up, *_, port = cell
    up.sse = sse
    msg = {"jsonrpc": "2.0", "id": "L", "method": "tools/list", "params": {"_meta": meta()}}
    r, out = post(port, msg, {"MCP-Protocol-Version": V, "Mcp-Method": "tools/list"})
    resp = out[-1] if sse else out
    assert [t["name"] for t in resp["result"]["tools"]] == ["read_sensor", "set_conveyor"]
    if sse:
        assert out[0]["method"] == "notifications/progress"  # other events relayed


@pytest.mark.parametrize("sse", [False, True])
def test_trip_on_result_latches_estop(cell, sse):
    up, il, _, port = cell
    up.sse, up.curtain = sse, "breached"
    r, out = tool_call(port, 8, "read_sensor", {"sensor": "light_curtain"})
    resp = out[-1] if sse else out
    assert "E-stop latched" in resp["result"]["content"][-1]["text"]
    assert il.estop_latched
    r, out = tool_call(port, 9, "set_conveyor", OK_CONV, {"Mcp-Param-Zone": "A"})
    assert out["result"]["isError"] and "estop" in out["result"]["content"][0]["text"]


def test_origin_size_and_shape_guards(cell):
    up, *_, port = cell
    r, _ = tool_call(port, 10, "read_sensor", {"sensor": "temp"}, Origin="http://evil.example")
    assert r.status == 403
    r, _ = tool_call(port, 11, "read_sensor", {"sensor": "temp"}, Origin="http://localhost:3000")
    assert r.status == 200
    r, _ = post(port, None, raw=b"x" * 5000)
    assert r.status == 413
    r, out = post(port, None, raw=b"[{}]")
    assert r.status == 400 and out["error"]["code"] == -32600
    r, out = post(port, None, raw=b"{oops")
    assert r.status == 400 and out["error"]["code"] == -32700
    assert len(up.received) == 1


def test_healthz_reports_latches(cell):
    _, il, _, port = cell
    il.estop(source="test")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/healthz")
    r = conn.getresponse()
    assert r.status == 200 and json.loads(r.read())["estop"] is True


def test_upstream_down_is_a_502(cell):
    up, *_, port = cell
    up.srv.shutdown()
    up.srv.server_close()
    r, out = tool_call(port, 12, "read_sensor", {"sensor": "temp"})
    assert r.status == 502 and out["error"]["code"] == -32603


def test_audit_to_stream_chains_and_does_not_close():
    import io

    from agent_interlock import audit

    buf = io.StringIO()
    log = audit.AuditLog(stream=buf)
    Interlock(Policy.from_toml(POLICY), audit=log).estop(source="t")
    log.close()
    assert not buf.closed
    records = [json.loads(line) for line in buf.getvalue().splitlines()]
    assert [r["kind"] for r in records] == ["start", "estop"] and audit.verify(records)[0]
