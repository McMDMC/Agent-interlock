"""Minimal stdio MCP server for gateway tests. Records every tools/call it executes."""

import json
import sys

TOOLS = [
    {"name": "move_arm", "inputSchema": {"type": "object"}},
    {"name": "read_sensor", "inputSchema": {"type": "object"}},
    {"name": "format_disk", "inputSchema": {"type": "object"}},  # not in the policy
]

for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method, result = msg.get("method"), {}
    if method == "initialize":
        result = {"protocolVersion": "2026-07-28", "capabilities": {"tools": {}}}
    elif method == "tools/list":
        result = {"resultType": "complete", "tools": TOOLS, "ttlMs": 1000}
    elif method == "tools/call":
        p = msg["params"]
        text = f"EXECUTED {p['name']} {json.dumps(p.get('arguments', {}), sort_keys=True)}"
        result = {"resultType": "complete", "content": [{"type": "text", "text": text}]}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
