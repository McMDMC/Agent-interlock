# agent-interlock

A safety interlock for AI agent tool calls. It is built for agents that
move real hardware (robot arms, conveyors, PLC-driven cells) but works the
same way for any tool an agent calls.

Every tool call goes through `Interlock.check()` before it runs. The call is
checked against a declared policy and gets one of four verdicts: **allow**,
**deny**, **hold** (needs a human) or **lockout**. Every decision lands in a
hash-chained audit log.

```
LLM agent ──tool_call──▶  INTERLOCK  ──allow──▶  tool / device
                           │  policy envelope (types, ranges, enums, regex)
                           │  keep-out zones
                           │  rate limits
                           │  operator approval (hold)
                           │  lockout/tagout + E-stop
                           └─▶ audit.jsonl (SHA-256 chain)
```

Architecture diagrams (modules, check pipeline, MCP session): [docs/architecture.md](docs/architecture.md)

## Why

Prompt filters stop bad *text*. On a machine, what does the damage is the
*action*: a speed of 1.5 m/s, a target inside the operator station, a `NaN`
that slips past `min`/`max` checks. In industrial safety you don't trust the
controller to behave. You put an interlock between it and the hazard. This
project does the same for agents.

| Machine safety | agent-interlock |
|---|---|
| Safe operating envelope | `params` with `min`/`max`/`enum`/`pattern`, fail closed |
| Light curtain / restricted zone | `keepout` boxes |
| Lockout/tagout (LOTO) | Repeated violations quarantine the agent; only a named operator can `release()` |
| E-stop | `estop()` latches and blocks every `actuate` tool until `reset_estop(operator=...)` |
| Commissioning / test run | `mode = "observe"`: log only, no blocking (E-stop and lockouts are still enforced) |
| Two-person rule / permit to work | `require_approval = true` → `HOLD` until an approver says yes |
| Machine logbook | Hash-chained JSONL audit trail, `interlock verify-audit` |

Inspired by the gateway pattern in Cisco's open-source
[DefenseClaw](https://siliconangle.com/2026/03/23/cisco-debuts-new-ai-agent-security-features-open-source-defenseclaw-tool/)
(policy on live tool calls, observe vs. action mode, quarantine, audit
trail). DefenseClaw governs software agents. This project focuses on
physical-world envelopes. It is independent, shares no code with
DefenseClaw and is not affiliated with Cisco.

## Quickstart

```bash
pip install -e ".[dev]"            # core is stdlib-only, Python 3.11+
python examples/robot_cell_demo.py
pytest -q
```

```python
from agent_interlock import Interlock, ToolCall, guarded

il = Interlock.from_file("policies/robot_cell.toml")

d = il.check(ToolCall("planner-01", "move_arm", {"x": 0.45, "y": 0, "z": 0.4, "speed": 0.1}))
d.verdict, d.reason  # (Verdict.DENY, "target inside keep-out zone 'operator_station'")


@guarded(il, agent="planner-01")  # raises InterlockBlocked instead of running
def move_arm(x: float, y: float, z: float, speed: float): ...
```

### Google ADK (tested against google-adk 2.12.0)

One plugin on the `App` gates every tool of every agent. A blocked call
returns its reason to the model as the tool result, so the agent can
re-plan.

```python
from google.adk.apps import App
from agent_interlock.adapters.adk import InterlockPlugin

app = App(name="robot_cell", root_agent=agent, plugins=[InterlockPlugin(il)])
```

Per-agent alternative: `LlmAgent(before_tool_callback=before_tool_callback(il))`.
For a full runnable example, see `examples/adk_robot_agent.py` (needs `pip install -e ".[adk]"`
and a Gemini API key or Vertex AI).

### MCP gateway (any MCP server, any language)

`interlock mcp-proxy` sits between an MCP client and a stdio MCP server
(spec 2026-07-28). It changes two things and relays the rest untouched:

* **`tools/call`** is checked first. A blocked call never reaches the server.
  The client gets a normal tool result with `isError: true` and the reason,
  so the model can correct itself.
* **`tools/list`** is cut down to the tools the policy declares. The model
  never sees a tool it may not use. `--show-all` turns this off.

Every forwarded message is re-serialised from what the gateway parsed, never
passed through as raw bytes. A trick like duplicate JSON keys
(`{"name":"format_disk","name":"read_sensor"}`) therefore cannot show the
server a different call from the one that was checked.

```bash
interlock mcp-proxy --policy policies/robot_cell.toml --agent planner-01 \
    --state /var/lib/interlock/latch.json --audit audit.jsonl \
    -- python examples/mcp_robot_server.py
```

Claude Code `.mcp.json`, or any client config: point the server entry at the gateway.

```json
{
  "mcpServers": {
    "robot-cell": {
      "command": "interlock",
      "args": ["mcp-proxy", "--policy", "policies/robot_cell.toml", "--agent", "claude",
               "--state", "/tmp/cell-latch.json", "--", "python", "examples/mcp_robot_server.py"]
    }
  }
}
```

Tested with the official MCP Python SDK 2.3.0 on both sides
(`tests/test_mcp_sdk_interop.py`). `kill -HUP <pid>` reloads the policy
without dropping the session. A broken policy is rejected, the old one stays
active, and both outcomes are written to the audit log.

## Operating it: E-stop, lockouts, reload

Lockouts and the E-stop are *latches*. Pass `state_path=` (Python) or
`--state` (CLI) and they are stored in a JSON file:

* **Survives restarts.** Restarting the agent process does not clear a lockout.
* **Shared.** Every gateway pointing at the same file sees a change on its
  next check. One E-stop stops every agent on the host.
* **Fail safe.** An unreadable state file latches the E-stop. Deleting the
  file does not clear a latched E-stop in a running gateway.

```bash
interlock estop   --state latch.json --source light_curtain --reason "beam broken"
interlock status  --state latch.json
interlock reset   --state latch.json --operator m.mcmorris
interlock release --state latch.json --agent planner-01 --operator m.mcmorris
```

Policy hot-reload: `Interlock.reload(policy, operator=...)`, or SIGHUP for
the gateway. Every audit log starts with the SHA-256 of the active policy,
and every reload records the old and new hash. For any decision you can
prove which policy made it.

## Policy (TOML)

```toml
[interlock]
mode = "enforce"            # or "observe"
lockout_after = 3           # violations within the window → lockout (0 = off)
violation_window_s = 300
estop_blocks = ["actuate"]

[tools.move_arm]
class = "actuate"           # read | write | actuate
rate = { max = 5, per_s = 1 }
params.speed = { type = "number", min = 0.0, max = 0.25 }
params.z     = { type = "number", min = 0.05, max = 0.90 }

[[tools.move_arm.keepout]]
name = "operator_station"
x = [0.30, 0.60]
y = [-0.20, 0.20]

[tools.load_program]
class = "write"
require_approval = true
params.name = { type = "string", pattern = "[A-Za-z0-9_\\-]{1,64}" }
```

Rules:

* A tool not in the policy is denied.
* Arguments not declared under `params` are denied (`strict = true` by default).
* Declared params are required unless `required = false`.
* `NaN`, `±inf` and booleans never pass a numeric check.
* Every keep-out axis must be a required numeric param. Otherwise an agent
  could skip the zone check by leaving the coordinate out.
* A malformed policy fails at load time, never mid-run.
* In observe mode, an operator's "no" on a `HOLD` is still enforced, like
  the E-stop and lockouts.

Optional per tool: `agents = ["name", ...]` restricts which agents may call it.

## CLI

```bash
interlock validate policies/robot_cell.toml
interlock check    policies/robot_cell.toml --tool move_arm --args '{"x":0.1,"y":0.1,"z":0.4,"speed":0.9}'
interlock verify-audit audit.jsonl
interlock bench    policies/robot_cell.toml --tool move_arm --args '{"x":0.1,"y":0.1,"z":0.4,"speed":0.1}'
interlock mcp-proxy --policy ... -- <server command>
interlock estop | reset | release | status --state latch.json
```

## Performance

Measured with `interlock bench` (100k calls, full `check()` including the
lock, audit I/O excluded) on a shared cloud container running Python 3.13:

| Tool | p50 | p99 |
|---|---|---|
| `read_joint_states` (no params) | 2.9 µs | 7.7 µs |
| `set_gripper` (2 range checks) | 4.3 µs | 12.4 µs |
| `set_gripper` with shared `--state` file | 6.5 µs | 16 µs |

The shared state file costs one `stat()` per check (about 2 µs) to pick up
E-stops from other processes. The occasional max of around 1 ms comes from
GC and scheduler noise. With a file-backed audit log, each decision also
costs one append and one SHA-256.

## Limits

* This is a **software** interlock. It does not replace a safety-rated
  controller, a hardware E-stop circuit or a risk assessment (ISO 12100,
  ISO 10218, IEC 62061 / ISO 13849). Treat it as one more layer that stops
  the agent from asking for something dangerous in the first place.
* Policy limits in `policies/robot_cell.toml` are illustrative.
* The audit log is tamper-*evident*, not tamper-*proof*. Ship it off the box
  (Cloud Logging, a WORM bucket) if an attacker could rewrite the whole file.
* Lockouts and the E-stop are shared through a local file. That covers
  processes on one host, not replicas on several hosts. Rate windows and
  violation counters are per process.
* Write one audit file per process. Two processes appending to the same
  file would interleave two hash chains.
* The MCP gateway covers stdio. Streamable HTTP is not gated yet.

## Roadmap

- [x] MCP gateway (stdio) in front of any MCP server
- [x] Latches that persist and are shared across processes on a host
- [x] Policy hot-reload with policy hash in the audit trail
- [ ] MCP gateway for Streamable HTTP (Cloud Run deployment)
- [ ] Shared state backend (Firestore / Redis) for multi-host
- [ ] Cloud Logging audit sink
- [ ] ROS 2 adapter (gate `/cmd_vel`, action goals)
- [ ] Policy export to OPA/Rego

## License

Apache-2.0
