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
* A malformed policy fails at load time, never mid-run.

Optional per tool: `agents = ["name", ...]` restricts which agents may call it.

## CLI

```bash
interlock validate policies/robot_cell.toml
interlock check    policies/robot_cell.toml --tool move_arm --args '{"x":0.1,"y":0.1,"z":0.4,"speed":0.9}'
interlock verify-audit audit.jsonl
interlock bench    policies/robot_cell.toml --tool move_arm --args '{"x":0.1,"y":0.1,"z":0.4,"speed":0.1}'
```

## Performance

Measured with `interlock bench` (100k calls, full `check()` including the
lock, audit I/O excluded) on a shared cloud container running Python 3.13:

| Tool | p50 | p99 |
|---|---|---|
| `read_joint_states` (no params) | 2.9 µs | 7.7 µs |
| `set_gripper` (2 range checks) | 4.3 µs | 12.4 µs |

The occasional max of around 1 ms comes from GC and scheduler noise. With a
file-backed audit log, each decision also costs one append and one SHA-256.

## Limits

* This is a **software** interlock. It does not replace a safety-rated
  controller, a hardware E-stop circuit or a risk assessment (ISO 12100,
  ISO 10218, IEC 62061 / ISO 13849). Treat it as one more layer that stops
  the agent from asking for something dangerous in the first place.
* Policy limits in `policies/robot_cell.toml` are illustrative.
* The audit log is tamper-*evident*, not tamper-*proof*. Ship it off the box
  (Cloud Logging, a WORM bucket) if an attacker could rewrite the whole file.
* State (rate windows, lockouts, E-stop) lives in memory in one process.
  Multi-replica deployments need shared state.

## Roadmap

- [ ] MCP proxy: run the interlock as a gateway in front of any MCP server
- [ ] Shared state backend (Redis / Firestore) for multi-replica Cloud Run
- [ ] Cloud Logging audit sink
- [ ] ROS 2 adapter (gate `/cmd_vel`, action goals)
- [ ] Policy export to OPA/Rego

## License

Apache-2.0
